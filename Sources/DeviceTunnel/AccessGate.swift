import CryptoKit
import Foundation
import Network
import NIOCore
import Synchronization

/// The exchange every connection to a host passes before SSH starts, so that
/// only the account's devices ever reach the host's SSH server.
///
/// SSH sends the host key — the host's stable endpoint ID — to anyone who
/// connects, and runs a Keychain lookup for every key offered, so without
/// this anyone who can reach a host's port could identify and track it, or
/// keep its handshake slots busy. Every device publishes a ``DeviceIdentity/gateKey``
/// in its registry record, which iCloud Keychain carries only to the
/// account's devices:
///
/// 1. The host sends ``magic``, a fresh nonce, and a tag proving it knows
///    its own gate key, so a client that reached some other device finds
///    out before sending anything. The tag can be replayed, so it only
///    saves a round trip; SSH's host key check is what pins the host.
/// 2. The client answers with a proof over the nonce under the host's gate
///    key, and then starts SSH.
/// 3. The host checks the proof in constant time and only then starts SSH;
///    a wrong proof, or none within ``timeout``, closes the connection.
///
/// Neither message identifies either device to anyone without the key. The
/// host's gate key also keys its Bonjour advertisement (``advertisementTag(gateKey:salt:)``).
enum AccessGate {
    /// Opens the host's challenge; the last character is the exchange's
    /// revision, so a client can tell an outdated host from a stranger.
    static let magic = Data("DTG1".utf8)
    /// Bytes of the host's fresh nonce.
    static let nonceLength = 32
    /// Bytes of a tag or proof: a full HMAC-SHA256.
    static let proofLength = 32
    /// The host's challenge: magic, nonce, then the host's tag.
    static let challengeLength = magic.count + nonceLength + proofLength
    /// How long a client may take to answer before the host hangs up.
    static let timeout: TimeAmount = .seconds(5)
    /// Bytes of the salt in a Bonjour advertisement.
    static let advertisementSaltLength = 16
    /// Bytes of the tag in a Bonjour advertisement: a truncated HMAC.
    static let advertisementTagLength = 16
    /// Bytes of the random Bonjour instance name a host advertises under.
    static let advertisementNameLength = 6

    /// The host's tag over `nonce`.
    static func hostTag(gateKey: Data, nonce: Data) -> Data {
        mac(gateKey: gateKey, label: "host", message: nonce)
    }

    /// The client's proof over the host's `nonce`.
    static func clientProof(gateKey: Data, nonce: Data) -> Data {
        mac(gateKey: gateKey, label: "client", message: nonce)
    }

    /// The tag a host's advertisement carries for `salt`, which a client
    /// that knows the host's gate key recognizes and nobody else can link.
    static func advertisementTag(gateKey: Data, salt: Data) -> Data {
        mac(gateKey: gateKey, label: "bonjour", message: salt).prefix(advertisementTagLength)
    }

    /// Whether `code` is `expected`, compared in constant time.
    static func matches(_ code: Data, _ expected: Data) -> Bool {
        guard code.count == expected.count else { return false }
        return zip(code, expected).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// Random bytes from the system's secure generator.
    static func randomBytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    /// HMAC-SHA256 under `gateKey` over a domain-separated `message`.
    private static func mac(gateKey: Data, label: String, message: Data) -> Data {
        var input = Data("device-tunnel-gate/1".utf8)
        input.append(0)
        input.append(Data(label.utf8))
        input.append(0)
        input.append(message)
        return Data(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: gateKey)))
    }
}

/// The host's end of the ``AccessGate``: the front of every incoming
/// connection's pipeline until the client proves it knows the host's gate
/// key. Then `admit` sets up SSH behind it, and the gate leaves the pipeline,
/// passing on any bytes that followed the proof.
final class AccessGateServerHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let gateKey: Data
    private let admit: (any Channel) throws -> Void
    private let limiter: AccessGateLimiter?
    private let nonce = AccessGate.randomBytes(AccessGate.nonceLength)
    private var received = Data()
    private var deadline: Scheduled<Void>?
    /// The channel `limiter` counts, from the start of the challenge until
    /// the gate finishes.
    private var tracked: (any Channel)?
    private var hasStarted = false
    private var isFinished = false
    private var leftover: ByteBuffer?

    /// A gate that runs `admit` on the channel once the client proves it
    /// knows `gateKey`, counting the connection against `limiter` while it
    /// waits.
    init(gateKey: Data, limiter: AccessGateLimiter?, admit: @escaping (any Channel) throws -> Void) {
        self.gateKey = gateKey
        self.limiter = limiter
        self.admit = admit
    }

    func handlerAdded(context: ChannelHandlerContext) {
        // A listener's child isn't active yet, and learns its peer's
        // address — which the limiter buckets by — only once it is.
        if context.channel.isActive {
            start(context: context)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        finish()
    }

    func channelActive(context: ChannelHandlerContext) {
        start(context: context)
        context.fireChannelActive()
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        guard !isFinished else {
            context.fireErrorCaught(error)
            return
        }
        finish()
        context.close(promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !isFinished else {
            context.fireChannelRead(data)
            return
        }
        var bytes = unwrapInboundIn(data)
        received.append(contentsOf: bytes.readBytes(length: bytes.readableBytes) ?? [])
        guard received.count >= AccessGate.proofLength else { return }

        let proof = received.prefix(AccessGate.proofLength)
        guard AccessGate.matches(proof, AccessGate.clientProof(gateKey: gateKey, nonce: nonce)) else {
            RemoteLog.host.info("Turning away a connection that didn't prove it's on the account")
            finish()
            context.close(promise: nil)
            return
        }
        do {
            try admit(context.channel)
        } catch {
            finish()
            context.close(promise: nil)
            return
        }
        let rest = received.dropFirst(AccessGate.proofLength)
        leftover = rest.isEmpty ? nil : ByteBuffer(bytes: rest)
        received = Data()
        finish()
        context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
    }

    /// Passes on the bytes that arrived with the proof — the start of the
    /// client's SSH — to the handlers `admit` added, before leaving.
    func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        if let leftover {
            context.fireChannelRead(wrapInboundOut(leftover))
            context.fireChannelReadComplete()
        }
        leftover = nil
        context.leavePipeline(removalToken: removalToken)
    }

    /// Sends the challenge once, starts the deadline, and counts the
    /// connection against the limiter.
    private func start(context: ChannelHandlerContext) {
        guard !hasStarted else { return }
        hasStarted = true
        if let limiter {
            tracked = context.channel
            limiter.admit(context.channel)
        }
        deadline = context.eventLoop.assumeIsolated().scheduleTask(in: AccessGate.timeout) { [self] in
            guard !isFinished else { return }
            finish()
            context.close(promise: nil)
        }
        var challenge = AccessGate.magic
        challenge.append(nonce)
        challenge.append(AccessGate.hostTag(gateKey: gateKey, nonce: nonce))
        context.writeAndFlush(wrapOutboundOut(ByteBuffer(bytes: challenge)), promise: nil)
    }

    /// Ends the gate's watch, once, freeing the connection's limiter slot.
    private func finish() {
        guard !isFinished else { return }
        isFinished = true
        deadline?.cancel()
        deadline = nil
        if let tracked {
            limiter?.release(tracked)
        }
        tracked = nil
    }
}

@available(*, unavailable)
extension AccessGateServerHandler: Sendable {}

/// The client's end of the ``AccessGate``: checks that the host proves it
/// knows the gate key the host's record publishes, answers its challenge,
/// then sets up SSH with `install` and leaves the pipeline. `promise`
/// carries the result of the future `install` returns.
final class AccessGateClientHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let gateKey: Data
    private let promise: EventLoopPromise<Void>
    private let install: (any Channel) throws -> EventLoopFuture<Void>
    private var received = Data()
    private var isSettled = false
    private var leftover: ByteBuffer?

    /// A gate that answers the challenge of the host whose gate key is
    /// `gateKey` and then runs `install`.
    init(gateKey: Data, promise: EventLoopPromise<Void>, install: @escaping (any Channel) throws -> EventLoopFuture<Void>) {
        self.gateKey = gateKey
        self.promise = promise
        self.install = install
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        fail(RemoteAccessError.unexpectedEndOfStream, context: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        fail(RemoteAccessError.unexpectedEndOfStream, context: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        guard !isSettled else {
            context.fireErrorCaught(error)
            return
        }
        fail(error, context: context)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !isSettled else {
            context.fireChannelRead(data)
            return
        }
        var bytes = unwrapInboundIn(data)
        received.append(contentsOf: bytes.readBytes(length: bytes.readableBytes) ?? [])
        if received.count >= AccessGate.magic.count, !received.starts(with: AccessGate.magic) {
            let isOtherRevision = received.starts(with: AccessGate.magic.dropLast())
            fail(isOtherRevision ? RemoteAccessError.outdatedPeer : RemoteAccessError.protocolViolation("not a device tunnel host"), context: context)
            return
        }
        guard received.count >= AccessGate.challengeLength else { return }

        let nonce = received.dropFirst(AccessGate.magic.count).prefix(AccessGate.nonceLength)
        let hostTag = received.dropFirst(AccessGate.magic.count + AccessGate.nonceLength).prefix(AccessGate.proofLength)
        guard AccessGate.matches(hostTag, AccessGate.hostTag(gateKey: gateKey, nonce: Data(nonce))) else {
            // Some other device answered at this address.
            fail(RemoteAccessError.hostKeyMismatch, context: context)
            return
        }
        context.writeAndFlush(wrapOutboundOut(ByteBuffer(bytes: AccessGate.clientProof(gateKey: gateKey, nonce: Data(nonce)))), promise: nil)
        let authenticated: EventLoopFuture<Void>
        do {
            authenticated = try install(context.channel)
        } catch {
            fail(error, context: context)
            return
        }
        let rest = received.dropFirst(AccessGate.challengeLength)
        leftover = rest.isEmpty ? nil : ByteBuffer(bytes: rest)
        received = Data()
        isSettled = true
        authenticated.cascade(to: promise)
        context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
    }

    /// Passes on the bytes that arrived with the challenge — the start of
    /// the host's SSH — to the handlers `install` added, before leaving.
    func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        if let leftover {
            context.fireChannelRead(wrapInboundOut(leftover))
            context.fireChannelReadComplete()
        }
        leftover = nil
        context.leavePipeline(removalToken: removalToken)
    }

    /// Fails the gate with `error`, once, closing the connection when
    /// `context` is given.
    private func fail(_ error: any Error, context: ChannelHandlerContext?) {
        guard !isSettled else { return }
        isSettled = true
        promise.fail(error)
        context?.close(promise: nil)
    }
}

@available(*, unavailable)
extension AccessGateClientHandler: Sendable {}

/// Bounds the connections waiting at a host's ``AccessGate``, which anyone
/// on the network can open.
///
/// Each source address — an IPv4 address or an IPv6 /64, since one host
/// commonly holds a whole /64 — may have ``maxPerSource`` waiting, and the
/// host ``maxTotal``. A connection over its source's limit closes that
/// source's oldest; one over the host's limit closes the oldest from
/// whichever source has the most waiting. So no source holds more than its
/// share, and a flood mostly turns away its own connections rather than a
/// device's single one.
final class AccessGateLimiter: Sendable {
    /// Most connections one source may have waiting.
    static let maxPerSource = 8
    /// Most connections the host may have waiting.
    static let maxTotal = 128

    /// A connection waiting at the gate.
    private struct Waiting {
        let channel: any Channel
        let source: String
        let arrived: ContinuousClock.Instant
    }

    private let waiting = Mutex<[ObjectIdentifier: Waiting]>([:])

    /// Starts tracking `channel`, closing a waiting connection to stay
    /// within the limits.
    func admit(_ channel: any Channel) {
        let source = Self.source(of: channel.remoteAddress)
        let evicted = waiting.withLock { waiting -> (any Channel)? in
            var victimSource: String?
            if waiting.values.count(where: { $0.source == source }) >= Self.maxPerSource {
                victimSource = source
            } else if waiting.count >= Self.maxTotal {
                let perSource = Dictionary(grouping: waiting.values, by: \.source).mapValues(\.count)
                victimSource = perSource.max { $0.value < $1.value }?.key
            }
            var evicted: (any Channel)?
            if let victimSource,
               let oldest = waiting.filter({ $0.value.source == victimSource }).min(by: { $0.value.arrived < $1.value.arrived }) {
                waiting[oldest.key] = nil
                evicted = oldest.value.channel
            }
            waiting[ObjectIdentifier(channel)] = Waiting(channel: channel, source: source, arrived: .now)
            return evicted
        }
        if let evicted {
            RemoteLog.host.info("Turning away a connection waiting at the gate to make room")
            evicted.close(promise: nil)
        }
    }

    /// Stops tracking `channel`, which passed the gate or closed.
    func release(_ channel: any Channel) {
        _ = waiting.withLock { $0.removeValue(forKey: ObjectIdentifier(channel)) }
    }

    /// How many connections are waiting, from `source` or in all.
    func count(from source: String? = nil) -> Int {
        waiting.withLock { waiting in
            waiting.values.count { source == nil || $0.source == source }
        }
    }

    /// The bucket `address` counts against: the IPv4 address, or the /64
    /// of an IPv6 one.
    static func source(of address: SocketAddress?) -> String {
        guard let ip = address?.ipAddress else { return "unknown" }
        if let v6 = IPv6Address(ip), !ip.contains(".") {
            return "v6:" + Data(v6.rawValue.prefix(8)).hexEncoded
        }
        return "v4:" + ip
    }
}
