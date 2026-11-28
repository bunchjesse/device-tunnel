import CryptoKit
import Foundation
import NIOCore
import NIOSSH
import Synchronization

/// Converts between endpoint IDs and SSH keys.
///
/// An endpoint ID is the hex of a device's Ed25519 public key, so it is also
/// the device's SSH key: hosts present it as their host key, and clients
/// authenticate with it.
enum SSHKeys {
    private static let ed25519Prefix = "ssh-ed25519"

    /// The SSH key for `identity`'s private key.
    static func privateKey(for identity: DeviceIdentity) throws -> NIOSSHPrivateKey {
        NIOSSHPrivateKey(ed25519Key: try Curve25519.Signing.PrivateKey(rawRepresentation: identity.secretKey))
    }

    /// The SSH public key an endpoint ID names.
    static func publicKey(endpointID: String) throws -> NIOSSHPublicKey {
        guard let raw = Data(hexEncoded: endpointID), raw.count == 32 else {
            throw RemoteAccessError.protocolViolation("malformed endpoint ID")
        }
        var blob = Data()
        for field in [Data(ed25519Prefix.utf8), raw] {
            let length = UInt32(field.count).bigEndian
            withUnsafeBytes(of: length) { blob.append(contentsOf: $0) }
            blob.append(field)
        }
        return try NIOSSHPublicKey(openSSHPublicKey: "\(ed25519Prefix) \(blob.base64EncodedString())")
    }

    /// The endpoint ID of an Ed25519 key, or nil for any other key type.
    static func endpointID(of key: NIOSSHPublicKey) -> String? {
        let parts = String(openSSHPublicKey: key).split(separator: " ")
        guard parts.count >= 2, parts[0] == ed25519Prefix,
              let blob = Data(base64Encoded: String(parts[1])),
              blob.count == 4 + ed25519Prefix.utf8.count + 4 + 32
        else { return nil }
        return Data(blob.suffix(32)).hexEncoded
    }
}

/// Sets up SSH on a connection's pipeline.
///
/// The SSH layer does what the tunnel needs and nothing more: the host proves
/// its endpoint key as the host key, the client proves its key with public-key
/// authentication, and each stream is a `direct-tcpip` channel. Shells, exec,
/// and every kind of forwarding the host didn't set up are refused.
enum SSHPipeline {
    /// Most streams a peer may have opened that the host hasn't taken yet.
    static let maxQueuedStreams = 64

    /// Adds the client side of SSH to `channel`, trusting only the host key
    /// `hostEndpointID` names. The returned future succeeds once both sides
    /// are authenticated. Must be called on the channel's event loop.
    static func addClient(
        to channel: any Channel,
        key: NIOSSHPrivateKey,
        hostEndpointID: String,
        username: String
    ) throws -> EventLoopFuture<Void> {
        let authenticated = channel.eventLoop.makePromise(of: Void.self)
        let watcher = AuthenticationWatcher(promise: authenticated, succeedsOnAuthEvent: true)
        let authenticator = ClientAuthenticator(
            key: key,
            username: username,
            expectedHostKey: try SSHKeys.publicKey(endpointID: hostEndpointID),
            watcher: watcher
        )
        let handler = NIOSSHHandler(
            role: .client(SSHClientConfiguration(userAuthDelegate: authenticator, serverAuthDelegate: authenticator)),
            allocator: channel.allocator,
            inboundChildChannelInitializer: nil
        )
        try channel.pipeline.syncOperations.addHandlers([handler, watcher])
        return authenticated.futureResult
    }

    /// Adds the server side of SSH to `channel`, presenting `hostKey` and
    /// accepting only keys `admits` approves. Streams the client opens go to
    /// `streams`. The returned future carries the client's endpoint ID once
    /// it has authenticated. Must be called on the channel's event loop.
    static func addServer(
        to channel: any Channel,
        hostKey: NIOSSHPrivateKey,
        username: String,
        admits: @escaping @Sendable (_ endpointID: String) -> Bool,
        streams: AsyncInbox<ChannelByteStream>
    ) throws -> EventLoopFuture<String> {
        let authenticated = channel.eventLoop.makePromise(of: Void.self)
        let watcher = AuthenticationWatcher(promise: authenticated, succeedsOnAuthEvent: false)
        let authenticator = ServerAuthenticator(
            username: username,
            admits: admits,
            watcher: NIOLoopBound(watcher, eventLoop: channel.eventLoop)
        )
        var configuration = SSHServerConfiguration(hostKeys: [hostKey], userAuthDelegate: authenticator)
        configuration.maxAuthAttempts = 4
        let handler = NIOSSHHandler(
            role: .server(configuration),
            allocator: channel.allocator,
            inboundChildChannelInitializer: { child, channelType in
                guard case .directTCPIP = channelType, streams.count < maxQueuedStreams else {
                    return child.eventLoop.makeFailedFuture(RemoteAccessError.protocolViolation("unsupported channel"))
                }
                return child.eventLoop.makeCompletedFuture {
                    guard streams.push(try ChannelByteStream.installOnSSHChannel(child)) else {
                        throw RemoteAccessError.unexpectedEndOfStream
                    }
                }
            }
        )
        try channel.pipeline.syncOperations.addHandlers([handler, watcher])
        channel.closeFuture.whenComplete { _ in streams.finish() }
        return authenticated.futureResult.flatMapThrowing {
            guard let endpointID = authenticator.authenticatedEndpointID else {
                throw RemoteAccessError.protocolViolation("authenticated without a key")
            }
            return endpointID
        }
    }

    /// Opens a stream on an authenticated connection.
    static func openStream(on channel: any Channel) async throws -> ChannelByteStream {
        let opened = channel.eventLoop.makePromise(of: (any Channel).self)
        let installed = channel.eventLoop.makePromise(of: ChannelByteStream.self)
        opened.futureResult.whenFailure { installed.fail($0) }
        channel.eventLoop.execute {
            do {
                let handler = try channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
                let target = SSHChannelType.DirectTCPIP(
                    targetHost: "localhost",
                    targetPort: 0,
                    originatorAddress: try SocketAddress(ipAddress: "127.0.0.1", port: 0)
                )
                handler.createChannel(opened, channelType: .directTCPIP(target)) { child, _ in
                    child.eventLoop.makeCompletedFuture {
                        installed.succeed(try ChannelByteStream.installOnSSHChannel(child))
                    }
                }
            } catch {
                opened.fail(error)
            }
        }
        _ = try await opened.futureResult.get()
        return try await installed.futureResult.get()
    }
}

/// The client's credentials and its check of the host's key.
///
/// Only the key the host's endpoint ID names is trusted, never an address, so
/// a stale or forged route fails with `hostKeyMismatch` — usually at the
/// access gate already, and here for a device that copied the host's gate
/// key. A host that turns the client's key away fails with `notRecognized`.
/// NIOSSH stalls instead of closing in both cases, so the authenticator ends
/// the connection itself.
private final class ClientAuthenticator: NIOSSHClientUserAuthenticationDelegate, NIOSSHClientServerAuthenticationDelegate {
    private let key: NIOSSHPrivateKey
    private let username: String
    private let expectedHostKey: NIOSSHPublicKey
    private let watcher: AuthenticationWatcher
    private var hasOffered = false

    init(key: NIOSSHPrivateKey, username: String, expectedHostKey: NIOSSHPublicKey, watcher: AuthenticationWatcher) {
        self.key = key
        self.username = username
        self.expectedHostKey = expectedHostKey
        self.watcher = watcher
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // NIOSSH stalls rather than closing when the client runs out of
        // offers, so the watcher ends the connection with the reason.
        guard !hasOffered else {
            // The host accepts every key its registry knows, so turning
            // this one away means its registry doesn't list this device
            // yet, or the host couldn't read its Keychain.
            watcher.fail(RemoteAccessError.notRecognized)
            nextChallengePromise.succeed(nil)
            return
        }
        guard availableMethods.contains(.publicKey) else {
            watcher.fail(RemoteAccessError.protocolViolation("the host doesn't accept keys"))
            nextChallengePromise.succeed(nil)
            return
        }
        hasOffered = true
        nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",
            offer: .privateKey(.init(privateKey: key))
        ))
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        if hostKey == expectedHostKey {
            validationCompletePromise.succeed()
        } else {
            validationCompletePromise.fail(RemoteAccessError.hostKeyMismatch)
            // NIOSSH stalls rather than closing on a rejected host key.
            watcher.fail(RemoteAccessError.hostKeyMismatch)
        }
    }
}

/// Accepts an Ed25519 key that proves itself under this build flavor's
/// username, when the host's registry knows it — revoked keys included, so
/// the host can tell a revoked device it's denied. Whether that device may
/// use the host is decided afterwards, on the tunnel's control stream, where
/// the host can explain a refusal.
private final class ServerAuthenticator: NIOSSHServerUserAuthenticationDelegate, Sendable {
    private let username: String
    private let admits: @Sendable (String) -> Bool
    private let watcher: NIOLoopBound<AuthenticationWatcher>
    private let authenticated = Mutex<String?>(nil)

    /// The endpoint ID of the key that authenticated, once one has.
    var authenticatedEndpointID: String? {
        authenticated.withLock { $0 }
    }

    init(username: String, admits: @escaping @Sendable (String) -> Bool, watcher: NIOLoopBound<AuthenticationWatcher>) {
        self.username = username
        self.admits = admits
        self.watcher = watcher
    }

    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods { .publicKey }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        // NIOSSH verifies the signature before asking, so the key is proven.
        guard request.username == username,
              case .publicKey(let offer) = request.request,
              let endpointID = SSHKeys.endpointID(of: offer.publicKey)
        else {
            responsePromise.succeed(.failure)
            return
        }
        // The registry lookup is a blocking Keychain call, so it runs on a
        // dispatch queue: never the event loop or Swift's cooperative pool.
        let eventLoop = responsePromise.futureResult.eventLoop
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            guard admits(endpointID) else {
                responsePromise.succeed(.failure)
                return
            }
            authenticated.withLock { $0 = endpointID }
            responsePromise.succeed(.success)
            // NIOSSH signals success only to clients; the server learns it here.
            eventLoop.execute { self.watcher.value.succeed() }
        }
    }
}

/// Completes a promise when SSH authentication finishes — on the client's
/// `UserAuthSuccessEvent`, or when the server's delegate accepts — and fails
/// it, closing the connection, on any error first. It watches the channel's
/// `closeFuture` because NIOSSH doesn't pass `channelInactive` down the parent
/// pipeline, and the server's delegate reports success itself because NIOSSH
/// signals it only on the client.
private final class AuthenticationWatcher: ChannelInboundHandler {
    typealias InboundIn = Any

    private var promise: EventLoopPromise<Void>?
    private let succeedsOnAuthEvent: Bool
    private var context: ChannelHandlerContext?

    init(promise: EventLoopPromise<Void>, succeedsOnAuthEvent: Bool) {
        self.promise = promise
        self.succeedsOnAuthEvent = succeedsOnAuthEvent
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        // NIOSSHHandler doesn't pass `channelInactive` on, so watch for the
        // close directly.
        context.channel.closeFuture.assumeIsolated().whenComplete { _ in
            self.complete(with: .failure(RemoteAccessError.unexpectedEndOfStream))
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
    }

    /// Marks authentication as finished.
    func succeed() {
        complete(with: .success(()))
    }

    /// Fails authentication and closes the connection.
    func fail(_ error: any Error) {
        complete(with: .failure(error))
        context?.close(promise: nil)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if succeedsOnAuthEvent, event is UserAuthSuccessEvent {
            succeed()
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        complete(with: .failure(error))
        context.close(promise: nil)
    }

    private func complete(with result: Result<Void, any Error>) {
        promise?.completeWith(result)
        promise = nil
    }
}

/// An authenticated SSH connection to another device.
struct SSHTunnelConnection: TunnelConnection {
    let channel: any Channel
    let remoteEndpointID: String
    /// How the connection reaches the peer.
    let path: ConnectionPath
    /// Streams the peer opened. Only hosts accept streams.
    let incoming: AsyncInbox<ChannelByteStream>

    func openStream() async throws -> any ByteStream {
        try await SSHPipeline.openStream(on: channel)
    }

    func acceptStream() async throws -> any ByteStream {
        guard let stream = await incoming.next() else {
            throw RemoteAccessError.unexpectedEndOfStream
        }
        return stream
    }

    func close(reason: String) {
        RemoteLog.tunnel.debug("Closing tunnel with \(remoteEndpointID.prefix(12), privacy: .public): \(reason, privacy: .public)")
        channel.close(promise: nil)
    }

    func waitUntilClosed() async {
        try? await channel.closeFuture.get()
    }
}

/// A connection that reached the host's SSH server and is authenticating.
struct SSHIncomingTunnel: IncomingTunnel {
    let channel: any Channel
    let authenticated: EventLoopFuture<String>
    let incoming: AsyncInbox<ChannelByteStream>
    /// How the tunnel reached this host.
    let path: ConnectionPath

    func accept() async throws -> any TunnelConnection {
        let endpointID = try await authenticated.get()
        return SSHTunnelConnection(channel: channel, remoteEndpointID: endpointID, path: path, incoming: incoming)
    }

    func refuse() async {
        try? await channel.close().get()
    }
}

/// A FIFO handed from event-loop callbacks to async consumers.
final class AsyncInbox<Element: Sendable>: Sendable {
    private struct Waiter {
        let id: Int
        let continuation: CheckedContinuation<Element?, Never>
    }

    private struct State {
        var items: [Element] = []
        var waiters: [Waiter] = []
        var nextWaiterID = 0
        var isFinished = false
    }

    private let state = Mutex(State())

    /// Elements waiting to be taken.
    var count: Int {
        state.withLock { $0.items.count }
    }

    /// Adds `element`. Returns false, dropping it, once the inbox is finished.
    @discardableResult
    func push(_ element: Element) -> Bool {
        let (accepted, waiter) = state.withLock { state -> (Bool, Waiter?) in
            guard !state.isFinished else { return (false, nil) }
            guard state.waiters.isEmpty else { return (true, state.waiters.removeFirst()) }
            state.items.append(element)
            return (true, nil)
        }
        waiter?.continuation.resume(returning: element)
        return accepted
    }

    /// Ends the inbox: waiting and later calls to ``next()`` return nil once
    /// the queued elements are taken.
    func finish() {
        let waiters = state.withLock { state -> [Waiter] in
            state.isFinished = true
            defer { state.waiters = [] }
            return state.waiters
        }
        waiters.forEach { $0.continuation.resume(returning: nil) }
    }

    /// The next element, waiting for one if needed. Nil once finished, or
    /// when the calling task is cancelled; a cancelled wait never takes an
    /// element, so the next one goes to the next caller.
    func next() async -> Element? {
        let id = state.withLock { state -> Int in
            defer { state.nextWaiterID += 1 }
            return state.nextWaiterID
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let ready = state.withLock { state -> Element?? in
                    if Task.isCancelled { return .some(nil) }
                    if !state.items.isEmpty { return .some(state.items.removeFirst()) }
                    if state.isFinished { return .some(nil) }
                    state.waiters.append(Waiter(id: id, continuation: continuation))
                    return nil
                }
                if let ready {
                    continuation.resume(returning: ready)
                }
            }
        } onCancel: {
            let waiter = state.withLock { state -> Waiter? in
                guard let index = state.waiters.firstIndex(where: { $0.id == id }) else { return nil }
                return state.waiters.remove(at: index)
            }
            waiter?.continuation.resume(returning: nil)
        }
    }
}
