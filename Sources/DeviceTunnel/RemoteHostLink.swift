import Foundation
import os
import Synchronization

/// A client's tunnel to one host, exposed as `http://127.0.0.1:<port>`.
///
/// The link keeps a loopback listener while connected and a tunnel for as
/// long as it can hold one, reconnecting with backoff when the tunnel
/// drops — the listener rebinds on every reconnect, because a suspended
/// app can lose its listener socket without telling us. Every TCP
/// connection the app makes to the listener becomes one stream through the
/// tunnel, which the host splices to its local server, so `URLSession` code
/// talks to a remote device exactly as it talks to a local server.
///
/// Each connection attempt keeps the tunnel and listener it builds to
/// itself until it has checked that it still belongs to the current
/// generation, so a loop that ``stop()`` or ``reconnect()`` replaced can
/// never overwrite its successor's tunnel, listener, or state.
///
/// A tunnel that runs through the relay keeps looking for a direct one —
/// right away, every ``directProbeInterval``, and whenever the network,
/// routes, or the host's record change — and the first direct tunnel the
/// host approves takes its place on the same listener.
///
/// A link dials only a host this device's user trusts (``TrustedHosts``);
/// until then it stops in ``State/untrustedHost(hostName:fingerprint:)``.
///
/// Every process on this device can connect to the loopback port, and
/// reaches the host as this device. Send the host's token with every
/// request, and don't hand the port to code you don't trust.
public actor RemoteHostLink {
    /// Where the link stands.
    public enum State: Sendable, Equatable {
        /// Trying to reach the host.
        case connecting
        /// This device's user hasn't trusted the host, or distrusted it.
        /// The link stops; once the user compares `fingerprint` with the
        /// one the host shows and trusts it, call ``reconnect()``.
        case untrustedHost(hostName: String, fingerprint: String)
        /// The host's user hasn't approved this device yet.
        case awaitingApproval(hostName: String)
        /// The host's API is reachable at `127.0.0.1:port` with `token`,
        /// through a tunnel that takes `path`.
        case connected(port: UInt16, token: String, path: ConnectionPath)
        /// The host's user refused this device. The link stops until
        /// ``reconnect()``.
        case denied(hostName: String)
        /// The host hasn't received this device's registry record yet.
        case notRecognized
        /// Local Network privacy blocked the dial; only the user can fix
        /// it, in Settings. The link keeps retrying.
        case localNetworkDenied
        /// The host answered but can't serve right now.
        case unavailable(reason: String)
        /// The host couldn't be reached; the link keeps retrying.
        case unreachable(reason: String)
    }

    private enum Outcome {
        case retry(after: Duration, resetBackoff: Bool)
        case stop
    }

    /// The wait before the first retry, which doubles up to ``maximumBackoff``.
    static let initialBackoff: Duration = .seconds(1)
    /// The longest wait between retries.
    static let maximumBackoff: Duration = .seconds(30)
    /// The wait before asking a host that didn't recognize this device
    /// again. iCloud Keychain usually delivers the record within seconds.
    static let notRecognizedRetry: Duration = .seconds(10)
    /// How often a relayed tunnel dials the host's direct routes again.
    static let directProbeInterval: Duration = .seconds(30)
    /// How long one dial, every route raced, may take to produce a tunnel.
    static let dialTimeout: Duration = .seconds(20)
    /// What ``State/unavailable(reason:)`` says when the two devices'
    /// versions can't talk to each other.
    static let updateBothDevices = "Update the app on both devices to connect."

    /// The host's endpoint ID.
    public nonisolated let hostEndpointID: String

    private let transport: any TunnelTransport
    /// The hosts this device's user trusts.
    private let trustedHosts: TrustedHosts
    /// The host's latest registry record, written without waiting for the
    /// actor so that the most recent ``update(host:)`` always wins.
    private let latestHost: Mutex<DeviceRecord>
    private let onStateChange: @Sendable (State) async -> Void
    private var state: State = .connecting
    private var listener: LoopbackListener?
    /// Identifies `listener`, so a failure reported by one it replaced is ignored.
    private var listenerID: UUID?
    private var connection: (any TunnelConnection)?
    /// Identifies `connection`, so the loop serving it can tell a tunnel
    /// that closed from one a direct tunnel replaced.
    private var connectionID: UUID?
    /// The port the current listener is bound to.
    private var listenerPort: UInt16?
    private var loopTask: Task<Void, Never>?
    /// Bumped whenever a connection loop starts or stops, so a loop that
    /// was replaced can't overwrite its successor's state.
    private var generation = 0
    /// The routes the current or latest attempt dialed.
    private var dialedRoutes: Routes
    /// Whether an attempt is dialing or handshaking, before the host answers.
    private var isDialing = false
    /// The wait before the next attempt, while there is one.
    private var retryWait: Task<Void, Never>?
    /// Set when something that could make the next attempt succeed changed
    /// during this one, so that if this one fails, the next goes at once.
    private var retryImmediately = false
    /// Looks for a direct tunnel while the current one runs through the relay.
    private var directProbe: Task<Void, Never>?
    /// The pause between direct probes, cancelled to probe at once.
    private var directProbeWait: Task<Void, Never>?
    /// Whether the direct probe is handshaking with a host that answered.
    private var isProbeHandshaking = false
    /// Set once the relayed tunnel closed: the probe finishes the handshake
    /// it's in, if any, and stops.
    private var isDirectProbeEnding = false
    /// Set when something that could open a direct path changed during a
    /// probe, so that if the probe fails, the next goes at once.
    private var probeImmediately = false

    /// A host record's routes, as far as redialing cares.
    private struct Routes: Equatable {
        /// The record's direct addresses.
        var directAddresses: [String]
        /// The record's relay.
        var relayAddress: String?

        /// The routes `record` publishes.
        init(_ record: DeviceRecord) {
            directAddresses = record.directAddresses
            relayAddress = record.relayAddress
        }
    }

    /// Creates a link to `host` over `node`, which connects only while
    /// `trustedHosts` trusts the host. Call ``start()`` to begin
    /// connecting; `onStateChange` receives every state transition.
    public init(
        node: RemoteNode,
        host: DeviceRecord,
        trustedHosts: TrustedHosts,
        onStateChange: @escaping @Sendable (State) async -> Void
    ) {
        self.init(transport: node, host: host, trustedHosts: trustedHosts, onStateChange: onStateChange)
    }

    init(
        transport: any TunnelTransport,
        host: DeviceRecord,
        trustedHosts: TrustedHosts,
        onStateChange: @escaping @Sendable (State) async -> Void
    ) {
        self.transport = transport
        self.trustedHosts = trustedHosts
        self.latestHost = Mutex(host)
        self.hostEndpointID = host.endpointID
        self.dialedRoutes = Routes(host)
        self.onStateChange = onStateChange
    }

    /// Starts connecting. Does nothing if the link is already running.
    public func start() {
        guard loopTask == nil else { return }
        generation += 1
        let generation = generation
        loopTask = Task { await self.runLoop(generation: generation) }
    }

    /// Closes the tunnel and the loopback listener.
    public func stop() {
        endLoop(reason: "link stopped")
        listener?.stop()
        listener = nil
        listenerID = nil
        listenerPort = nil
    }

    /// Drops the tunnel and the loopback listener and connects again from
    /// scratch: on Try Again, after the host rejected the token, when the
    /// listener fails, and when the app returns from the background or the
    /// Mac wakes. A suspended app can lose its listener socket without
    /// `onFailure` firing, and a tunnel that died meanwhile can look open
    /// until TCP gives up; requests on the old port fail fast instead of
    /// hanging.
    ///
    /// This is the link's only reset. A narrower one, such as rebuilding just
    /// the listener, would leave states this doesn't cover.
    public func reconnect() {
        RemoteLog.link.notice("Reconnecting to \(self.hostName, privacy: .public) (was \(self.stateLabel, privacy: .public))")
        stop()
        start()
    }

    /// Adopts the host's latest registry record. Callable from anywhere
    /// without waiting, and the most recent call wins however the calls are
    /// scheduled. New addresses redial at once unless the link is connected
    /// or waiting on the host's user.
    public nonisolated func update(host newHost: DeviceRecord) {
        latestHost.withLock { $0 = newHost }
        Task { await self.hostUpdated() }
    }

    /// Tells the link this device's network changed. A link waiting to
    /// retry redials now; one in the middle of a dial lets it finish, and
    /// retries at once if it fails. A relayed tunnel looks for a direct one.
    public func networkChanged() {
        redialSoon(restartingDial: false)
    }

    /// Tells the link a new way to reach the host turned up, such as a
    /// Bonjour advertisement, or that this device started using relays.
    /// Redials now, abandoning a dial in progress, unless the link is
    /// connected or waiting on the host's user; a relayed tunnel looks for
    /// a direct one.
    public func routesChanged() {
        redialSoon(restartingDial: true)
    }

    private func hostUpdated() {
        let routes = latestHost.withLock { Routes($0) }
        guard routes != dialedRoutes else { return }
        routesChanged()
    }

    /// Dials again without waiting out the retry delay. While connected it
    /// instead hurries the direct probe, if one runs, since the only better
    /// route is a direct one. `restartingDial` abandons a dial in progress,
    /// for changes that make its routes stale.
    private func redialSoon(restartingDial: Bool) {
        guard loopTask != nil else { return }
        guard connection == nil else {
            if let directProbeWait {
                directProbeWait.cancel()
            } else if directProbe != nil {
                probeImmediately = true
            }
            return
        }
        if case .awaitingApproval = state { return }
        if let retryWait {
            retryWait.cancel()
        } else if restartingDial, isDialing {
            reconnect()
        } else {
            retryImmediately = true
        }
    }

    private func endLoop(reason: String) {
        generation += 1
        loopTask?.cancel()
        loopTask = nil
        retryWait?.cancel()
        retryWait = nil
        isDialing = false
        retryImmediately = false
        stopDirectProbe()
        connection?.close(reason: reason)
        connection = nil
        connectionID = nil
    }

    private var hostName: String {
        latestHost.withLock { $0.name }
    }

    // MARK: - Connection loop

    private func runLoop(generation: Int) async {
        var backoff = Self.initialBackoff
        while generation == self.generation {
            let outcome = await attempt(backoff: backoff, generation: generation)
            guard generation == self.generation else { return }
            guard case .retry(let delay, let resetBackoff) = outcome else {
                loopTask = nil
                return
            }
            backoff = resetBackoff ? Self.initialBackoff : min(backoff * 2, Self.maximumBackoff)
            if retryImmediately {
                retryImmediately = false
                backoff = Self.initialBackoff
            } else if await pause(for: delay, generation: generation) {
                backoff = Self.initialBackoff
            }
        }
    }

    /// Waits `delay` before the next attempt. Returns true when
    /// ``redialSoon(restartingDial:)`` cut the wait short.
    private func pause(for delay: Duration, generation: Int) async -> Bool {
        let wait = Task<Void, Never> { try? await Task.sleep(for: delay) }
        retryWait = wait
        await withTaskCancellationHandler {
            await wait.value
        } onCancel: {
            wait.cancel()
        }
        guard generation == self.generation else { return false }
        retryWait = nil
        return wait.isCancelled
    }

    /// Dials the host and handshakes once, then serves the tunnel until it
    /// closes. Commits nothing to the actor until it has checked its
    /// generation, so every `await` on this path must be followed by that check.
    private func attempt(backoff: Duration, generation: Int) async -> Outcome {
        let host = latestHost.withLock { $0 }
        let trusted: Bool
        do {
            trusted = try isTrusted(host)
        } catch {
            RemoteLog.link.error("Keychain read failed while checking trust in \(host.name, privacy: .public): \(error.localizedDescription, privacy: .public)")
            await setState(.unavailable(reason: "This device couldn't read which hosts it trusts."), generation: generation)
            return .retry(after: backoff, resetBackoff: false)
        }
        guard trusted else {
            await setState(.untrustedHost(hostName: host.name, fingerprint: host.fingerprint), generation: generation)
            return .stop
        }
        dialedRoutes = Routes(host)
        isDialing = true
        await setState(.connecting, generation: generation)

        let transport = transport
        let connection: any TunnelConnection
        do {
            connection = try await withTimeout(Self.dialTimeout, discardingLateResult: { $0.close(reason: "abandoned") }) {
                try await transport.connect(to: host, allowingRelay: true)
            }
        } catch {
            return await failed(error, backoff: backoff, generation: generation)
        }
        guard generation == self.generation else {
            connection.close(reason: "link stopped")
            return .stop
        }

        let reply: HostReply
        do {
            // The wait for approval has no deadline, so a link stopped
            // meanwhile must close the connection to end it.
            reply = try await withTaskCancellationHandler {
                try await handshake(on: connection, generation: generation)
            } onCancel: {
                connection.close(reason: "link stopped")
            }
        } catch {
            connection.close(reason: "handshake failed")
            return await failed(error, backoff: backoff, generation: generation)
        }
        guard generation == self.generation else {
            connection.close(reason: "link stopped")
            return .stop
        }
        isDialing = false

        switch reply {
        case .approved(let token, _):
            return await serve(connection, token: token, backoff: backoff, generation: generation)
        case .denied(let hostName):
            connection.close(reason: "denied")
            await setState(.denied(hostName: hostName), generation: generation)
            return .stop
        case .unknownDevice:
            connection.close(reason: "not recognized")
            await setState(.notRecognized, generation: generation)
            return .retry(after: Self.notRecognizedRetry, resetBackoff: true)
        case .unsupportedProtocol:
            connection.close(reason: "unsupported protocol")
            await setState(.unavailable(reason: Self.updateBothDevices), generation: generation)
            return .stop
        case .unavailable(let reason):
            connection.close(reason: "unavailable")
            await setState(.unavailable(reason: reason), generation: generation)
            return .retry(after: backoff, resetBackoff: false)
        case .pendingApproval:
            connection.close(reason: "unexpected reply")
            return .retry(after: backoff, resetBackoff: false)
        }
    }

    /// Publishes an approved tunnel on a freshly bound loopback listener,
    /// then serves it, and any direct tunnel that replaces it, until the
    /// tunnel in use closes.
    private func serve(_ connection: any TunnelConnection, token: String, backoff: Duration, generation: Int) async -> Outcome {
        // Always rebind. The port from an earlier connection may have been
        // reclaimed while the app was suspended, and with the tunnel down
        // the link was `.unreachable`, so nothing else would have caught
        // it; only a fresh bind here guarantees the port we publish exists.
        let bound: (listener: LoopbackListener, id: UUID, port: UInt16)
        do {
            bound = try await makeListener()
        } catch {
            connection.close(reason: "couldn't bind listener")
            return await failed(error, backoff: backoff, generation: generation)
        }
        guard generation == self.generation else {
            bound.listener.stop()
            connection.close(reason: "link stopped")
            return .stop
        }
        listener?.stop()
        listener = bound.listener
        listenerID = bound.id
        listenerPort = bound.port
        retryImmediately = false
        await adopt(connection, token: token, generation: generation)

        var current = connection
        while true {
            let waitedID = connectionID
            await current.waitUntilClosed()
            guard generation == self.generation else { return .stop }
            await settleDirectProbe()
            guard generation == self.generation else { return .stop }
            if connectionID != waitedID, let replacement = self.connection {
                current = replacement
                continue
            }
            self.connection = nil
            connectionID = nil
            await setState(.unreachable(reason: "The connection was lost."), generation: generation)
            return .retry(after: .seconds(1), resetBackoff: true)
        }
    }

    /// Makes `connection` the tunnel new requests use, publishes it on the
    /// current listener, and starts looking for a direct tunnel if it runs
    /// through the relay. Returns false, adopting nothing, while no
    /// listener is up.
    @discardableResult
    private func adopt(_ connection: any TunnelConnection, token: String, generation: Int) async -> Bool {
        guard let port = listenerPort else { return false }
        let id = UUID()
        stopDirectProbe()
        self.connection = connection
        connectionID = id
        if connection.path == .relay {
            isDirectProbeEnding = false
            probeImmediately = false
            directProbe = Task { await self.probeDirectRoutes(replacing: id, generation: generation) }
        }
        await setState(.connected(port: port, token: token, path: connection.path), generation: generation)
        RemoteLog.link.notice("Connected to \(self.hostName, privacy: .public) on 127.0.0.1:\(port), \(connection.path == .relay ? "through the relay" : "directly", privacy: .public)")
        return true
    }

    // MARK: - Moving off the relay

    /// Dials the host's direct routes while the tunnel `relayedID` runs
    /// through the relay, until one replaces it, it closes, or the link
    /// stops. Probes at once, then every ``directProbeInterval`` or sooner
    /// when ``redialSoon(restartingDial:)`` cuts the wait short.
    private func probeDirectRoutes(replacing relayedID: UUID, generation: Int) async {
        while isProbing(for: relayedID, generation: generation) {
            probeImmediately = false
            if await probeDirectRoute(replacing: relayedID, generation: generation) { return }
            guard isProbing(for: relayedID, generation: generation) else { return }
            guard !probeImmediately else { continue }
            let wait = Task<Void, Never> { try? await Task.sleep(for: Self.directProbeInterval) }
            directProbeWait = wait
            await withTaskCancellationHandler {
                await wait.value
            } onCancel: {
                wait.cancel()
            }
            if directProbeWait == wait {
                directProbeWait = nil
            }
        }
    }

    /// Whether the probe for the relayed tunnel `relayedID` should go on.
    private func isProbing(for relayedID: UUID, generation: Int) -> Bool {
        generation == self.generation && connectionID == relayedID && !isDirectProbeEnding && !Task.isCancelled
    }

    /// Dials the host's direct routes once, and adopts the tunnel if the
    /// host approves it while the relayed tunnel `relayedID` is still the
    /// one in use. Returns whether it did.
    private func probeDirectRoute(replacing relayedID: UUID, generation: Int) async -> Bool {
        let host = latestHost.withLock { $0 }
        guard (try? isTrusted(host)) == true else { return false }
        dialedRoutes = Routes(host)
        let transport = transport
        let direct: any TunnelConnection
        do {
            direct = try await withTimeout(Self.dialTimeout, discardingLateResult: { $0.close(reason: "abandoned") }) {
                try await transport.connect(to: host, allowingRelay: false)
            }
        } catch {
            RemoteLog.link.debug("No direct route to \(self.hostName, privacy: .public) yet: \(error.localizedDescription, privacy: .public)")
            return false
        }
        guard generation == self.generation, connectionID == relayedID, !Task.isCancelled else {
            direct.close(reason: "no longer needed")
            return false
        }
        isProbeHandshaking = true
        defer { isProbeHandshaking = false }
        let reply: HostReply
        do {
            reply = try await withTaskCancellationHandler {
                try await handshake(on: direct, generation: generation, waitsForApproval: false)
            } onCancel: {
                direct.close(reason: "link stopped")
            }
        } catch {
            RemoteLog.link.debug("Direct handshake with \(self.hostName, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            direct.close(reason: "handshake failed")
            return false
        }
        // The host closes the relayed tunnel as soon as it approves this one,
        // so the relayed tunnel may already be gone; it's still the one in use
        // until this adopts its replacement.
        guard case .approved(let token, _) = reply, generation == self.generation, connectionID == relayedID else {
            direct.close(reason: "not approved")
            return false
        }
        let relayed = connection
        // This runs inside `directProbe`; forgetting it first keeps
        // `adopt`'s `stopDirectProbe()` from cancelling this very task.
        directProbe = nil
        guard await adopt(direct, token: token, generation: generation) else {
            direct.close(reason: "no listener")
            return false
        }
        relayed?.close(reason: "moved to a direct connection")
        return true
    }

    /// Ends the direct probe once the relayed tunnel closed: a probe
    /// handshaking with the host finishes, since its tunnel may be what
    /// replaced the relayed one, and a probe dialing or waiting stops. The
    /// link reports the loss only after that, which a host that answered
    /// the dial but stalls the handshake can delay by the handshake's
    /// timeouts.
    private func settleDirectProbe() async {
        guard let probe = directProbe else { return }
        isDirectProbeEnding = true
        directProbeWait?.cancel()
        if !isProbeHandshaking {
            probe.cancel()
        }
        await probe.value
        if directProbe == probe {
            directProbe = nil
        }
    }

    /// Stops the direct probe, abandoning any dial or handshake it's in.
    private func stopDirectProbe() {
        directProbe?.cancel()
        directProbe = nil
        directProbeWait?.cancel()
        directProbeWait = nil
    }

    /// Records why an attempt failed and when to try again.
    private func failed(_ error: any Error, backoff: Duration, generation: Int) async -> Outcome {
        guard generation == self.generation else { return .stop }
        isDialing = false
        switch error as? RemoteAccessError {
        case .notRecognized?:
            await setState(.notRecognized, generation: generation)
            return .retry(after: Self.notRecognizedRetry, resetBackoff: true)
        case .localNetworkDenied?:
            await setState(.localNetworkDenied, generation: generation)
        case .outdatedPeer?:
            await setState(.unavailable(reason: Self.updateBothDevices), generation: generation)
        default:
            RemoteLog.link.info("Couldn't reach \(self.hostName, privacy: .public): \(error.localizedDescription, privacy: .public)")
            await setState(.unreachable(reason: error.localizedDescription), generation: generation)
        }
        return .retry(after: backoff, resetBackoff: false)
    }

    /// Whether this device's user trusts `host`. Throws when the Keychain
    /// can't say, which callers treat as not trusted.
    private func isTrusted(_ host: DeviceRecord) throws -> Bool {
        try trustedHosts.decision(for: host.endpointID) == .approved
    }

    /// Says hello on a new tunnel and returns the host's answer. With
    /// `waitsForApproval`, a host that has to ask its user first is waited
    /// on, without a deadline; otherwise its `pendingApproval` is returned.
    private func handshake(on connection: any TunnelConnection, generation: Int, waitsForApproval: Bool = true) async throws -> HostReply {
        let control = try await withTimeout(.seconds(10), discardingLateResult: Self.abandon) {
            try await connection.openStream()
        }
        try await FrameCodec.write(ClientHello(protocolVersion: DeviceRecord.currentProtocolVersion), to: control)
        var reply = try await withTimeout(.seconds(15)) { try await FrameCodec.read(HostReply.self, from: control) }
        if case .pendingApproval(let hostName) = reply, waitsForApproval {
            await setState(.awaitingApproval(hostName: hostName), generation: generation)
            // No deadline: the host's user may take a while to walk over.
            reply = try await FrameCodec.read(HostReply.self, from: control)
        }
        try? await control.finish()
        return reply
    }

    /// Publishes `newState` unless the loop that computed it has been replaced.
    private func setState(_ newState: State, generation: Int) async {
        guard generation == self.generation, newState != state else { return }
        state = newState
        await onStateChange(newState)
    }

    /// A short, token-free description of `state` for logging.
    private var stateLabel: String {
        switch state {
        case .connecting: "connecting"
        case .untrustedHost: "untrustedHost"
        case .awaitingApproval: "awaitingApproval"
        case .connected(let port, _, let path): "connected(port: \(port), \(path))"
        case .denied: "denied"
        case .notRecognized: "notRecognized"
        case .localNetworkDenied: "localNetworkDenied"
        case .unavailable: "unavailable"
        case .unreachable: "unreachable"
        }
    }

    // MARK: - Loopback listener

    private func makeListener() async throws -> (listener: LoopbackListener, id: UUID, port: UInt16) {
        let id = UUID()
        let listener = try LoopbackListener(
            onConnection: { [weak self] tcp in
                Task {
                    guard let self else {
                        await tcp.abort()
                        return
                    }
                    await self.forward(tcp)
                }
            },
            onFailure: { [weak self] reason in
                Task { await self?.listenerFailed(reason, id: id) }
            }
        )
        return (listener, id, try await listener.start())
    }

    /// Resets the link when its listener fails, as iOS does to the sockets
    /// of suspended apps. A new listener means a new port, which a
    /// reconnect publishes anyway.
    private func listenerFailed(_ reason: String, id: UUID) {
        guard id == listenerID else { return }
        RemoteLog.link.info("Loopback listener for \(self.hostName, privacy: .public) failed: \(reason, privacy: .public)")
        listener = nil
        listenerID = nil
        listenerPort = nil
        // A link that stopped (a declined device) stays stopped.
        if loopTask != nil {
            reconnect()
        }
    }

    private func forward(_ tcp: TCPStream) async {
        guard let connection = await currentConnection(waitingUpTo: .seconds(10)) else {
            await tcp.abort()
            return
        }
        await Self.splice(tcp, through: connection)
    }

    /// The open tunnel, waiting briefly for one while the link reconnects so
    /// a request made during a network handoff doesn't fail outright.
    private func currentConnection(waitingUpTo timeout: Duration) async -> (any TunnelConnection)? {
        let deadline = ContinuousClock.now + timeout
        while connection == nil, ContinuousClock.now < deadline, loopTask != nil {
            try? await Task.sleep(for: .milliseconds(200))
        }
        return connection
    }

    /// Opens a stream on `connection` and splices `tcp` to it. Opening is
    /// bounded to 10 seconds, and a timeout closes the tunnel, so one that
    /// looks open but died underneath fails fast instead of hanging requests.
    private nonisolated static func splice(_ tcp: TCPStream, through connection: any TunnelConnection) async {
        do {
            let stream = try await withTimeout(.seconds(10), discardingLateResult: abandon) {
                try await connection.openStream()
            }
            await StreamSplice.run(tcp, stream)
        } catch {
            RemoteLog.link.error("Couldn't open a stream: \(error.localizedDescription, privacy: .public)")
            if case RemoteAccessError.timedOut = error {
                connection.close(reason: "stream open timed out")
            }
            await tcp.abort()
        }
    }

    /// Tears down a stream that opened after its caller stopped waiting.
    private static let abandon: @Sendable (any ByteStream) -> Void = { stream in
        Task { await stream.abort() }
    }
}
