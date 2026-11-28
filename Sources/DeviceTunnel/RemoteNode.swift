import CryptoKit
import Foundation
import Network
import NIOCore
import NIOSSH
import NIOTransportServices
import RendezvousRelayClient
import RendezvousRelayProtocol
import Synchronization

/// This process's tunnel endpoint.
///
/// One identity serves both roles: a Mac accepts tunnels as a host and dials
/// other Macs as a client. Tunnels are SSH sessions in which each device's
/// Ed25519 key is its SSH key, so both ends are authenticated by the keys the
/// registry lists and everything is encrypted end to end.
///
/// A host listens for direct TCP connections on every interface, puts the
/// ``AccessGate`` in front of SSH on each, and advertises the listener over
/// Bonjour under a blinded name and tag. A client dials every route it
/// knows at once: the Bonjour advertisements it found on the local network,
/// and the addresses the host's registry record publishes, which include
/// the DNS names of the host's addresses so name-based network policy, such
/// as a VPN that connects on demand for the host's domain, applies.
///
/// A host can also stay registered with a relay (``setRelay(_:)``), and a
/// client that uses relays (``setDialsThroughRelays(_:)``) dials the relay a
/// host publishes as one more route, a moment after the direct ones, so a
/// direct path that answers always wins. The relay only copies the SSH
/// session's bytes; the keys are checked end to end as on any route.
public final class RemoteNode: Sendable {
    /// Where a host's registration with its relay stands.
    public enum RelayStatus: Sendable, Equatable {
        /// No relay is configured.
        case off
        /// Dialing the relay or proving this device's key to it.
        case connecting
        /// Registered: devices that can't reach this Mac directly can
        /// connect through the relay.
        case registered
        /// The last attempt failed for `reason`; the registration retries.
        case unavailable(reason: String)
    }

    /// This device's identity; its endpoint ID is what peers dial.
    public let identity: DeviceIdentity

    private let configuration: RemoteAccessConfiguration
    private let sshKey: NIOSSHPrivateKey
    /// Signs relay proofs; the same key as ``sshKey``.
    private let signingKey: Curve25519.Signing.PrivateKey
    private let incoming: AsyncInbox<SSHIncomingTunnel>
    /// The devices a host admits; nil for a client.
    private let registry: DeviceRegistry?
    /// Fixed direct address to publish instead of the interfaces' addresses.
    private let publishedHost: String?
    /// Bounds the direct connections waiting at the access gate.
    let gateLimiter: AccessGateLimiter
    /// Runs ``HostNames`` lookups one at a time, off the cooperative thread
    /// pool, since they block on DNS.
    private let hostNameQueue = DispatchQueue(label: "dev.bunch.DeviceTunnel.hostnames")
    private let state: Mutex<State>

    private struct State {
        var listener: (any Channel)?
        /// The Network framework listener under `listener`, whose Bonjour
        /// advertisement is renewed on every network change.
        var advertiser: NWListener?
        var listeningPort: UInt16?
        var directAddresses: [String] = []
        /// The confirmed DNS names of this host's addresses, by address
        /// (``HostNames``), published after the addresses.
        var hostNames: [String: String] = [:]
        /// Bumped on every address refresh, so only the newest refresh's
        /// name lookup is published.
        var addressGeneration = 0
        /// Every host advertisement discovery currently sees.
        var advertisements: [Advertisement] = []
        /// The gate keys of the hosts this node has dialed, by endpoint ID,
        /// for telling which advertisements are theirs.
        var knownHosts: [String: Data] = [:]
        /// The advertised routes of each known host.
        var discoveredRoutes: [String: [NWEndpoint]] = [:]
        var networkMonitor: NetworkChangeMonitor?
        var browser: ServiceBrowser?
        /// Rebinds a listener that failed, while it's trying.
        var rebind: Task<Void, Never>?
        var addressObservers: [@Sendable () -> Void] = []
        var networkObservers: [@Sendable () -> Void] = []
        var routeObservers: [@Sendable (Set<String>) -> Void] = []
        /// The relay this host registers with, and the registration.
        var relay: (address: RelayAddress, registration: RelayHost)?
        /// Bumped whenever the relay changes, so a replaced registration's
        /// late status reports are ignored.
        var relayGeneration = 0
        /// Where the relay registration stands.
        var relayStatus: RelayStatus = .off
        /// Called on every change to `relayStatus`.
        var relayObservers: [@Sendable (RelayStatus) -> Void] = []
        /// Whether ``connect(to:allowingRelay:)`` may dial hosts' relays.
        var dialsThroughRelays = false
        var isClosed = false
    }

    /// How long establishing one path may take, access gate and SSH
    /// handshake included.
    static let attemptTimeout: Duration = .seconds(15)
    /// Most connections waiting for the host service to take them.
    static let maxQueuedConnections = 64
    /// How many times a failed listener tries its old port before moving.
    static let samePortAttempts = 3
    /// How long the direct routes get before the relay is dialed alongside
    /// them, so a direct path that answers promptly always wins.
    static let relayHeadStart: Duration = .milliseconds(750)
    /// How long a TCP connection to a device or relay may take to open.
    static let connectTimeout: TimeAmount = .seconds(5)

    private init(
        identity: DeviceIdentity,
        configuration: RemoteAccessConfiguration,
        sshKey: NIOSSHPrivateKey,
        signingKey: Curve25519.Signing.PrivateKey,
        incoming: AsyncInbox<SSHIncomingTunnel>,
        registry: DeviceRegistry?,
        listener: BoundListener?,
        publishedHost: String?,
        gateLimiter: AccessGateLimiter
    ) {
        self.identity = identity
        self.configuration = configuration
        self.sshKey = sshKey
        self.signingKey = signingKey
        self.incoming = incoming
        self.registry = registry
        self.publishedHost = publishedHost
        self.gateLimiter = gateLimiter
        self.state = Mutex(State(listener: listener?.channel, advertiser: listener?.advertiser, listeningPort: listener?.port))

        let monitor = NetworkChangeMonitor { [weak self] in self?.networkPathChanged() }
        let browser = configuration.serviceType.map { serviceType in
            ServiceBrowser(serviceType: serviceType, ownGateKey: identity.gateKey) { [weak self] advertisements in
                self?.discovered(advertisements)
            }
        }
        state.withLock { state in
            state.networkMonitor = monitor
            state.browser = browser
        }
        browser?.start()
        if let listener {
            refreshDirectAddresses()
            watch(listener.channel)
        }
    }

    /// Starts an endpoint for `identity`.
    ///
    /// - Parameters:
    ///   - registry: The device list whose members may open tunnels to this
    ///     node, which then listens for them; nil for a client that accepts
    ///     none (iOS devices).
    ///   - preferredPort: The port to listen on if it's free, so a host's
    ///     published addresses survive a relaunch. Any free port otherwise.
    ///   - listenHost: An address to listen on instead of every interface,
    ///     which is then also the only direct address published.
    public static func start(
        identity: DeviceIdentity,
        configuration: RemoteAccessConfiguration,
        acceptingDevicesIn registry: DeviceRegistry?,
        preferredPort: UInt16? = nil,
        listenHost: String? = nil
    ) async throws -> RemoteNode {
        let sshKey = try SSHKeys.privateKey(for: identity)
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: identity.secretKey)
        let incoming = AsyncInbox<SSHIncomingTunnel>()
        let gateLimiter = AccessGateLimiter()
        guard let registry else {
            return RemoteNode(identity: identity, configuration: configuration, sshKey: sshKey, signingKey: signingKey, incoming: incoming, registry: nil, listener: nil, publishedHost: nil, gateLimiter: gateLimiter)
        }
        let listener = try await listen(
            preferredPort: preferredPort,
            listenHost: listenHost,
            setup: HostSetup(sshKey: sshKey, gateKey: identity.gateKey, username: configuration.protocolName, admits: admission(by: registry), incoming: incoming),
            serviceType: configuration.serviceType,
            gateLimiter: gateLimiter
        )
        return RemoteNode(
            identity: identity,
            configuration: configuration,
            sshKey: sshKey,
            signingKey: signingKey,
            incoming: incoming,
            registry: registry,
            listener: listener,
            publishedHost: listenHost,
            gateLimiter: gateLimiter
        )
    }

    /// The port hosts accept direct connections on, or nil for a client.
    public var listeningPort: UInt16? {
        state.withLock { $0.listeningPort }
    }

    /// The listener accepting direct connections, or nil for a client.
    var listenerChannel: (any Channel)? {
        state.withLock { $0.listener }
    }

    /// The direct addresses (`host:port`) where this node can currently be
    /// reached: its IP addresses, then their confirmed DNS names.
    public func address() -> [String] {
        state.withLock { $0.directAddresses }
    }

    /// Calls `handler` right away and again whenever this node's direct
    /// addresses change, until the node closes. Calls can overlap, so read
    /// ``address()`` for the current addresses rather than tracking them.
    public func onAddressChange(_ handler: @escaping @Sendable () -> Void) {
        let isOpen = state.withLock { state -> Bool in
            guard !state.isClosed else { return false }
            state.addressObservers.append(handler)
            return true
        }
        if isOpen {
            handler()
        }
    }

    /// Calls `handler` whenever this device's network path changes, until
    /// the node closes.
    public func onNetworkChange(_ handler: @escaping @Sendable () -> Void) {
        state.withLock { state in
            guard !state.isClosed else { return }
            state.networkObservers.append(handler)
        }
    }

    /// Calls `handler` with the endpoint IDs of hosts whose routes on the
    /// local network appeared or changed, until the node closes. Only hosts
    /// this node has dialed are recognized, since an advertisement names a
    /// host only to a device that knows its gate key.
    public func onRoutesChange(_ handler: @escaping @Sendable (Set<String>) -> Void) {
        state.withLock { state in
            guard !state.isClosed else { return }
            state.routeObservers.append(handler)
        }
    }

    /// Re-reads this host's interface addresses, catching a change — a DHCP
    /// renewal, a new IPv6 address — that came without a network path update.
    public func refreshAddresses() {
        refreshDirectAddresses()
    }

    /// Starts local-network discovery over, as after the app returns from
    /// the background, where a browser can stop reporting without failing.
    public func restartDiscovery() {
        state.withLock { $0.browser }?.start()
    }

    // MARK: - Relay

    /// Returns `string` as a canonical relay `host:port`, filling in the
    /// relay's default port, or nil if it isn't a valid relay address.
    public static func canonicalRelayAddress(_ string: String) -> String? {
        RelayAddress(parsing: string)?.description
    }

    /// Registers this host with the relay at `address` (`host` or
    /// `host:port`), replacing any earlier registration, or ends the
    /// registration with nil. Clients ignore it: they accept no tunnels.
    public func setRelay(_ address: String?) {
        let parsed = address.flatMap { RelayAddress(parsing: $0) }
        // Swapped under the lock so concurrent calls can't leave a
        // registration running that `state` no longer tracks. Starting and
        // stopping only schedule work, so neither calls back into `state`.
        let changed = state.withLock { state -> Bool in
            guard !state.isClosed, let registry, state.relay?.address != parsed else { return false }
            state.relay?.registration.stop()
            state.relayGeneration += 1
            state.relay = parsed.map { relay in
                (relay, makeRelayRegistration(with: relay, registry: registry, generation: state.relayGeneration))
            }
            state.relay?.registration.start()
            return true
        }
        guard changed else { return }
        if let parsed {
            RemoteLog.host.notice("Registering with relay \(parsed.description, privacy: .public)")
        } else {
            relayStatusChanged(to: .off, generation: nil)
        }
    }

    /// Where this host's relay registration stands.
    public var relayStatus: RelayStatus {
        state.withLock { $0.relayStatus }
    }

    /// Calls `handler` right away and again whenever ``relayStatus``
    /// changes, until the node closes.
    public func onRelayStatusChange(_ handler: @escaping @Sendable (RelayStatus) -> Void) {
        let current = state.withLock { state -> RelayStatus? in
            guard !state.isClosed else { return nil }
            state.relayObservers.append(handler)
            return state.relayStatus
        }
        if let current {
            handler(current)
        }
    }

    /// Sets whether connections may go through the relays hosts publish.
    /// Off, only direct routes are dialed.
    public func setDialsThroughRelays(_ enabled: Bool) {
        state.withLock { $0.dialsThroughRelays = enabled }
    }

    /// A registration with `relay` whose sessions run this host's access
    /// gate and then its SSH server.
    private func makeRelayRegistration(with relay: RelayAddress, registry: DeviceRegistry, generation: Int) -> RelayHost {
        let signingKey = signingKey
        let setup = HostSetup(
            sshKey: sshKey,
            gateKey: identity.gateKey,
            username: configuration.protocolName,
            admits: Self.admission(by: registry),
            incoming: incoming
        )
        return RelayHost(
            namespace: configuration.relayNamespace,
            endpointID: identity.endpointID,
            sign: { try signingKey.signature(for: $0) },
            dial: { try await Self.openRelayConnection(to: relay) },
            acceptSession: { channel in
                // The relay already bounds a host's pending sessions, and
                // they all share its address, so no limiter here.
                try Self.gate(channel, path: .relay, setup: setup, limiter: nil)
            },
            onStatusChange: { [weak self] status in
                self?.relayStatusChanged(to: RelayStatus(status), generation: generation)
            },
            log: { message in
                RemoteLog.host.info("Relay: \(message, privacy: .public)")
            }
        )
    }

    /// Publishes `status` unless it comes from a registration that was
    /// replaced (`generation` is nil for the node's own changes).
    private func relayStatusChanged(to status: RelayStatus, generation: Int?) {
        let observers = state.withLock { state -> [@Sendable (RelayStatus) -> Void] in
            guard !state.isClosed, generation == nil || generation == state.relayGeneration, state.relayStatus != status else { return [] }
            state.relayStatus = status
            return state.relayObservers
        }
        if case .unavailable(let reason) = status {
            RemoteLog.host.info("Relay unavailable: \(reason, privacy: .public)")
        }
        observers.forEach { $0(status) }
    }

    /// Opens a TCP connection to `relay` with the tunnel's socket options.
    private static func openRelayConnection(to relay: RelayAddress) async throws -> any Channel {
        try await NIOTSConnectionBootstrap(group: NIOTSEventLoopGroup.singleton)
            .connectTimeout(Self.connectTimeout)
            .tcpOptions(TunnelSocket.tcpOptions)
            .connect(host: relay.host, port: relay.port)
            .get()
    }

    /// Shuts the endpoint down, closing its listener, relay registration,
    /// and discovery. Tunnels already open stay open until their peers or
    /// owners close them.
    public func close() async {
        let (listener, monitor, browser, rebind, relay) = state.withLock { state in
            state.isClosed = true
            state.addressObservers = []
            state.networkObservers = []
            state.routeObservers = []
            state.relayObservers = []
            state.relayGeneration += 1
            defer { state.relay = nil }
            return (state.listener, state.networkMonitor, state.browser, state.rebind, state.relay?.registration)
        }
        relay?.stop()
        rebind?.cancel()
        monitor?.stop()
        browser?.cancel()
        incoming.finish()
        try? await listener?.close().get()
    }

    private func networkPathChanged() {
        renewAdvertisement()
        refreshDirectAddresses()
        let observers = state.withLock { $0.isClosed ? [] : $0.networkObservers }
        observers.forEach { $0() }
    }

    /// Advertises under a fresh random name and salt, so the advertisement
    /// on this network can't be linked to the one on the last.
    private func renewAdvertisement() {
        guard let serviceType = configuration.serviceType else { return }
        let advertiser = state.withLock { $0.isClosed ? nil : $0.advertiser }
        advertiser?.service = .tunnel(serviceType: serviceType, gateKey: identity.gateKey)
    }

    /// Adopts the advertisements discovery found, reporting the known hosts
    /// whose routes appeared or changed. Hosts that vanished go quietly:
    /// their links keep whatever tunnel they have.
    func discovered(_ advertisements: [Advertisement]) {
        let (observers, changed) = state.withLock { state -> ([@Sendable (Set<String>) -> Void], Set<String>) in
            guard !state.isClosed else { return ([], []) }
            state.advertisements = advertisements
            return (state.routeObservers, Self.matchRoutes(in: &state))
        }
        guard !changed.isEmpty else { return }
        RemoteLog.discovery.info("Found \(changed.count) host(s) on the local network")
        observers.forEach { $0(changed) }
    }

    /// Learns the gate key of `host`, so discovery can recognize its
    /// advertisements. Every dial does this; a host's routes are reported
    /// only once something has dialed it.
    func remember(host: DeviceRecord) {
        guard let gateKey = host.gateKey else { return }
        state.withLock { state in
            guard state.knownHosts[host.endpointID] != gateKey else { return }
            state.knownHosts[host.endpointID] = gateKey
            _ = Self.matchRoutes(in: &state)
        }
    }

    /// Recomputes each known host's advertised routes, returning the hosts
    /// whose routes appeared or changed.
    private static func matchRoutes(in state: inout State) -> Set<String> {
        var routes: [String: [NWEndpoint]] = [:]
        for (endpointID, gateKey) in state.knownHosts {
            let endpoints = state.advertisements.filter { $0.isAdvertised(byGateKey: gateKey) }.map(\.endpoint)
            if !endpoints.isEmpty {
                routes[endpointID] = endpoints
            }
        }
        let changed = Set(routes.filter { state.discoveredRoutes[$0.key] != $0.value }.keys)
        state.discoveredRoutes = routes
        return changed
    }

    // MARK: - Host side

    /// What a host needs to gate and serve an incoming connection.
    private struct HostSetup: Sendable {
        let sshKey: NIOSSHPrivateKey
        let gateKey: Data
        let username: String
        let admits: @Sendable (String) -> Bool
        let incoming: AsyncInbox<SSHIncomingTunnel>
    }

    /// A listener bound for direct connections.
    private struct BoundListener {
        let channel: any Channel
        let advertiser: NWListener
        let port: UInt16
    }

    /// Admits the keys `registry` knows, revoked ones included so the host
    /// service can turn them away with a reason. Fails closed: a Keychain
    /// failure admits nothing, so no key the registry doesn't list ever
    /// holds an authenticated session.
    private static func admission(by registry: DeviceRegistry) -> @Sendable (String) -> Bool {
        { endpointID in
            do {
                return try registry.knows(endpointID: endpointID)
            } catch {
                RemoteLog.host.error("Keychain read failed while admitting a device: \(error.localizedDescription, privacy: .public)")
                return false
            }
        }
    }

    /// Puts the access gate in front of `channel`, a connection arriving
    /// over `path`; once the peer passes it, runs this host's SSH server and
    /// queues the connection on `incoming`. Must run on the channel's event
    /// loop.
    private static func gate(_ channel: any Channel, path: ConnectionPath, setup: HostSetup, limiter: AccessGateLimiter?) throws {
        let gate = AccessGateServerHandler(gateKey: setup.gateKey, limiter: limiter) { channel in
            try serveIncoming(channel, path: path, setup: setup)
        }
        try channel.pipeline.syncOperations.addHandler(gate)
    }

    /// Runs this host's SSH server on `channel`, which passed the access
    /// gate, and queues it on `incoming`. Throws, so the connection is
    /// dropped, once ``maxQueuedConnections`` are waiting or the node has
    /// closed. Must run on the channel's event loop.
    private static func serveIncoming(_ channel: any Channel, path: ConnectionPath, setup: HostSetup) throws {
        guard setup.incoming.count < maxQueuedConnections else {
            throw RemoteAccessError.localSocketFailed("too many pending connections")
        }
        let streams = AsyncInbox<ChannelByteStream>()
        let authenticated = try SSHPipeline.addServer(to: channel, hostKey: setup.sshKey, username: setup.username, admits: setup.admits, streams: streams)
        guard setup.incoming.push(SSHIncomingTunnel(channel: channel, authenticated: authenticated, incoming: streams, path: path)) else {
            throw RemoteAccessError.localSocketFailed("endpoint closed")
        }
    }

    private static func listen(
        preferredPort: UInt16?,
        fallingBackToAnyPort: Bool = true,
        listenHost host: String?,
        setup: HostSetup,
        serviceType: String?,
        gateLimiter: AccessGateLimiter
    ) async throws -> BoundListener {
        let preferred = preferredPort.flatMap(NWEndpoint.Port.init(rawValue:))
        let ports = [preferred, fallingBackToAnyPort || preferred == nil ? NWEndpoint.Port.any : nil].compactMap { $0 }
        var lastError: (any Error)?
        for port in ports {
            let parameters = NWParameters(tls: nil, tcp: TunnelSocket.tcpOptions)
            // The port stays in use by tunnels accepted on it, and by
            // connections in TIME_WAIT after a relaunch; without reuse,
            // rebinding it would fail and the published addresses go stale.
            parameters.allowLocalEndpointReuse = true
            if let host {
                let address = NWEndpoint.Host(host)
                parameters.requiredLocalEndpoint = .hostPort(host: address, port: port)
                // Advertise a loopback listener only where it can be reached.
                if case .ipv4(let ip) = address, ip.isLoopback {
                    parameters.requiredInterfaceType = .loopback
                }
            }
            do {
                let nwListener = host == nil ? try NWListener(using: parameters, on: port) : try NWListener(using: parameters)
                nwListener.service = serviceType.map { .tunnel(serviceType: $0, gateKey: setup.gateKey) }
                // One loop: with an existing NWListener, NIOTS picks the
                // listener's loop twice from the group and asserts they match.
                let channel = try await NIOTSListenerBootstrap(group: NIOTSEventLoopGroup.singleton.next())
                    .childChannelInitializer { child in
                        child.eventLoop.makeCompletedFuture {
                            try gate(child, path: .direct, setup: setup, limiter: gateLimiter)
                        }
                    }
                    .withNWListener(nwListener)
                    .get()
                guard let bound = nwListener.port?.rawValue else {
                    try? await channel.close().get()
                    throw RemoteAccessError.localSocketFailed("listener has no port")
                }
                return BoundListener(channel: channel, advertiser: nwListener, port: bound)
            } catch {
                lastError = error
            }
        }
        throw lastError ?? RemoteAccessError.localSocketFailed("couldn't listen")
    }

    /// Publishes this host's current addresses at once, with the names last
    /// confirmed for them, then confirms the names again in the background
    /// and republishes if they changed. A fixed `publishedHost` is published
    /// alone.
    private func refreshDirectAddresses() {
        let hosts = publishedHost.map { [$0] } ?? LocalAddresses.current()
        let refresh = state.withLock { state -> (generation: Int, observers: [@Sendable () -> Void])? in
            guard !state.isClosed else { return nil }
            state.addressGeneration += 1
            return (state.addressGeneration, Self.setDirectAddresses(hosts, in: &state))
        }
        guard let refresh else { return }
        refresh.observers.forEach { $0() }
        guard publishedHost == nil else { return }
        hostNameQueue.async { [weak self] in
            self?.confirmHostNames(of: hosts, generation: refresh.generation)
        }
    }

    /// Confirms the DNS names of `hosts`, the addresses refresh `generation`
    /// published, and republishes with them unless a newer refresh has come
    /// along since. Blocks on DNS.
    private func confirmHostNames(of hosts: [String], generation: Int) {
        guard state.withLock({ !$0.isClosed && $0.addressGeneration == generation }) else { return }
        let names = HostNames.confirmed(for: hosts)
        let observers = state.withLock { state -> [@Sendable () -> Void] in
            guard !state.isClosed, state.addressGeneration == generation, state.hostNames != names else { return [] }
            state.hostNames = names
            return Self.setDirectAddresses(hosts, in: &state)
        }
        guard !observers.isEmpty else { return }
        let distinct = Set(names.values).sorted()
        RemoteLog.host.info("Publishing \(distinct.count) DNS name(s): \(distinct.joined(separator: ", "), privacy: .private)")
        observers.forEach { $0() }
    }

    /// Sets `state`'s direct addresses to `hosts` and their confirmed names
    /// on the listening port. Returns the observers to call, which is none
    /// when nothing changed or nothing is listening.
    private static func setDirectAddresses(_ hosts: [String], in state: inout State) -> [@Sendable () -> Void] {
        guard let port = state.listeningPort else { return [] }
        let addresses = publishedAddresses(hosts: hosts, names: state.hostNames, port: port)
        guard state.directAddresses != addresses else { return [] }
        state.directAddresses = addresses
        return state.addressObservers
    }

    /// The direct addresses to publish, all on `port`: each of `hosts`, then
    /// the names `names` confirms for them, each name once, in host order.
    static func publishedAddresses(hosts: [String], names: [String: String], port: UInt16) -> [String] {
        var seen = Set<String>()
        let confirmedNames = hosts.compactMap { names[$0] }.filter { seen.insert($0).inserted }
        return (hosts + confirmedNames).map { HostPort(host: $0, port: Int(port)).description }
    }

    /// Listens again if `listener` closes while the node is still open.
    private func watch(_ listener: any Channel) {
        listener.closeFuture.whenComplete { [weak self] _ in
            self?.listenerClosed(listener)
        }
    }

    private func listenerClosed(_ listener: any Channel) {
        let port = state.withLock { state -> UInt16?? in
            guard !state.isClosed, state.listener === listener else { return nil }
            state.listener = nil
            return .some(state.listeningPort)
        }
        guard let port else { return }
        RemoteLog.host.error("Direct listener closed unexpectedly; listening again")
        let rebind = Task { await self.listenAgain(preferredPort: port) }
        state.withLock { $0.rebind = rebind }
    }

    /// Rebinds the listener, retrying with backoff until it succeeds or the
    /// node closes. The first few tries insist on the port it had, so the
    /// addresses already published stay valid; if something else holds that
    /// port, it moves and republishes.
    private func listenAgain(preferredPort: UInt16?) async {
        guard let registry else { return }
        // The failed listener releases its socket asynchronously, so the
        // first try on the same port can still find it taken.
        var delay = Duration.milliseconds(250)
        var attempt = 0
        while !state.withLock({ $0.isClosed }) {
            attempt += 1
            do {
                let bound = try await Self.listen(
                    preferredPort: preferredPort,
                    fallingBackToAnyPort: attempt > Self.samePortAttempts,
                    listenHost: publishedHost,
                    setup: HostSetup(
                        sshKey: sshKey,
                        gateKey: identity.gateKey,
                        username: configuration.protocolName,
                        admits: Self.admission(by: registry),
                        incoming: incoming
                    ),
                    serviceType: configuration.serviceType,
                    gateLimiter: gateLimiter
                )
                let adopted = state.withLock { state -> Bool in
                    guard !state.isClosed else { return false }
                    state.listener = bound.channel
                    state.advertiser = bound.advertiser
                    state.listeningPort = bound.port
                    return true
                }
                guard adopted else {
                    try? await bound.channel.close().get()
                    return
                }
                RemoteLog.host.notice("Listening again on port \(bound.port)")
                watch(bound.channel)
                refreshDirectAddresses()
                return
            } catch {
                RemoteLog.host.error("Couldn't listen again: \(error.localizedDescription, privacy: .public)")
                try? await Task.sleep(for: delay)
                delay = min(delay * 2, .seconds(30))
            }
        }
    }

    // MARK: - Client side

    /// Dials one route to a host: TCP, the access gate, then SSH, trusting
    /// only the host key `host`'s endpoint ID names. A route that has to
    /// wait for connectivity fails at once with the reason ``PathWatcher``
    /// recorded.
    private func dial(_ endpoint: NWEndpoint, host: GatedHost) async throws -> SSHTunnelConnection {
        let sshKey = sshKey
        let username = configuration.protocolName
        let diagnosis = DialDiagnosis()
        do {
            let dialed = try await NIOTSConnectionBootstrap(group: NIOTSEventLoopGroup.singleton)
                .connectTimeout(Self.connectTimeout)
                .tcpOptions(TunnelSocket.tcpOptions)
                .connect(endpoint: endpoint) { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(PathWatcher(diagnosis: diagnosis))
                        return Dialed(
                            channel: channel,
                            authenticated: try Self.answerGate(on: channel, host: host, key: sshKey, username: username)
                        )
                    }
                }
            return try await dialed.connection(hostEndpointID: host.endpointID, path: .direct)
        } catch {
            throw diagnosis.error ?? error
        }
    }

    /// Dials a host through `relay`: TCP to the relay, which joins the
    /// connection to the host, then the access gate and SSH end to end,
    /// trusting only the host key `host`'s endpoint ID names.
    private func dialRelay(_ relay: RelayAddress, host: GatedHost) async throws -> SSHTunnelConnection {
        let sshKey = sshKey
        let username = configuration.protocolName
        let namespace = configuration.relayNamespace
        let diagnosis = DialDiagnosis()
        do {
            let (channel, joined) = try await NIOTSConnectionBootstrap(group: NIOTSEventLoopGroup.singleton)
                .connectTimeout(Self.connectTimeout)
                .tcpOptions(TunnelSocket.tcpOptions)
                .connect(host: relay.host, port: relay.port) { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(PathWatcher(diagnosis: diagnosis))
                        let joined = try RelayClient.connect(on: channel, namespace: namespace, endpointID: host.endpointID) { channel in
                            try Self.answerGate(on: channel, host: host, key: sshKey, username: username)
                        }
                        return (channel as any Channel, joined)
                    }
                }
            let authenticated = try await withTaskCancellationHandler {
                try await joined.get()
            } onCancel: {
                channel.close(promise: nil)
            }
            return try await Dialed(channel: channel, authenticated: authenticated).connection(hostEndpointID: host.endpointID, path: .relay)
        } catch {
            throw diagnosis.error ?? Self.relayFailure(error)
        }
    }

    /// Adds the client's end of the access gate to `channel`, which starts
    /// SSH once the host has proven it knows `host`'s gate key. The future
    /// succeeds once both sides are authenticated. Must be called on the
    /// channel's event loop.
    private static func answerGate(on channel: any Channel, host: GatedHost, key: NIOSSHPrivateKey, username: String) throws -> EventLoopFuture<Void> {
        let passed = channel.eventLoop.makePromise(of: Void.self)
        let gate = AccessGateClientHandler(gateKey: host.gateKey, promise: passed) { channel in
            try SSHPipeline.addClient(to: channel, key: key, hostEndpointID: host.endpointID, username: username)
        }
        try channel.pipeline.syncOperations.addHandler(gate)
        return passed.futureResult
    }

    /// The tunnel's own error for a relay client failure.
    private static func relayFailure(_ error: any Error) -> any Error {
        switch error as? RelayClientError {
        case .refused(let refusal)?: RemoteAccessError.relayRefused(refusal)
        case .timedOut?: RemoteAccessError.timedOut
        case .connectionClosed?: RemoteAccessError.unexpectedEndOfStream
        case .malformedFrame?, .unexpectedEvent?: RemoteAccessError.protocolViolation("unexpected reply from the relay")
        case nil: error
        }
    }
}

extension RemoteNode.RelayStatus {
    /// The node's status for a relay registration's.
    init(_ status: RelayHost.Status) {
        switch status {
        case .connecting:
            self = .connecting
        case .registered:
            self = .registered
        case .disconnected(let error):
            let reason = switch error as? RelayClientError {
            case .refused(let refusal)?: RemoteAccessError.relayRefused(refusal).localizedDescription
            default: error.localizedDescription
            }
            self = .unavailable(reason: reason)
        }
    }
}

extension RemoteNode: TunnelTransport {
    /// Dials every direct route to the host at once — the ones found on the
    /// local network first, then the registry's — plus, when allowed, the
    /// host's relay after ``relayHeadStart``, and keeps the first to finish
    /// the SSH handshake. A host whose record has no gate key runs a build
    /// too old to reach.
    func connect(to record: DeviceRecord, allowingRelay: Bool) async throws -> any TunnelConnection {
        guard let gateKey = record.gateKey else { throw RemoteAccessError.outdatedPeer }
        let host = GatedHost(endpointID: record.endpointID, gateKey: gateKey)
        remember(host: record)
        let (discovered, usesRelays) = state.withLock { ($0.discoveredRoutes[host.endpointID] ?? [], $0.dialsThroughRelays) }
        let endpoints = discovered + record.directAddresses.compactMap { HostPort(parsing: $0)?.endpoint }
        var attempts: [@Sendable () async throws -> SSHTunnelConnection] = endpoints.map { endpoint in
            { try await self.dial(endpoint, host: host) }
        }
        if allowingRelay, usesRelays, let relay = record.relayAddress.flatMap({ RelayAddress(parsing: $0) }) {
            let waitsForDirect = !attempts.isEmpty
            attempts.append {
                if waitsForDirect {
                    try await Task.sleep(for: Self.relayHeadStart)
                }
                return try await self.dialRelay(relay, host: host)
            }
        }
        guard !attempts.isEmpty else { throw RemoteAccessError.noRoute }
        return try await firstSuccess(of: attempts) { loser in
            loser.close(reason: "another path won")
        }
    }

    func nextIncoming() async -> (any IncomingTunnel)? {
        await incoming.next()
    }
}

/// The host a dial is for: the key SSH must find, and the gate key it must
/// prove it knows first.
private struct GatedHost: Sendable {
    let endpointID: String
    let gateKey: Data
}

/// A TCP connection with the client's access gate installed, which sets up
/// the client side of SSH once the host passes it.
private struct Dialed: Sendable {
    let channel: any Channel
    let authenticated: EventLoopFuture<Void>

    /// Waits for authentication, closing the connection if it fails or
    /// takes too long.
    func connection(hostEndpointID: String, path: ConnectionPath) async throws -> SSHTunnelConnection {
        do {
            let authenticated = authenticated
            let channel = channel
            try await withTaskCancellationHandler {
                try await withTimeout(RemoteNode.attemptTimeout) { try await authenticated.get() }
            } onCancel: {
                channel.close(promise: nil)
            }
        } catch {
            try? await channel.close().get()
            throw error
        }
        return SSHTunnelConnection(channel: channel, remoteEndpointID: hostEndpointID, path: path, incoming: AsyncInbox())
    }
}

/// Runs `attempts` concurrently and returns the first to succeed. Attempts
/// still running are cancelled, and any that succeed anyway go to `discard`.
/// When every attempt fails, fails with the most telling error (see
/// ``mostTelling(_:)``). `attempts` must not be empty.
func firstSuccess<T: Sendable>(
    of attempts: [@Sendable () async throws -> T],
    discard: @escaping @Sendable (T) -> Void
) async throws -> T {
    let race = RaceOutcome<T>()
    let failures = Mutex<[Int: any Error]>([:])
    return try await race.run {
        attempts.enumerated().map { index, attempt in
            Task {
                do {
                    let value = try await attempt()
                    if !race.settle(with: .success(value)) {
                        discard(value)
                    }
                } catch {
                    let all = failures.withLock { failures -> [any Error]? in
                        failures[index] = error
                        guard failures.count == attempts.count else { return nil }
                        return failures.sorted { $0.key < $1.key }.map(\.value)
                    }
                    if let all {
                        race.settle(with: .failure(mostTelling(all)))
                    }
                }
            }
        }
    }
}

/// The error that best explains why every path to a host failed:
/// `notRecognized` (a path reached the right host, which doesn't know this
/// device yet), then `localNetworkDenied` (only the user can fix it), then
/// `hostKeyMismatch` (a path reached some other device — which outranks
/// addresses that simply didn't answer, as every host with a VPN or several
/// interfaces has some), then `relayRefused` (the relay answered, and says
/// why the host can't be reached through it), then the first path's error,
/// since paths are ordered by preference. `errors` must not be empty.
func mostTelling(_ errors: [any Error]) -> any Error {
    let ranked: [@Sendable (RemoteAccessError) -> Bool] = [
        { $0 == .notRecognized },
        { $0 == .localNetworkDenied },
        { $0 == .hostKeyMismatch },
        { if case .relayRefused = $0 { true } else { false } },
    ]
    for matches in ranked {
        if let match = errors.first(where: { ($0 as? RemoteAccessError).map(matches) ?? false }) {
            return match
        }
    }
    return errors[0]
}
