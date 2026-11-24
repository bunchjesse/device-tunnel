import Foundation
import os

/// Accepts tunnels from the account's other devices and forwards their
/// streams to a local server on this device.
///
/// A device gets through when three things hold: SSH authentication proved
/// it owns its endpoint key, its record is in this host's copy of the synchronized
/// registry (so it's signed in to the same Apple Account), and this host's
/// user approved it once. It then receives an access token and each stream it
/// opens is spliced to a TCP connection to the local server.
public actor RemoteHostService {
    /// What the host needs from the app.
    public struct Environment: Sendable {
        /// The account's device list.
        public var registry: DeviceRegistry
        /// This host's approval decisions.
        public var approvals: DeviceApprovals
        /// Name reported to connecting devices.
        public var hostName: @Sendable () async -> String
        /// Port of the local API server, or nil while it isn't serving.
        public var localPort: @Sendable () async -> UInt16?
        /// Returns the API token an approved device should use, issuing it if needed.
        public var token: @Sendable (_ endpointID: String) async -> String
        /// Stops accepting a device's API token.
        public var revokeToken: @Sendable (_ endpointID: String) async -> Void
        /// Asks the user whether `device` may connect. Returns nil when no
        /// decision was made.
        public var requestApproval: @Sendable (_ device: DeviceRecord) async -> ApprovalDecision?
        /// Whether this Mac currently accepts remote connections.
        public var isAcceptingConnections: @Sendable () async -> Bool
        /// Called whenever the set of connected devices changes.
        public var connectionsChanged: @Sendable (_ devices: [ConnectedDevice]) async -> Void

        /// Creates an environment.
        public init(
            registry: DeviceRegistry,
            approvals: DeviceApprovals,
            hostName: @escaping @Sendable () async -> String,
            localPort: @escaping @Sendable () async -> UInt16?,
            token: @escaping @Sendable (_ endpointID: String) async -> String,
            revokeToken: @escaping @Sendable (_ endpointID: String) async -> Void,
            requestApproval: @escaping @Sendable (_ device: DeviceRecord) async -> ApprovalDecision?,
            isAcceptingConnections: @escaping @Sendable () async -> Bool,
            connectionsChanged: @escaping @Sendable (_ devices: [ConnectedDevice]) async -> Void
        ) {
            self.registry = registry
            self.approvals = approvals
            self.hostName = hostName
            self.localPort = localPort
            self.token = token
            self.revokeToken = revokeToken
            self.requestApproval = requestApproval
            self.isAcceptingConnections = isAcceptingConnections
            self.connectionsChanged = connectionsChanged
        }
    }

    /// A device currently connected through a tunnel.
    public struct ConnectedDevice: Sendable, Hashable, Identifiable {
        public var id: String { endpointID }
        /// The device's endpoint ID.
        public let endpointID: String
        /// The device's name from the registry.
        public let name: String
        /// How the device's tunnel reaches this Mac.
        public let path: ConnectionPath
    }

    /// Oldest client protocol revision this host serves.
    static let minimumProtocolVersion = 2

    /// Most tunnels that may be between arriving and being authorized at
    /// once. A device waiting on its approval prompt holds one.
    static let maxPendingHandshakes = 32

    private enum Authorization {
        case granted(DeviceRecord, token: String)
        case refused
    }

    private struct ActiveTunnel {
        let device: ConnectedDevice
        let connection: any TunnelConnection
    }

    /// A tunnel between arriving and being authorized.
    private struct PendingHandshake {
        let incoming: any IncomingTunnel
        let arrived: ContinuousClock.Instant
        var isAuthenticated = false
    }

    private let transport: any TunnelTransport
    private let environment: Environment
    private var tunnels: [UUID: ActiveTunnel] = [:]
    private var pendingApprovals: [String: Task<ApprovalDecision?, Never>] = [:]
    private var pendingHandshakes: [UUID: PendingHandshake] = [:]

    /// Creates a host service that accepts tunnels on `node`.
    public init(node: RemoteNode, environment: Environment) {
        self.init(transport: node, environment: environment)
    }

    init(transport: any TunnelTransport, environment: Environment) {
        self.transport = transport
        self.environment = environment
    }

    /// Accepts tunnels until the node closes.
    public func run() async {
        await withDiscardingTaskGroup { group in
            while let incoming = await transport.nextIncoming() {
                guard await makeRoomForHandshake() else {
                    RemoteLog.host.warning("Refusing a tunnel: \(Self.maxPendingHandshakes) authenticated devices already waiting")
                    await incoming.refuse()
                    continue
                }
                let id = UUID()
                pendingHandshakes[id] = PendingHandshake(incoming: incoming, arrived: .now)
                group.addTask { await self.serve(incoming, id: id) }
            }
        }
    }

    /// Frees a handshake slot when they're all taken by turning away the
    /// oldest tunnel that hasn't authenticated, so connections anything on
    /// the network can open can't lock out the account's devices. Returns
    /// false when every slot holds an authenticated device.
    private func makeRoomForHandshake() async -> Bool {
        guard pendingHandshakes.count >= Self.maxPendingHandshakes else { return true }
        let oldest = pendingHandshakes
            .filter { !$0.value.isAuthenticated }
            .min { $0.value.arrived < $1.value.arrived }
        guard let (id, handshake) = oldest else { return false }
        pendingHandshakes[id] = nil
        RemoteLog.host.info("Turning away a tunnel that hasn't authenticated to make room")
        await handshake.incoming.refuse()
        return true
    }

    /// Closes every tunnel from `endpointID` and revokes its API token, after
    /// the device's approval was withdrawn.
    ///
    /// Withdraw the approval first: a tunnel that is mid-handshake when this
    /// runs finds the approval gone once it registers, and cuts itself off.
    public func disconnect(endpointID: String) async {
        let matching = tunnels.filter { $0.value.device.endpointID == endpointID }
        for (id, tunnel) in matching {
            tunnel.connection.close(reason: "access revoked")
            tunnels[id] = nil
        }
        await environment.revokeToken(endpointID)
        if !matching.isEmpty {
            await publishConnections()
        }
    }

    /// Closes every tunnel and revokes the connected devices' tokens, e.g.
    /// when remote access is turned off.
    public func disconnectAll() async {
        for endpointID in Set(tunnels.values.map(\.device.endpointID)) {
            await disconnect(endpointID: endpointID)
        }
    }

    // MARK: - Serving one tunnel

    /// Authenticates and serves one tunnel until it closes.
    ///
    /// A device keeps one tunnel: once this one is authorized, every older
    /// tunnel from the same endpoint ID closes, since one abandoned across
    /// sleep may be half-open and keep pinning that device's SSE subscribers
    /// toward their per-session cap.
    private func serve(_ incoming: any IncomingTunnel, id: UUID) async {
        defer { pendingHandshakes[id] = nil }

        let connection: any TunnelConnection
        do {
            connection = try await withTimeout(.seconds(15)) { try await incoming.accept() }
        } catch RemoteAccessError.unexpectedEndOfStream {
            // A client racing several paths closes the ones that lose.
            RemoteLog.host.debug("Tunnel closed during its SSH handshake")
            await incoming.refuse()
            return
        } catch {
            RemoteLog.host.info("Tunnel handshake failed: \(error.localizedDescription, privacy: .public)")
            await incoming.refuse()
            return
        }

        pendingHandshakes[id]?.isAuthenticated = true
        let endpointID = connection.remoteEndpointID
        let control: any ByteStream
        let hello: ClientHello
        do {
            control = try await withTimeout(.seconds(10)) { try await connection.acceptStream() }
            hello = try await withTimeout(.seconds(10)) { try await FrameCodec.read(ClientHello.self, from: control) }
        } catch {
            RemoteLog.host.info("No hello from \(endpointID.prefix(12), privacy: .public): \(error.localizedDescription, privacy: .public)")
            connection.close(reason: "no hello")
            return
        }

        guard case .granted(let record, let token) = await authorize(endpointID: endpointID, hello: hello, control: control, connection: connection) else {
            try? await control.finish()
            // Give the refusal time to arrive; the client closes once it reads it.
            _ = try? await withTimeout(.seconds(5)) { await connection.waitUntilClosed() }
            connection.close(reason: "not authorized")
            return
        }

        do {
            try await FrameCodec.write(HostReply.approved(token: token, hostName: await environment.hostName()), to: control)
            try await control.finish()
        } catch {
            connection.close(reason: "handshake failed")
            return
        }

        let tunnelID = UUID()
        tunnels[tunnelID] = ActiveTunnel(
            device: ConnectedDevice(endpointID: endpointID, name: record.name, path: connection.path),
            connection: connection
        )
        // A client holds one tunnel per host; an older one from this device
        // was abandoned (e.g. across sleep) and may be half-open, pinning
        // SSE subscribers.
        let superseded = tunnels.filter { $0.key != tunnelID && $0.value.device.endpointID == endpointID }
        for (olderID, older) in superseded {
            older.connection.close(reason: "replaced by a newer tunnel")
            tunnels[olderID] = nil
        }
        // A `disconnect` that ran while this tunnel was being authorized
        // couldn't see it, and may have revoked the token before it was
        // issued. With the tunnel registered, any later `disconnect` will
        // close it; re-checking covers the earlier ones.
        guard (try? environment.approvals.decision(for: endpointID)) == .approved,
              await environment.isAcceptingConnections() else {
            tunnels[tunnelID] = nil
            connection.close(reason: "access revoked")
            await environment.revokeToken(endpointID)
            return
        }
        pendingHandshakes[id] = nil
        RemoteLog.host.info("Tunnel open from \(record.name, privacy: .public) (\(endpointID.prefix(12), privacy: .public))")
        await publishConnections()

        await Self.forwardStreams(on: connection, localPort: environment.localPort)

        tunnels[tunnelID] = nil
        RemoteLog.host.info("Tunnel closed from \(record.name, privacy: .public)")
        await publishConnections()
    }

    private func authorize(endpointID: String, hello: ClientHello, control: any ByteStream, connection: any TunnelConnection) async -> Authorization {
        let hostName = await environment.hostName()

        func refuse(_ reply: HostReply) async -> Authorization {
            try? await FrameCodec.write(reply, to: control)
            return .refused
        }

        guard hello.protocolVersion >= Self.minimumProtocolVersion else {
            return await refuse(.unsupportedProtocol(minimumVersion: Self.minimumProtocolVersion))
        }
        guard await environment.isAcceptingConnections() else {
            return await refuse(.unavailable(reason: "Remote access is turned off on \(hostName)."))
        }

        let record: DeviceRecord
        let storedDecision: ApprovalDecision?
        do {
            guard let found = try environment.registry.record(for: endpointID) else {
                RemoteLog.host.info("Refusing \(endpointID.prefix(12), privacy: .public): not in the registry")
                return await refuse(.unknownDevice)
            }
            record = found
            storedDecision = try environment.approvals.decision(for: endpointID)
        } catch {
            RemoteLog.host.error("Keychain read failed while authorizing a device: \(error.localizedDescription, privacy: .public)")
            return await refuse(.unavailable(reason: "\(hostName) couldn't read its device list."))
        }

        let decision: ApprovalDecision?
        if let storedDecision {
            decision = storedDecision
        } else {
            try? await FrameCodec.write(HostReply.pendingApproval(hostName: hostName), to: control)
            decision = await approvalDecision(for: record, unlessClosed: connection)
        }

        switch decision {
        case .approved?:
            break
        case .denied?:
            return await refuse(.denied(hostName: hostName))
        case nil:
            return await refuse(.unavailable(reason: "Nobody approved this device on \(hostName)."))
        }

        guard await environment.localPort() != nil else {
            return await refuse(.unavailable(reason: "\(hostName) is still starting."))
        }
        return .granted(record, token: await environment.token(endpointID))
    }

    /// The user's decision about `record`, or nil once `connection` closes
    /// first, so a device that gave up waiting doesn't hold a handshake slot
    /// until someone answers. The prompt stays up for the device's next try.
    private func approvalDecision(for record: DeviceRecord, unlessClosed connection: any TunnelConnection) async -> ApprovalDecision? {
        await firstFinished(
            { await self.approvalDecision(for: record) },
            {
                await connection.waitUntilClosed()
                return nil
            }
        )
    }

    /// Asks the user about `record`, sharing one prompt between every tunnel
    /// the device opens while the question is on screen, and records the answer.
    private func approvalDecision(for record: DeviceRecord) async -> ApprovalDecision? {
        if let pending = pendingApprovals[record.endpointID] {
            return await pending.value
        }
        let requestApproval = environment.requestApproval
        let task = Task { await requestApproval(record) }
        pendingApprovals[record.endpointID] = task
        let decision = await task.value
        pendingApprovals[record.endpointID] = nil

        if let decision {
            do {
                try environment.approvals.record(DeviceApproval(
                    endpointID: record.endpointID,
                    deviceName: record.name,
                    decision: decision
                ))
            } catch {
                RemoteLog.host.error("Failed to store approval decision: \(error.localizedDescription, privacy: .public)")
            }
        }
        return decision
    }

    private func publishConnections() async {
        let devices = tunnels.values.map(\.device).sorted { $0.name < $1.name }
        await environment.connectionsChanged(devices)
    }

    /// Splices every stream the peer opens to a fresh TCP connection to the
    /// local server, until the tunnel closes.
    private nonisolated static func forwardStreams(
        on connection: any TunnelConnection,
        localPort: @escaping @Sendable () async -> UInt16?
    ) async {
        await withDiscardingTaskGroup { group in
            while let stream = try? await connection.acceptStream() {
                group.addTask {
                    guard let port = await localPort() else {
                        RemoteLog.host.debug("Dropped a stream: the local server isn't running")
                        await stream.abort()
                        return
                    }
                    do {
                        let server = try await TCPStream.connectToLoopback(port: port)
                        await StreamSplice.run(stream, server)
                    } catch {
                        RemoteLog.host.debug("Dropped a stream: \(error.localizedDescription, privacy: .public)")
                        await stream.abort()
                    }
                }
            }
        }
    }
}
