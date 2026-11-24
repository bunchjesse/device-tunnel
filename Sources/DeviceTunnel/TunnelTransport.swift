import Foundation

/// A mutually authenticated, end-to-end encrypted connection to another device.
protocol TunnelConnection: Sendable {
    /// The peer's endpoint ID, as proven during the handshake.
    var remoteEndpointID: String { get }

    /// How the connection reaches the peer.
    var path: ConnectionPath { get }

    /// Opens a new bidirectional stream to the peer.
    func openStream() async throws -> any ByteStream

    /// Waits for the peer to open a bidirectional stream.
    func acceptStream() async throws -> any ByteStream

    /// Closes the connection and every stream on it.
    func close(reason: String)

    /// Returns once the connection has closed, for whatever reason.
    func waitUntilClosed() async
}

/// A connection attempt a host hasn't accepted yet.
protocol IncomingTunnel: Sendable {
    /// Completes the handshake, failing if the peer doesn't authenticate.
    func accept() async throws -> any TunnelConnection

    /// Turns the attempt away without completing the handshake.
    func refuse() async
}

/// Dials and accepts tunnel connections.
protocol TunnelTransport: Sendable {
    /// Connects to the device `record` describes: over its direct routes,
    /// and through its relay as well when `allowingRelay` is set and this
    /// device uses relays. Direct routes are always preferred.
    func connect(to record: DeviceRecord, allowingRelay: Bool) async throws -> any TunnelConnection

    /// Waits for the next inbound connection attempt. Returns nil once the
    /// transport has shut down.
    func nextIncoming() async -> (any IncomingTunnel)?
}

/// How a tunnel reaches the other device.
public enum ConnectionPath: Sendable, Hashable {
    /// Straight to the device's own address, on a network both can reach.
    case direct
    /// Through the relay, because the device couldn't be reached directly.
    case relay
}
