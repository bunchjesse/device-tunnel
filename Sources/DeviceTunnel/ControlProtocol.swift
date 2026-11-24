import Foundation

/// First message on a tunnel's control stream, sent by the connecting device.
struct ClientHello: Codable, Sendable, Equatable {
    /// Tunnel protocol revision the client speaks.
    let protocolVersion: Int
}

/// The host's answer on the control stream.
///
/// `pendingApproval` is provisional: the host sends a second, final reply
/// on the same stream once its user decides.
enum HostReply: Codable, Sendable, Equatable {
    /// The device may use the host's API with `token`.
    case approved(token: String, hostName: String)
    /// The host's user hasn't decided yet.
    case pendingApproval(hostName: String)
    /// The host's user refused this device.
    case denied(hostName: String)
    /// The device isn't in the host's copy of the registry, usually because
    /// iCloud Keychain hasn't delivered its record there yet.
    case unknownDevice
    /// The client's protocol is older than the host supports.
    case unsupportedProtocol(minimumVersion: Int)
    /// The host can't serve right now (remote access off, server starting).
    case unavailable(reason: String)
}

/// Length-prefixed JSON frames: a 4-byte big-endian length, then the payload.
enum FrameCodec {
    /// Largest payload either side accepts.
    static let maxPayloadLength = 64 * 1024

    static func write(_ value: some Encodable, to stream: some ByteStream) async throws {
        let payload = try JSONEncoder().encode(value)
        guard payload.count <= maxPayloadLength else {
            throw RemoteAccessError.protocolViolation("frame of \(payload.count) bytes is too large")
        }
        var frame = Data(capacity: 4 + payload.count)
        let length = UInt32(payload.count)
        frame.append(contentsOf: [
            UInt8(truncatingIfNeeded: length >> 24),
            UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length),
        ])
        frame.append(payload)
        try await stream.write(frame)
    }

    static func read<T: Decodable>(_ type: T.Type, from stream: some ByteStream) async throws -> T {
        let header = try await stream.readExactly(4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length <= maxPayloadLength else {
            throw RemoteAccessError.protocolViolation("frame of \(length) bytes is too large")
        }
        let payload = try await stream.readExactly(length)
        do {
            return try JSONDecoder().decode(T.self, from: payload)
        } catch {
            throw RemoteAccessError.protocolViolation("undecodable \(T.self)")
        }
    }
}
