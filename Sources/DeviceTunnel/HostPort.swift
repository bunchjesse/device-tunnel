import Foundation
import Network

/// A `host:port` pair, the form devices publish direct addresses in.
struct HostPort: Sendable, Hashable, CustomStringConvertible {
    /// Hostname or IP address. IPv6 literals are stored without brackets.
    let host: String
    /// TCP port.
    let port: Int

    /// Creates a pair from its parts.
    init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    /// Parses `host:port` or `[ipv6]:port`. Returns nil for anything else.
    init?(parsing string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.contains("/"), !trimmed.contains(" "),
              let (host, port) = Self.split(trimmed)
        else { return nil }
        self.host = host
        self.port = port
    }

    var description: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    /// The Network framework endpoint to dial.
    var endpoint: NWEndpoint? {
        NWEndpoint.Port(rawValue: UInt16(port)).map { .hostPort(host: NWEndpoint.Host(host), port: $0) }
    }

    private static func split(_ string: String) -> (String, Int)? {
        func validPort(_ text: Substring) -> Int? {
            guard let port = Int(text), (1...65535).contains(port) else { return nil }
            return port
        }
        if string.hasPrefix("[") {
            guard let close = string.firstIndex(of: "]") else { return nil }
            let host = String(string[string.index(after: string.startIndex)..<close])
            let rest = string[string.index(after: close)...]
            guard !host.isEmpty, rest.hasPrefix(":"), let port = validPort(rest.dropFirst()) else { return nil }
            return (host, port)
        }
        let parts = string.split(separator: ":", omittingEmptySubsequences: false)
        // Two parts is host:port; more is an IPv6 literal, which needs
        // brackets to carry a port, and one has no port at all.
        guard parts.count == 2, !parts[0].isEmpty, let port = validPort(parts[1]) else { return nil }
        return (String(parts[0]), port)
    }
}

extension Data {
    /// Decodes an even-length hexadecimal string, or returns nil.
    init?(hexEncoded string: String) {
        guard string.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(string.count / 2)
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    /// Lowercase hexadecimal encoding, two digits per byte.
    var hexEncoded: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
