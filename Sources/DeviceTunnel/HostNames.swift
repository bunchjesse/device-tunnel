import Darwin
import Foundation
import Network

/// The DNS names of a host's addresses, which it publishes alongside the
/// addresses themselves.
///
/// Dialing a name instead of an address lets name-based network policy act
/// on the dial: a VPN whose On Demand rules connect for the host's domain
/// comes up when a client looks the name up, but never for a bare address.
enum HostNames {
    /// The name reverse DNS gives an address, or nil when it has none.
    typealias ReverseLookup = @Sendable (String) -> String?
    /// The addresses a name resolves to.
    typealias ForwardLookup = @Sendable (String) -> [String]

    /// Maps each of `addresses` to its reverse DNS name, keeping only names
    /// that resolve back to the same address, so a stale or forged PTR
    /// record publishes nothing. Skips multicast DNS (`.local`) names, which
    /// resolve only on the host's own link, where Bonjour already finds it.
    /// Blocks on DNS, so never call it on the cooperative thread pool.
    static func confirmed(
        for addresses: [String],
        reverse: ReverseLookup = systemReverseLookup,
        forward: ForwardLookup = systemForwardLookup
    ) -> [String: String] {
        var names: [String: String] = [:]
        for address in addresses {
            guard let raw = rawAddress(address),
                  let name = reverse(address).map(normalized),
                  isPublishable(name),
                  forward(name).contains(where: { rawAddress($0) == raw })
            else { continue }
            names[address] = name
        }
        return names
    }

    /// Reverse DNS through the system resolver.
    static let systemReverseLookup: ReverseLookup = { address in
        socketAddresses(of: address, flags: AI_NUMERICHOST) { nameInfo(of: $0, length: $1, flags: NI_NAMEREQD) }.first
    }

    /// Forward DNS through the system resolver, as numeric addresses.
    static let systemForwardLookup: ForwardLookup = { name in
        socketAddresses(of: name, flags: 0) { nameInfo(of: $0, length: $1, flags: NI_NUMERICHOST) }
    }

    /// `name` lowercased and without the root's trailing dot.
    private static func normalized(_ name: String) -> String {
        let lowercased = name.lowercased()
        return lowercased.hasSuffix(".") ? String(lowercased.dropLast()) : lowercased
    }

    /// Whether `name` is a DNS hostname worth publishing: letters, digits,
    /// hyphens, and dots only, and neither an address literal nor a
    /// multicast DNS name.
    private static func isPublishable(_ name: String) -> Bool {
        !name.isEmpty
            && !name.hasSuffix(".local")
            && rawAddress(name) == nil
            && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }
    }

    /// The bytes of an IPv4 or IPv6 address literal, so differently written
    /// forms of one address compare equal. Nil for anything else.
    private static func rawAddress(_ address: String) -> Data? {
        IPv4Address(address)?.rawValue ?? IPv6Address(address)?.rawValue
    }

    /// Runs `body` on each socket address `getaddrinfo` gives `host`,
    /// keeping the non-nil results.
    private static func socketAddresses<T>(
        of host: String,
        flags: Int32,
        _ body: (UnsafePointer<sockaddr>, socklen_t) -> T?
    ) -> [T] {
        var hints = addrinfo()
        hints.ai_flags = flags
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var head: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &head) == 0, let first = head else { return [] }
        defer { freeaddrinfo(head) }
        return sequence(first: first, next: { $0.pointee.ai_next }).compactMap { info in
            info.pointee.ai_addr.flatMap { body($0, info.pointee.ai_addrlen) }
        }
    }

    /// `getnameinfo`'s host for `address`, or nil when it fails.
    private static func nameInfo(of address: UnsafePointer<sockaddr>, length: socklen_t, flags: Int32) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, flags) == 0 else { return nil }
        return host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }
}
