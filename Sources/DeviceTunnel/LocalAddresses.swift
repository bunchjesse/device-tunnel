import Darwin
import Foundation
import Network
import Synchronization

/// This device's routable IP addresses, which a host publishes in its
/// registry record so other devices can dial it.
enum LocalAddresses {
    /// Every up, non-loopback interface's address except link-local ones,
    /// which need an interface scope a peer can't know. IPv4 first, each
    /// family sorted, so an unchanged network yields an unchanged list.
    static func current() -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var ipv4 = Set<String>()
        var ipv6 = Set<String>()
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0,
                  let address = entry.pointee.ifa_addr
            else { continue }
            switch Int32(address.pointee.sa_family) {
            case AF_INET:
                let ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { IPv4Address(withUnsafeBytes(of: $0.pointee.sin_addr) { Data($0) }) }
                if let ip, !ip.isLinkLocal, !ip.isLoopback {
                    ipv4.insert("\(ip)")
                }
            case AF_INET6:
                let ip = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { IPv6Address(withUnsafeBytes(of: $0.pointee.sin6_addr) { Data($0) }) }
                if let ip, !ip.isLinkLocal, !ip.isLoopback, !ip.isMulticast {
                    ipv6.insert("\(ip)")
                }
            default:
                continue
            }
        }
        return ipv4.sorted() + ipv6.sorted()
    }
}

/// Reports whenever the device's network path changes, so a host can
/// republish its addresses and a client can redial right away.
final class NetworkChangeMonitor: Sendable {
    private let monitor = NWPathMonitor()

    /// Calls `onChange` after every network path update, starting with the
    /// current path, until ``stop()``.
    init(onChange: @escaping @Sendable () -> Void) {
        monitor.pathUpdateHandler = { _ in onChange() }
        monitor.start(queue: DispatchQueue(label: "dev.bunch.DeviceTunnel.path"))
    }

    /// Stops monitoring.
    func stop() {
        monitor.cancel()
    }
}
