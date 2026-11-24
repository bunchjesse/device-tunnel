import CryptoKit
import Foundation
import Testing
@testable import DeviceTunnel

struct HostPortTests {
    /// Addresses parse in the form devices publish them.
    @Test(arguments: [
        ("mac.example.com:4000", HostPort(host: "mac.example.com", port: 4000)),
        ("10.0.0.2:51000", HostPort(host: "10.0.0.2", port: 51000)),
        ("[fd00::1]:51000", HostPort(host: "fd00::1", port: 51000)),
        (" mac.example.com:4000 ", HostPort(host: "mac.example.com", port: 4000)),
    ] as [(String, HostPort)])
    func parsesValidAddresses(input: String, expected: HostPort) {
        #expect(HostPort(parsing: input) == expected)
    }

    /// Malformed input — URLs, missing or out-of-range ports, unbracketed
    /// IPv6 with a port — is rejected instead of guessed at.
    @Test(arguments: [
        "http://mac.example.com:4000",
        "mac.example.com",
        "mac.example.com:0",
        "mac.example.com:70000",
        "mac.example.com:port",
        "[fd00::1]",
        "fd00::1:51000",
        "",
        "host name:4000",
    ])
    func rejectsMalformedAddresses(input: String) {
        #expect(HostPort(parsing: input) == nil)
    }

    /// IPv6 hosts print in brackets so the result parses back.
    @Test func descriptionRoundTrips() {
        let address = HostPort(host: "fd00::1", port: 51000)
        #expect(address.description == "[fd00::1]:51000")
        #expect(HostPort(parsing: address.description) == address)
    }
}

struct HostNamesTests {
    /// Builds a reverse lookup from a fixed PTR table.
    private static func reverse(_ table: [String: String]) -> HostNames.ReverseLookup {
        { table[$0] }
    }

    /// Builds a forward lookup from a fixed address table.
    private static func forward(_ table: [String: [String]]) -> HostNames.ForwardLookup {
        { table[$0] ?? [] }
    }

    /// A name whose forward lookup includes the address it came from is
    /// kept, normalized to lowercase without the root's trailing dot.
    @Test func keepsForwardConfirmedNames() {
        let names = HostNames.confirmed(
            for: ["17.203.82.54"],
            reverse: Self.reverse(["17.203.82.54": "Mac.Example.COM."]),
            forward: Self.forward(["mac.example.com": ["17.203.82.54"]])
        )
        #expect(names == ["17.203.82.54": "mac.example.com"])
    }

    /// A PTR record whose name resolves elsewhere, or not at all, publishes
    /// nothing, so a stale or forged record can't add a route.
    @Test func dropsNamesThatDontResolveBack() {
        let names = HostNames.confirmed(
            for: ["10.0.0.2", "10.0.0.3"],
            reverse: Self.reverse(["10.0.0.2": "moved.example.com", "10.0.0.3": "gone.example.com"]),
            forward: Self.forward(["moved.example.com": ["10.0.0.9"]])
        )
        #expect(names.isEmpty)
    }

    /// Differently written forms of one IPv6 address confirm each other.
    @Test func comparesIPv6AddressesByValue() {
        let names = HostNames.confirmed(
            for: ["2620:149:4::1"],
            reverse: Self.reverse(["2620:149:4::1": "mac.example.com"]),
            forward: Self.forward(["mac.example.com": ["2620:0149:0004:0000:0000:0000:0000:0001"]])
        )
        #expect(names == ["2620:149:4::1": "mac.example.com"])
    }

    /// Multicast DNS names, address literals, and names that aren't plain
    /// hostnames are never published, even when they resolve back.
    @Test(arguments: ["jesses-mac.local", "10.0.0.2", "bad name.example.com", "mac.example.com:80", ""])
    func skipsUnpublishableNames(name: String) {
        let names = HostNames.confirmed(
            for: ["10.0.0.2"],
            reverse: Self.reverse(["10.0.0.2": name]),
            forward: Self.forward([name: ["10.0.0.2"]])
        )
        #expect(names.isEmpty)
    }

    /// Addresses without a PTR record get no name and leave the others alone.
    @Test func skipsAddressesWithoutNames() {
        let names = HostNames.confirmed(
            for: ["10.0.0.2", "10.0.0.3"],
            reverse: Self.reverse(["10.0.0.3": "mac.example.com"]),
            forward: Self.forward(["mac.example.com": ["10.0.0.3"]])
        )
        #expect(names == ["10.0.0.3": "mac.example.com"])
    }
}

struct DirectAddressTests {
    /// A host publishes its addresses first, then each confirmed name once,
    /// in the order of the addresses they belong to.
    @Test func publishesAddressesThenDistinctNames() {
        let addresses = RemoteNode.publishedAddresses(
            hosts: ["10.0.0.2", "17.203.82.54", "fd00::1"],
            names: ["17.203.82.54": "mac.example.com", "fd00::1": "mac.example.com", "10.0.0.2": "lan.example.com"],
            port: 51000
        )
        #expect(addresses == [
            "10.0.0.2:51000",
            "17.203.82.54:51000",
            "[fd00::1]:51000",
            "lan.example.com:51000",
            "mac.example.com:51000",
        ])
    }

    /// Names confirmed for addresses the host no longer has aren't published.
    @Test func ignoresNamesOfOldAddresses() {
        let addresses = RemoteNode.publishedAddresses(hosts: ["10.0.0.2"], names: ["10.0.0.9": "old.example.com"], port: 51000)
        #expect(addresses == ["10.0.0.2:51000"])
    }
}

struct SSHKeysTests {
    /// An endpoint ID converts to an SSH key and back unchanged, which is
    /// what lets a host key or client key be checked against the registry.
    @Test func endpointIDRoundTripsThroughSSHKey() throws {
        let identity = try DeviceIdentity(secretKey: Curve25519.Signing.PrivateKey().rawRepresentation)
        let key = try SSHKeys.publicKey(endpointID: identity.endpointID)
        #expect(SSHKeys.endpointID(of: key) == identity.endpointID)
        #expect(try SSHKeys.privateKey(for: identity).publicKey == key)
    }

    /// Strings that aren't 32-byte hex keys are rejected.
    @Test(arguments: ["", "abc", String(repeating: "zz", count: 32), String(repeating: "ab", count: 31)])
    func malformedEndpointIDsAreRejected(endpointID: String) {
        #expect(throws: RemoteAccessError.self) {
            _ = try SSHKeys.publicKey(endpointID: endpointID)
        }
    }
}
