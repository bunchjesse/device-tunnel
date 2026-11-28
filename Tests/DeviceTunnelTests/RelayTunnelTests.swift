import Foundation
import RendezvousRelayServer
import Testing
@testable import DeviceTunnel

/// A relay running in-process on 127.0.0.1, standing in for a deployed one.
struct InProcessRelay {
    /// `host:port`, as a host's settings and record name it.
    let address: String
    /// The task running the relay.
    private let task: Task<Void, any Error>

    /// Starts a relay serving `allowedNamespaces` (nil for any).
    static func start(allowedNamespaces: Set<String>? = nil) async throws -> InProcessRelay {
        let server = RelayServer(configuration: RelayServerConfiguration(
            host: "127.0.0.1",
            port: 0,
            allowedNamespaces: allowedNamespaces,
            log: { _ in }
        ))
        let (bound, continuation) = AsyncStream.makeStream(of: Int.self)
        let task = Task { try await server.run { continuation.yield($0) } }
        var ports = bound.makeAsyncIterator()
        guard let port = await ports.next() else { throw RemoteAccessError.localSocketFailed("relay didn't start") }
        return InProcessRelay(address: "127.0.0.1:\(port)", task: task)
    }

    /// Stops serving.
    func stop() async {
        task.cancel()
        _ = await task.result
    }
}

extension RemoteNode {
    /// Waits until the relay registration reports a status matching `predicate`.
    func waitForRelayStatus(timeout: Duration = .seconds(10), _ predicate: @escaping @Sendable (RelayStatus) -> Bool) async throws -> RelayStatus {
        let deadline = ContinuousClock.now + timeout
        while true {
            let status = relayStatus
            if predicate(status) { return status }
            guard ContinuousClock.now < deadline else { throw RemoteAccessError.timedOut }
            try await Task.sleep(for: .milliseconds(20))
        }
    }
}

/// Tunnels through a real relay, end to end: the host registers, the client
/// dials the relay the host's record publishes, and SSH runs through it.
@Suite(.timeLimit(.minutes(1)))
struct RelayTunnelTests {
    /// Starts the fixture with its host registered on `relay`, and the
    /// client using relays. Returns the host record publishing the relay,
    /// with the host's direct addresses unless `withDirectAddresses` is off.
    private func makeRelayedFixture(relay: InProcessRelay, withDirectAddresses: Bool = false) async throws -> (TunnelFixture, DeviceRecord) {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        fixture.hostNode.setRelay(relay.address)
        fixture.clientNode.setDialsThroughRelays(true)
        _ = try await fixture.hostNode.waitForRelayStatus { $0 == .registered }
        var record = fixture.hostRecord
        record.relayAddress = relay.address
        if !withDirectAddresses {
            record.directAddresses = []
        }
        return (fixture, record)
    }

    /// A host that can only be reached through its relay is, and the link
    /// says the tunnel runs through the relay. Requests reach the host's
    /// server, and the host sees the device as connected through the relay.
    @Test func hostIsReachedThroughItsRelay() async throws {
        let relay = try await InProcessRelay.start()
        let (fixture, relayOnly) = try await makeRelayedFixture(relay: relay)
        let devices = Locked<[RemoteHostService.ConnectedDevice]>([])
        let service = RemoteHostService(node: fixture.hostNode, environment: RemoteHostService.Environment(
            registry: fixture.registry,
            approvals: fixture.approvals,
            hostName: { "Studio" },
            localPort: { [apiPort = fixture.apiPort] in apiPort },
            token: { _ in "token" },
            revokeToken: { _ in },
            requestApproval: { _ in .approved },
            isAcceptingConnections: { true },
            connectionsChanged: { list in devices.value = list }
        ))
        let host = Task { await service.run() }
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder, host: relayOnly)

        let state = try await withTimeout(.seconds(15)) { await recorder.first { $0.connectedPort != nil } }
        #expect(state.connectedPath == .relay)
        let port = try #require(state.connectedPort)
        #expect(try await echo("through the relay", throughPort: port) == "through the relay")
        try await waitUntil { !devices.value.isEmpty }
        #expect(devices.value.first?.path == .relay)

        await fixture.tearDown(link: link, host: host)
        await relay.stop()
    }

    /// With both a direct route and a relay, the direct route wins: the
    /// relay waits out its head start and is never used.
    @Test func directRouteIsPreferredOverTheRelay() async throws {
        let relay = try await InProcessRelay.start()
        let (fixture, record) = try await makeRelayedFixture(relay: relay, withDirectAddresses: true)
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder, host: record)

        let state = try await withTimeout(.seconds(15)) { await recorder.first { $0.connectedPort != nil } }
        #expect(state.connectedPath == .direct)

        await fixture.tearDown(link: link, host: host)
        await relay.stop()
    }

    /// A client that doesn't use relays never dials one, even when the
    /// host publishes it: with no direct route, there's no route at all.
    @Test func clientThatDoesNotUseRelaysIgnoresThem() async throws {
        let relay = try await InProcessRelay.start()
        let (fixture, relayOnly) = try await makeRelayedFixture(relay: relay)
        fixture.clientNode.setDialsThroughRelays(false)

        await #expect(throws: RemoteAccessError.noRoute) {
            _ = try await fixture.clientNode.connect(to: relayOnly, allowingRelay: true)
        }

        await fixture.clientNode.close()
        await fixture.hostNode.close()
        await relay.stop()
    }

    /// A tunnel through the relay moves to a direct one as soon as the
    /// host's record offers a direct route, on the same loopback port, and
    /// the relayed tunnel is closed.
    @Test func relayedTunnelMovesToADirectRouteWhenOneAppears() async throws {
        let relay = try await InProcessRelay.start()
        let (fixture, relayOnly) = try await makeRelayedFixture(relay: relay)
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder, host: relayOnly)
        let relayed = try await withTimeout(.seconds(15)) { await recorder.first { $0.connectedPath == .relay } }

        var withDirect = relayOnly
        withDirect.directAddresses = fixture.hostRecord.directAddresses
        link.update(host: withDirect)

        let direct = try await withTimeout(.seconds(15)) { await recorder.first { $0.connectedPath == .direct } }
        #expect(direct.connectedPort == relayed.connectedPort)
        let port = try #require(direct.connectedPort)
        #expect(try await echo("direct now", throughPort: port) == "direct now")
        #expect(await !recorder.states.contains { $0.isUnreachable })

        await fixture.tearDown(link: link, host: host)
        await relay.stop()
    }

    /// A relay that doesn't serve the app's namespace leaves the host's
    /// registration unavailable, with the relay's reason, rather than
    /// claiming it registered.
    @Test func relayThatRefusesTheNamespaceIsReported() async throws {
        let relay = try await InProcessRelay.start(allowedNamespaces: ["com.example.other"])
        let fixture = try await TunnelFixture.make()
        fixture.hostNode.setRelay(relay.address)

        let status = try await fixture.hostNode.waitForRelayStatus { if case .unavailable = $0 { true } else { false } }
        #expect(status == .unavailable(reason: RemoteAccessError.relayRefused(.namespaceNotAllowed).localizedDescription))

        fixture.hostNode.setRelay(nil)
        #expect(fixture.hostNode.relayStatus == .off)
        await fixture.clientNode.close()
        await fixture.hostNode.close()
        await relay.stop()
    }

    /// The host registers in its build flavor's namespace — the Keychain
    /// prefix — so a relay that admits only that namespace serves it.
    @Test func hostRegistersInItsFlavorsNamespace() async throws {
        let fixture = try await TunnelFixture.make()
        let relay = try await InProcessRelay.start(allowedNamespaces: [fixture.configuration.relayNamespace])
        fixture.hostNode.setRelay(relay.address)

        _ = try await fixture.hostNode.waitForRelayStatus { $0 == .registered }

        await fixture.clientNode.close()
        await fixture.hostNode.close()
        await relay.stop()
    }
}

/// Relay addresses as Settings and device records carry them.
struct RelayAddressTests {
    /// Relay addresses entered in Settings are canonicalized with the
    /// relay's default port, and anything that isn't a host and optional
    /// port is rejected.
    @Test func relayAddressesAreCanonicalized() {
        #expect(RemoteNode.canonicalRelayAddress("relay.example.com") == "relay.example.com:3340")
        #expect(RemoteNode.canonicalRelayAddress(" relay.example.com:4000 ") == "relay.example.com:4000")
        #expect(RemoteNode.canonicalRelayAddress("http://relay.example.com") == nil)
        #expect(RemoteNode.canonicalRelayAddress("") == nil)
    }

    /// A record without a `relayAddress` key decodes with no relay, one
    /// from protocol 2 decodes without a gate key, and a record's relay
    /// survives the round trip through the registry's JSON.
    @Test func recordsDecodeWithAndWithoutARelay() throws {
        let withoutRelay = Data("""
        {"endpointID":"ab","name":"Studio","platform":"macOS","canHost":true,"directAddresses":[],"protocolVersion":2,"updatedAt":0}
        """.utf8)
        let decodedOld = try JSONDecoder().decode(DeviceRecord.self, from: withoutRelay)
        #expect(decodedOld.relayAddress == nil)
        #expect(decodedOld.gateKey == nil)

        let record = makeRecord(endpointID: "ab", canHost: true, relayAddress: "relay.example.com:3340")
        let decoded = try JSONDecoder().decode(DeviceRecord.self, from: JSONEncoder().encode(record))
        #expect(decoded.relayAddress == "relay.example.com:3340")
    }
}
