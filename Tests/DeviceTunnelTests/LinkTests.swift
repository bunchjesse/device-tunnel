import Foundation
import Testing
@testable import DeviceTunnel

/// A link's reactions to what changes around it, mostly driven through a
/// scripted transport so every dial happens exactly when the test says.
@Suite(.timeLimit(.minutes(1)))
struct LinkTests {
    private let oldHost = makeRecord(endpointID: "host", canHost: true, directAddresses: ["10.0.0.2:4000"])
    private let newHost = makeRecord(endpointID: "host", canHost: true, directAddresses: ["10.0.0.3:4000"])

    private func startLink(_ transport: ScriptedTransport, recorder: StateRecorder = StateRecorder()) async throws -> RemoteHostLink {
        let link = RemoteHostLink(transport: transport, host: oldHost, trustedHosts: try trusting(oldHost)) { state in
            await recorder.record(state)
        }
        await link.start()
        return link
    }

    /// A host this device's user hasn't trusted is never dialed: the link
    /// stops and shows the host's fingerprint to compare. Once the user
    /// trusts it, reconnecting dials it.
    @Test func untrustedHostIsNeverDialed() async throws {
        let recorder = StateRecorder()
        let transport = ScriptedTransport { _ in ReplyingConnection(reply: .approved(token: "t", hostName: "Studio")) }
        let trustedHosts = TrustedHosts(store: InMemoryKeychainStore(), configuration: makeConfiguration())
        let link = RemoteHostLink(transport: transport, host: oldHost, trustedHosts: trustedHosts) { await recorder.record($0) }
        await link.start()

        let state = try await withTimeout(.seconds(3)) { await recorder.first { if case .untrustedHost = $0 { true } else { false } } }
        #expect(state == .untrustedHost(hostName: oldHost.name, fingerprint: oldHost.fingerprint))
        try await Task.sleep(for: .milliseconds(100))
        #expect(await transport.dials.records.isEmpty)

        try trustedHosts.trust(oldHost)
        await link.reconnect()
        _ = try await withTimeout(.seconds(3)) { await recorder.first { $0.connectedPort != nil } }
        #expect(await transport.dials.records.count == 1)
        await link.stop()
    }

    /// A host this device distrusted — by hand, or because it was revoked
    /// on the account — is never dialed either.
    @Test func distrustedHostIsNeverDialed() async throws {
        let recorder = StateRecorder()
        let transport = ScriptedTransport { _ in ReplyingConnection(reply: .approved(token: "t", hostName: "Studio")) }
        let trustedHosts = try trusting(oldHost)
        try trustedHosts.applyRevocations([DeviceRevocation(endpointID: oldHost.endpointID, deviceName: oldHost.name)])
        let link = RemoteHostLink(transport: transport, host: oldHost, trustedHosts: trustedHosts) { await recorder.record($0) }
        await link.start()

        _ = try await withTimeout(.seconds(3)) { await recorder.first { if case .untrustedHost = $0 { true } else { false } } }
        #expect(await transport.dials.records.isEmpty)
        await link.stop()
    }

    /// A trust store the link can't read dials nothing, but isn't mistaken
    /// for the user not trusting the host: the link says so and retries
    /// rather than asking the user to trust the host again.
    @Test func unreadableTrustStoreRetriesWithoutDialing() async throws {
        let recorder = StateRecorder()
        let transport = ScriptedTransport { _ in ReplyingConnection(reply: .approved(token: "t", hostName: "Studio")) }
        let trustedHosts = TrustedHosts(store: UnreadableKeychainStore(), configuration: makeConfiguration())
        let link = RemoteHostLink(transport: transport, host: oldHost, trustedHosts: trustedHosts) { await recorder.record($0) }
        await link.start()

        _ = try await withTimeout(.seconds(3)) { await recorder.first { if case .unavailable = $0 { true } else { false } } }
        #expect(await recorder.states.contains { if case .untrustedHost = $0 { true } else { false } } == false)
        #expect(await transport.dials.records.isEmpty)
        await link.stop()
    }

    /// A host whose record has no gate key runs a build too old to reach,
    /// and the link says to update rather than that the host is offline.
    @Test func hostWithoutAGateKeyNeedsAnUpdate() async throws {
        let recorder = StateRecorder()
        let fixture = try await TunnelFixture.make()
        let outdated = makeRecord(endpointID: fixture.hostRecord.endpointID, gateKey: nil, canHost: true, directAddresses: fixture.hostRecord.directAddresses)
        let link = RemoteHostLink(node: fixture.clientNode, host: outdated, trustedHosts: try trusting(outdated)) { await recorder.record($0) }
        await link.start()

        _ = try await withTimeout(.seconds(3)) { await recorder.first { $0 == .unavailable(reason: RemoteHostLink.updateBothDevices) } }
        await link.stop()
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// A registry update with new addresses that lands while a dial to the
    /// old ones is still in flight redials right away with the new ones,
    /// instead of waiting out a dial that will never answer.
    @Test func newAddressesMidDialRedialRightAway() async throws {
        let transport = ScriptedTransport { _ in
            try await Task.sleep(for: .seconds(30))
            throw RemoteAccessError.timedOut
        }
        let link = try await startLink(transport)
        await transport.dials.waitForDials(1)

        link.update(host: newHost)

        try await withTimeout(.seconds(3)) { await transport.dials.waitForDials(2) }
        #expect(await transport.dials.records.last?.directAddresses == newHost.directAddresses)
        await link.stop()
    }

    /// Updates applied back to back leave the link dialing the newest
    /// record, however their delivery is scheduled.
    @Test func latestUpdateWins() async throws {
        let transport = ScriptedTransport { _ in throw RemoteAccessError.notRecognized }
        let link = try await startLink(transport)
        await transport.dials.waitForDials(1)

        link.update(host: makeRecord(endpointID: "host", canHost: true, directAddresses: ["10.0.0.9:4000"]))
        link.update(host: newHost)

        try await withTimeout(.seconds(3)) { await transport.dials.waitForDials(2) }
        try await Task.sleep(for: .milliseconds(200))
        #expect(await transport.dials.records.last?.directAddresses == newHost.directAddresses)
        await link.stop()
    }

    /// A network change while the link waits out a retry redials right away.
    @Test func networkChangeWhileWaitingRedialsRightAway() async throws {
        let transport = ScriptedTransport { _ in ReplyingConnection(reply: .unknownDevice) }
        let link = try await startLink(transport)
        await transport.dials.waitForDials(1)
        try await Task.sleep(for: .milliseconds(100))

        await link.networkChanged()

        try await withTimeout(.seconds(3)) { await transport.dials.waitForDials(2) }
        await link.stop()
    }

    /// A network change during a dial doesn't abandon it, but if that dial
    /// fails, the next one follows right away instead of after the delay.
    @Test func networkChangeDuringADialRetriesRightAfterItFails() async throws {
        let gate = Gate()
        let transport = ScriptedTransport { _ in
            await gate.wait()
            return ReplyingConnection(reply: .unknownDevice)
        }
        let link = try await startLink(transport)
        await transport.dials.waitForDials(1)

        await link.networkChanged()
        try await Task.sleep(for: .milliseconds(100))
        #expect(await transport.dials.records.count == 1)
        gate.open()

        try await withTimeout(.seconds(3)) { await transport.dials.waitForDials(2) }
        await link.stop()
    }

    /// A host that doesn't find this device in its registry — whether it
    /// says so on the control stream or turns the key away during SSH
    /// authentication — shows as not recognized, the state that tells the
    /// user iCloud Keychain is behind.
    @Test(arguments: [true, false])
    func unrecognizedDeviceIsReportedAsSuch(turnedAwayDuringAuthentication: Bool) async throws {
        let recorder = StateRecorder()
        let transport = ScriptedTransport { _ in
            if turnedAwayDuringAuthentication { throw RemoteAccessError.notRecognized }
            return ReplyingConnection(reply: .unknownDevice)
        }
        let link = try await startLink(transport, recorder: recorder)

        _ = try await withTimeout(.seconds(3)) { await recorder.first { $0 == .notRecognized } }
        await link.stop()
    }

    /// A dial Local Network privacy blocked says so, rather than showing
    /// the Mac as offline, since only the user can fix it.
    @Test func localNetworkDenialIsReported() async throws {
        let recorder = StateRecorder()
        let transport = ScriptedTransport { _ in throw RemoteAccessError.localNetworkDenied }
        let link = try await startLink(transport, recorder: recorder)

        _ = try await withTimeout(.seconds(3)) { await recorder.first { $0 == .localNetworkDenied } }
        await link.stop()
    }

    /// A dial that lands after the link stopped is closed, and the stopped
    /// link publishes nothing more.
    @Test func stoppedLinkIgnoresALateDial() async throws {
        let recorder = StateRecorder()
        let gate = Gate()
        let connection = FakeConnection()
        let transport = ScriptedTransport { _ in
            await gate.wait()
            return connection
        }
        let link = try await startLink(transport, recorder: recorder)
        await transport.dials.waitForDials(1)

        await link.stop()
        let published = await recorder.states.count
        gate.open()
        try await Task.sleep(for: .milliseconds(200))

        #expect(connection.isClosed)
        #expect(await recorder.states.count == published)
    }

    /// A tunnel through the relay keeps dialing the host directly. When a
    /// direct dial fails it stays on the relay; a network change sends the
    /// next dial at once, and the direct tunnel that succeeds replaces the
    /// relayed one on the same port, closing it. Probes never use the relay.
    @Test func relayedTunnelMovesToADirectOneWhenItCan() async throws {
        let recorder = StateRecorder()
        let relayed = ReplyingConnection(reply: .approved(token: "t", hostName: "Studio"), path: .relay)
        let direct = ReplyingConnection(reply: .approved(token: "t", hostName: "Studio"), path: .direct)
        let directDials = LockedCounter()
        let transport = ScriptedTransport(dialAllowingRelay: { _, allowingRelay in
            if allowingRelay { return relayed }
            directDials.increment()
            if directDials.value == 1 { throw RemoteAccessError.timedOut }
            return direct
        })
        let link = try await startLink(transport, recorder: recorder)
        let first = try await withTimeout(.seconds(3)) { await recorder.first { $0.connectedPath == .relay } }
        await transport.dials.waitForDials(2)
        try await waitUntil { directDials.value == 1 }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await recorder.states.last?.connectedPath == .relay)

        await link.networkChanged()

        let moved = try await withTimeout(.seconds(3)) { await recorder.first { $0.connectedPath == .direct } }
        #expect(moved.connectedPort == first.connectedPort)
        #expect(relayed.isClosed)
        #expect(!direct.isClosed)
        #expect(await transport.dials.allowedRelay == [true, false, false])
        await link.stop()
    }

    /// A direct tunnel looks for nothing better: no further dials happen
    /// while it's open, even when the network changes.
    @Test func directTunnelDoesNotProbe() async throws {
        let recorder = StateRecorder()
        let transport = ScriptedTransport { _ in ReplyingConnection(reply: .approved(token: "t", hostName: "Studio")) }
        let link = try await startLink(transport, recorder: recorder)
        _ = try await withTimeout(.seconds(3)) { await recorder.first { $0.connectedPath == .direct } }

        await link.networkChanged()
        try await Task.sleep(for: .milliseconds(200))

        #expect(await transport.dials.records.count == 1)
        await link.stop()
    }

    /// When the relayed tunnel drops while a direct dial is still waiting
    /// for an answer, the link reports the loss and redials instead of
    /// sitting out the dial.
    @Test func lostRelayedTunnelRedials() async throws {
        let recorder = StateRecorder()
        let relayed = ReplyingConnection(reply: .approved(token: "t", hostName: "Studio"), path: .relay)
        let transport = ScriptedTransport(dialAllowingRelay: { _, allowingRelay in
            guard allowingRelay else {
                try await Task.sleep(for: .seconds(30))
                throw RemoteAccessError.timedOut
            }
            return relayed
        })
        let link = try await startLink(transport, recorder: recorder)
        _ = try await withTimeout(.seconds(3)) { await recorder.first { $0.connectedPath == .relay } }
        await transport.dials.waitForDials(2)

        relayed.close(reason: "relay went away")

        _ = try await withTimeout(.seconds(3)) { await recorder.first { $0.isUnreachable } }
        await link.stop()
    }
}
