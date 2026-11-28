import CryptoKit
import Foundation
import Network
import NIOCore
import NIOEmbedded
import Synchronization
import Testing
@testable import DeviceTunnel

/// A host and a client on real endpoints bound to the loopback interface,
/// plus a TCP echo server standing in for the host's API server.
struct TunnelFixture {
    let configuration: RemoteAccessConfiguration
    let hostStore: InMemoryKeychainStore
    let hostNode: RemoteNode
    let clientNode: RemoteNode
    let hostRecord: DeviceRecord
    let clientRecord: DeviceRecord
    /// The client's trust store, which trusts the fixture's host.
    let trustedHosts: TrustedHosts
    let apiServer: LoopbackListener
    let apiPort: UInt16

    var registry: DeviceRegistry { DeviceRegistry(store: hostStore, configuration: configuration) }
    var approvals: DeviceApprovals { DeviceApprovals(store: hostStore, configuration: configuration) }

    /// Starts both endpoints. `hostPort` asks the host to listen on that
    /// port rather than an ephemeral one another test's socket might take;
    /// `discovery` has it advertise over Bonjour, on loopback only.
    static func make(hostPort: UInt16? = nil, discovery: Bool = false) async throws -> TunnelFixture {
        let configuration = makeConfiguration(discovery: discovery)
        let synced = InMemoryKeychainStore.SyncedStorage()
        let hostStore = InMemoryKeychainStore(synced: synced)
        let clientStore = InMemoryKeychainStore(synced: synced)
        let hostIdentity = try DeviceIdentity.loadOrCreate(store: hostStore, configuration: configuration)
        let clientIdentity = try DeviceIdentity.loadOrCreate(store: clientStore, configuration: configuration)

        let hostNode = try await RemoteNode.start(
            identity: hostIdentity,
            configuration: configuration,
            acceptingDevicesIn: DeviceRegistry(store: hostStore, configuration: configuration),
            preferredPort: hostPort,
            listenHost: "127.0.0.1"
        )
        let clientNode = try await RemoteNode.start(
            identity: clientIdentity,
            configuration: configuration,
            acceptingDevicesIn: nil
        )

        let apiServer = try LoopbackListener(onConnection: { connection in
            Task { await echoUntilFinished(connection) }
        }, onFailure: { _ in })
        let apiPort = try await apiServer.start()

        let hostRecord = DeviceRecord(
            endpointID: hostIdentity.endpointID,
            gateKey: hostIdentity.gateKey,
            name: "Studio",
            platform: .macOS,
            canHost: true,
            directAddresses: hostNode.address()
        )
        let clientRecord = makeRecord(endpointID: clientIdentity.endpointID, gateKey: clientIdentity.gateKey, name: "iPhone")
        let trustedHosts = TrustedHosts(store: clientStore, configuration: configuration)
        try trustedHosts.trust(hostRecord)

        return TunnelFixture(
            configuration: configuration,
            hostStore: hostStore,
            hostNode: hostNode,
            clientNode: clientNode,
            hostRecord: hostRecord,
            clientRecord: clientRecord,
            trustedHosts: trustedHosts,
            apiServer: apiServer,
            apiPort: apiPort
        )
    }

    /// Registers the client on the account and approves it on the host.
    func approveClient() throws {
        try registry.publish(clientRecord)
        try approvals.record(DeviceApproval(endpointID: clientRecord.endpointID, deviceName: "iPhone", decision: .approved))
    }

    /// A host service whose approval prompt answers with `answer`.
    func makeHostService(
        prompts: LockedCounter = LockedCounter(),
        revocations: LockedCounter = LockedCounter(),
        accepting: LockedFlag = LockedFlag(true),
        answer: @escaping @Sendable (DeviceRecord) async -> ApprovalDecision? = { _ in .approved }
    ) -> RemoteHostService {
        let apiPort = apiPort
        return RemoteHostService(node: hostNode, environment: RemoteHostService.Environment(
            registry: registry,
            approvals: approvals,
            hostName: { "Studio" },
            localPort: { apiPort },
            token: { endpointID in "token-\(endpointID.prefix(8))" },
            revokeToken: { _ in revocations.increment() },
            requestApproval: { record in
                prompts.increment()
                return await answer(record)
            },
            isAcceptingConnections: { accepting.value },
            connectionsChanged: { _ in }
        ))
    }

    /// Starts a host service whose approval prompt answers with `answer`.
    func startHost(
        prompts: LockedCounter = LockedCounter(),
        answer: @escaping @Sendable (DeviceRecord) async -> ApprovalDecision? = { _ in .approved }
    ) -> Task<Void, Never> {
        let service = makeHostService(prompts: prompts, answer: answer)
        return Task { await service.run() }
    }

    /// Starts a client link to `host` (the fixture's host by default),
    /// recording its states. The client trusts `host` first, as its user
    /// would have; `LinkTests` covers hosts the user hasn't trusted.
    func startLink(recorder: StateRecorder, host: DeviceRecord? = nil) async -> RemoteHostLink {
        let host = host ?? hostRecord
        do {
            try trustedHosts.trust(host)
        } catch {
            Issue.record(error, "Couldn't trust the host")
        }
        let link = RemoteHostLink(node: clientNode, host: host, trustedHosts: trustedHosts) { state in
            await recorder.record(state)
        }
        await link.start()
        return link
    }

    func tearDown(link: RemoteHostLink, host: Task<Void, Never>) async {
        await link.stop()
        await clientNode.close()
        await hostNode.close()
        await host.value
        apiServer.stop()
    }
}

/// Sends `payload` through a link's loopback port and returns the echo.
func echo(_ payload: String, throughPort port: UInt16) async throws -> String {
    String(decoding: try await echo(Data(payload.utf8), throughPort: port), as: UTF8.self)
}

/// Sends `payload` through a link's loopback port and returns the echo.
func echo(_ payload: Data, throughPort port: UInt16) async throws -> Data {
    let stream = try await TCPStream.connectToLoopback(port: port)
    try await stream.write(payload)
    try await stream.finish()
    let reply = try await readToEnd(stream)
    await stream.close()
    return reply
}

extension RemoteHostLink.State {
    var isUnreachable: Bool {
        if case .unreachable = self { return true }
        return false
    }
}

/// Streams on a raw tunnel between the fixture's two endpoints, with no
/// host service in between.
@Suite(.timeLimit(.minutes(1)))
struct SSHStreamTests {
    /// Dials the fixture's host and returns both ends of one stream.
    private func openStream(_ fixture: TunnelFixture) async throws -> (client: any ByteStream, host: any ByteStream) {
        let dialing = Task { try await fixture.clientNode.connect(to: fixture.hostRecord, allowingRelay: false) }
        let incoming = try #require(await fixture.hostNode.nextIncoming())
        let hostConnection = try await incoming.accept()
        let clientConnection = try await dialing.value
        let clientStream = try await clientConnection.openStream()
        let hostStream = try await hostConnection.acceptStream()
        return (clientStream, hostStream)
    }

    /// The side that finishes second — after it has already seen the
    /// peer's end of stream — finishes without error, and the first side
    /// reads a clean end of stream rather than an abort. HTTP needs both:
    /// a server replies after the client's half-close.
    @Test func secondSideFinishesCleanly() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let (client, host) = try await openStream(fixture)

        try await client.write(Data("request".utf8))
        try await client.finish()
        #expect(try await readToEnd(host) == Data("request".utf8))

        try await host.write(Data("response".utf8))
        try await host.finish()
        #expect(try await readToEnd(client) == Data("response".utf8))

        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// Finishing before reading the peer's end of stream still leaves that
    /// end of stream readable afterwards, instead of turning it into a
    /// failure.
    @Test func finishingBeforeReadingThePeersEndStillReadsIt() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let (client, host) = try await openStream(fixture)

        try await client.write(Data("request".utf8))
        try await client.finish()
        #expect(try await host.readExactly(7) == Data("request".utf8))
        try await Task.sleep(for: .milliseconds(50))

        try await host.finish()
        #expect(try await host.read(upTo: 16).isEmpty)

        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }
}

@Suite(.timeLimit(.minutes(1)))
struct TunnelTests {
    /// An approved device on the account gets a token and its loopback
    /// connections reach the host's local server end to end over a direct
    /// connection, including the half-close an HTTP client sends after its
    /// request.
    @Test func approvedDeviceReachesLocalServer() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)

        let state = await recorder.first { $0.connectedPort != nil }
        guard case .connected(let port, let token, let path) = state else {
            Issue.record("Expected a connected state, got \(state)")
            return
        }
        #expect(token == "token-\(fixture.clientRecord.endpointID.prefix(8))")
        #expect(path == .direct)
        #expect(try await echo("ping", throughPort: port) == "ping")

        await fixture.tearDown(link: link, host: host)
    }

    /// `reconnect()` drops both the tunnel and the loopback listener and
    /// connects again from scratch — passing back through `.connecting`
    /// rather than jumping straight from one `.connected` state to the
    /// next — and the port it republishes is a fresh, working one; the old
    /// port stops answering once its listener is torn down.
    @Test func reconnectReplacesTunnelAndListener() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        let firstState = await recorder.first { $0.connectedPort != nil }
        let firstPort = try #require(firstState.connectedPort)
        #expect(try await echo("before", throughPort: firstPort) == "before")

        let markIndex = await recorder.states.count
        await link.reconnect()
        let nextState = await recorder.first { $0.connectedPort != nil && $0.connectedPort != firstPort }
        let nextPort = try #require(nextState.connectedPort, "reconnect() never republished a new port")

        let statesSinceReconnect = await recorder.states.suffix(from: markIndex)
        #expect(statesSinceReconnect.contains(.connecting), "reconnect() should drop through .connecting, not republish the old connection in place")

        #expect(try await echo("after", throughPort: nextPort) == "after")
        await #expect(throws: (any Error).self) {
            try await echo("stale", throughPort: firstPort)
        }

        await fixture.tearDown(link: link, host: host)
    }

    /// Calling `reconnect()` while the link is waiting on the host's
    /// approval prompt closes that connection — ending the wait — and dials
    /// again, landing back on the same shared prompt task rather than
    /// opening a second one.
    @Test func reconnectWhileAwaitingApprovalDoesNotPromptAgain() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.registry.publish(fixture.clientRecord)
        let prompts = LockedCounter()
        let (answers, answer) = AsyncStream.makeStream(of: ApprovalDecision.self)
        let host = fixture.startHost(prompts: prompts) { _ in
            await answers.first { _ in true }
        }

        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        _ = await recorder.first { $0 == .awaitingApproval(hostName: "Studio") }

        let markIndex = await recorder.states.count
        await link.reconnect()

        // A second `.awaitingApproval` recorded after the mark proves the
        // reconnect dialed again and is waiting anew, rather than the test
        // observing the first, already-cached occurrence.
        let deadline = ContinuousClock.now + .seconds(10)
        var sawSecondPrompt = false
        while ContinuousClock.now < deadline {
            if await recorder.states.suffix(from: markIndex).contains(.awaitingApproval(hostName: "Studio")) {
                sawSecondPrompt = true
                break
            }
            try? await Task.sleep(for: .milliseconds(20))
        }
        #expect(sawSecondPrompt)
        #expect(prompts.value == 1)

        answer.yield(.approved)
        _ = await recorder.first { $0.connectedPort != nil }
        #expect(prompts.value == 1)

        await fixture.tearDown(link: link, host: host)
    }

    /// A host serves one tunnel per device: when a second link from the
    /// same client identity connects, the host closes the first tunnel
    /// rather than keeping both — an older tunnel left over across sleep
    /// can't pin the host's SSE subscribers forever.
    @Test func hostReplacesADevicesOlderTunnel() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()

        let recorderA = StateRecorder()
        let linkA = await fixture.startLink(recorder: recorderA)
        let stateA = await recorderA.first { $0.connectedPort != nil }
        let portA = try #require(stateA.connectedPort)
        #expect(try await echo("a", throughPort: portA) == "a")

        let recorderB = StateRecorder()
        let linkB = await fixture.startLink(recorder: recorderB)
        let stateB = await recorderB.first { $0.connectedPort != nil }
        let portB = try #require(stateB.connectedPort)
        #expect(portB != portA)

        // The host closed A's now-superseded tunnel, so A's link sees the
        // connection drop.
        _ = await recorderA.first(where: \.isUnreachable)
        await linkA.stop()

        #expect(try await echo("b", throughPort: portB) == "b")

        await fixture.tearDown(link: linkB, host: host)
    }

    /// Throughput probe: 4 MB through the link over a direct connection, so
    /// slow bulk transfers (large transcripts) can be attributed. Prints
    /// MB/s; kept simple so reading the number is the point.
    @Test func tunnelThroughputProbe() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        let port = try #require(await recorder.first { $0.connectedPort != nil }.connectedPort)

        let total = 4 * 1024 * 1024
        let chunk = Data(repeating: 0x61, count: 64 * 1024)
        let started = ContinuousClock.now
        let stream = try await TCPStream.connectToLoopback(port: port)
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                var remaining = total
                while remaining > 0 {
                    let n = min(chunk.count, remaining)
                    try await stream.write(chunk.prefix(n))
                    remaining -= n
                }
                try await stream.finish()
            }
            group.addTask {
                var received = 0
                while received < total {
                    received += try await stream.read(upTo: 64 * 1024).count
                }
            }
            try await group.waitForAll()
        }
        await stream.close()
        let seconds = ContinuousClock.now - started
        let elapsed = Double(seconds.components.seconds) + Double(seconds.components.attoseconds) / 1e18
        let mbps = (2.0 * Double(total) / (1024 * 1024)) / elapsed
        print("THROUGHPUT: \(String(format: "%.2f", mbps)) MB/s round-trip for 4 MB each way (\(seconds))")

        await fixture.tearDown(link: link, host: host)
    }

    /// Many simultaneous connections, as URLSession opens for parallel
    /// requests and SSE streams, each get their own stream through one tunnel.
    @Test func concurrentConnectionsShareOneTunnel() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        let port = try #require(await recorder.first { $0.connectedPort != nil }.connectedPort)

        let replies = try await withThrowingTaskGroup(of: String.self) { group in
            for index in 0..<8 {
                group.addTask { try await echo("request-\(index)", throughPort: port) }
            }
            return try await group.reduce(into: Set<String>()) { $0.insert($1) }
        }
        #expect(replies == Set((0..<8).map { "request-\($0)" }))

        await fixture.tearDown(link: link, host: host)
    }

    /// A device's first connection waits on the host user's answer; the
    /// approval is stored, so reconnecting doesn't ask again.
    @Test func firstConnectionAsksOnceAndIsRemembered() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.registry.publish(fixture.clientRecord)
        let prompts = LockedCounter()
        let host = fixture.startHost(prompts: prompts) { _ in
            try? await Task.sleep(for: .milliseconds(200))
            return .approved
        }
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)

        _ = await recorder.first { $0 == .awaitingApproval(hostName: "Studio") }
        _ = await recorder.first { $0.connectedPort != nil }
        #expect(prompts.value == 1)
        #expect(try fixture.approvals.decision(for: fixture.clientRecord.endpointID) == .approved)

        let reconnected = StateRecorder()
        let secondLink = await fixture.startLink(recorder: reconnected)
        _ = await reconnected.first { $0.connectedPort != nil }
        #expect(prompts.value == 1)
        #expect(await !reconnected.states.contains { if case .awaitingApproval = $0 { true } else { false } })

        await secondLink.stop()
        await fixture.tearDown(link: link, host: host)
    }

    /// A device that gives up while the host's user is still deciding
    /// closes its connection, and its next attempt waits on the same prompt
    /// instead of opening another.
    @Test func stoppingWhileAwaitingApprovalKeepsOnePrompt() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.registry.publish(fixture.clientRecord)
        let prompts = LockedCounter()
        let (answers, answer) = AsyncStream.makeStream(of: ApprovalDecision.self)
        let host = fixture.startHost(prompts: prompts) { _ in
            await answers.first { _ in true }
        }

        let first = StateRecorder()
        let firstLink = await fixture.startLink(recorder: first)
        _ = await first.first { $0 == .awaitingApproval(hostName: "Studio") }
        await firstLink.stop()

        let second = StateRecorder()
        let secondLink = await fixture.startLink(recorder: second)
        _ = await second.first { $0 == .awaitingApproval(hostName: "Studio") }
        answer.yield(.approved)
        _ = await second.first { $0.connectedPort != nil }
        #expect(prompts.value == 1)

        await secondLink.stop()
        await fixture.tearDown(link: firstLink, host: host)
    }

    /// A device whose record hasn't reached the host's registry is refused
    /// as not recognized, without prompting the host's user.
    @Test func deviceMissingFromRegistryIsNotRecognized() async throws {
        let fixture = try await TunnelFixture.make()
        let prompts = LockedCounter()
        let host = fixture.startHost(prompts: prompts)
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)

        _ = await recorder.first { $0 == .notRecognized }
        #expect(prompts.value == 0)

        await fixture.tearDown(link: link, host: host)
    }

    /// Revoking a connected device closes its tunnel and revokes its token,
    /// and its reconnection has to ask for approval again.
    @Test func disconnectCutsOffConnectedDevice() async throws {
        let fixture = try await TunnelFixture.make()
        let clientID = fixture.clientRecord.endpointID
        try fixture.approveClient()
        let revocations = LockedCounter()
        let service = fixture.makeHostService(revocations: revocations) { _ in .denied }
        let host = Task { await service.run() }
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        _ = await recorder.first { $0.connectedPort != nil }

        try fixture.approvals.remove(endpointID: clientID)
        await service.disconnect(endpointID: clientID)

        #expect(revocations.value == 1)
        _ = await recorder.first { $0 == .denied(hostName: "Studio") }
        await fixture.tearDown(link: link, host: host)
    }

    /// Turning remote access off disconnects connected devices, revokes
    /// their tokens, and turns their reconnection away.
    @Test func turningRemoteAccessOffDisconnectsEveryone() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let revocations = LockedCounter()
        let accepting = LockedFlag(true)
        let service = fixture.makeHostService(revocations: revocations, accepting: accepting)
        let host = Task { await service.run() }
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        _ = await recorder.first { $0.connectedPort != nil }

        accepting.value = false
        await service.disconnectAll()

        #expect(revocations.value == 1)
        _ = await recorder.first { $0 == .unavailable(reason: "Remote access is turned off on Studio.") }
        await fixture.tearDown(link: link, host: host)
    }

    /// A device the host's user refused is told so and gets no token.
    @Test func deniedDeviceIsRefused() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.registry.publish(fixture.clientRecord)
        try fixture.approvals.record(DeviceApproval(endpointID: fixture.clientRecord.endpointID, deviceName: "iPhone", decision: .denied))
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)

        _ = await recorder.first { $0 == .denied(hostName: "Studio") }
        #expect(await !recorder.states.contains { $0.connectedPort != nil })

        await fixture.tearDown(link: link, host: host)
    }

    /// A server answering at the host's address that can't prove it knows
    /// the gate key of the host the registry lists is never trusted: the
    /// client stays unreachable instead of sending anything to an impostor.
    @Test func hostWithTheWrongKeyIsRejected() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        let impostor = try DeviceIdentity(secretKey: Curve25519.Signing.PrivateKey().rawRepresentation)
        let impostorRecord = DeviceRecord(
            endpointID: impostor.endpointID,
            gateKey: impostor.gateKey,
            name: "Studio",
            platform: .macOS,
            canHost: true,
            directAddresses: fixture.hostRecord.directAddresses
        )
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder, host: impostorRecord)

        let state = await recorder.first(where: \.isUnreachable)
        #expect(state == .unreachable(reason: RemoteAccessError.hostKeyMismatch.localizedDescription))
        #expect(await !recorder.states.contains { $0.connectedPort != nil })

        await fixture.tearDown(link: link, host: host)
    }
}

@Suite(.timeLimit(.minutes(1)))
struct HostListenerTests {
    /// A host whose listener fails — Network can fail one across sleep or
    /// a network reset — listens again on the same port, even with tunnels
    /// still open on it, so its published addresses stay valid and clients
    /// reconnect without waiting for iCloud Keychain.
    @Test func hostListensAgainOnTheSamePortAfterItsListenerFails() async throws {
        // Outside the ephemeral range, so no other test's socket takes the
        // port while the listener is down.
        let fixture = try await TunnelFixture.make(hostPort: .random(in: 20000...40000))
        try fixture.approveClient()
        let host = fixture.startHost()
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        let firstPort = try #require(await recorder.first { $0.connectedPort != nil }.connectedPort)
        let listeningPort = try #require(fixture.hostNode.listeningPort)
        let failed = try #require(fixture.hostNode.listenerChannel)

        try await failed.close().get()
        try await withTimeout(.seconds(5)) {
            while fixture.hostNode.listenerChannel == nil || fixture.hostNode.listenerChannel === failed {
                try await Task.sleep(for: .milliseconds(20))
            }
        }
        #expect(fixture.hostNode.listeningPort == listeningPort)

        await link.reconnect()
        let next = try await withTimeout(.seconds(5)) {
            await recorder.first { $0.connectedPort != nil && $0.connectedPort != firstPort }
        }
        #expect(try await echo("again", throughPort: try #require(next.connectedPort)) == "again")

        await fixture.tearDown(link: link, host: host)
    }

    /// Subscribing to a host's address changes reports right away, so a
    /// change landing between reading the addresses and subscribing can't
    /// be missed.
    @Test func subscribingToAddressChangesReportsRightAway() async throws {
        let fixture = try await TunnelFixture.make()
        let reports = LockedCounter()

        fixture.hostNode.onAddressChange { reports.increment() }

        #expect(reports.value == 1)
        await fixture.hostNode.close()
        await fixture.clientNode.close()
    }
}

@Suite(.timeLimit(.minutes(1)))
struct HostAdmissionTests {
    /// A device the host's registry doesn't list is turned away during SSH
    /// authentication — before it can open a stream or send a message the
    /// host has to parse — and learns that it isn't recognized, which
    /// iCloud Keychain will fix, rather than that the host is offline.
    @Test func unregisteredDeviceIsTurnedAwayDuringAuthentication() async throws {
        let fixture = try await TunnelFixture.make()
        let service = fixture.makeHostService()
        let host = Task { await service.run() }

        await #expect(throws: RemoteAccessError.notRecognized) {
            _ = try await fixture.clientNode.connect(to: fixture.hostRecord, allowingRelay: false)
        }

        await fixture.clientNode.close()
        await fixture.hostNode.close()
        await host.value
        fixture.apiServer.stop()
    }

    /// Connections that never answer the access gate — anything on the
    /// network can open them — can't lock out a registered device: they
    /// never reach the host's handshake slots, and the gate's limiter turns
    /// away the oldest of them to make room.
    @Test func idleConnectionsCantLockOutARegisteredDevice() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        let port = try #require(fixture.hostNode.listeningPort)
        var idle: [TCPStream] = []
        for _ in 0..<(RemoteHostService.maxPendingHandshakes + 8) {
            idle.append(try await TCPStream.connectToLoopback(port: port))
        }
        try await Task.sleep(for: .milliseconds(200))

        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        _ = try await withTimeout(.seconds(10)) {
            await recorder.first { $0.connectedPort != nil }
        }

        for connection in idle { await connection.abort() }
        await fixture.tearDown(link: link, host: host)
    }

    /// A device revoked on the account is cut off and denied, and stays
    /// denied after the revocation is deleted and its record republished —
    /// which the revoked device itself could do.
    @Test func revokedDeviceStaysDenied() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let revocations = LockedCounter()
        let service = fixture.makeHostService(revocations: revocations)
        let host = Task { await service.run() }
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        _ = await recorder.first { $0.connectedPort != nil }

        try fixture.registry.revoke(DeviceRevocation(endpointID: fixture.clientRecord.endpointID, deviceName: "iPhone"))
        try await service.applyRevocations()
        _ = await recorder.first { $0 == .denied(hostName: "Studio") }
        #expect(revocations.value == 1)
        #expect(try fixture.approvals.decision(for: fixture.clientRecord.endpointID) == .denied)

        try fixture.registry.unrevoke(endpointID: fixture.clientRecord.endpointID)
        try fixture.registry.publish(fixture.clientRecord)
        let retried = StateRecorder()
        let retry = await fixture.startLink(recorder: retried)
        _ = await retried.first { $0 == .denied(hostName: "Studio") }

        await retry.stop()
        await fixture.tearDown(link: link, host: host)
    }

    /// A revoked device that connects is denied, and the host records the
    /// denial then, even if ``RemoteHostService/applyRevocations()`` hasn't
    /// run since the revocation.
    @Test func revokedDeviceIsDeniedOnArrival() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        try fixture.registry.revoke(DeviceRevocation(endpointID: fixture.clientRecord.endpointID, deviceName: "iPhone"))
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)

        _ = await recorder.first { $0 == .denied(hostName: "Studio") }
        #expect(try fixture.approvals.decision(for: fixture.clientRecord.endpointID) == .denied)

        await fixture.tearDown(link: link, host: host)
    }

    /// One device can hold only one handshake waiting on the host's user:
    /// each new hello from it closes its earlier waiting tunnel, so it
    /// can't fill the slots that other devices need.
    @Test func oneDeviceHoldsOneWaitingHandshake() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.registry.publish(fixture.clientRecord)
        let prompts = LockedCounter()
        let host = fixture.startHost(prompts: prompts) { _ in
            try? await Task.sleep(for: .seconds(30))
            return nil
        }

        func waitForApproval() async throws -> any TunnelConnection {
            let connection = try await fixture.clientNode.connect(to: fixture.hostRecord, allowingRelay: false)
            let control = try await connection.openStream()
            try await FrameCodec.write(ClientHello(protocolVersion: DeviceRecord.currentProtocolVersion), to: control)
            #expect(try await FrameCodec.read(HostReply.self, from: control) == .pendingApproval(hostName: "Studio"))
            return connection
        }
        let first = try await waitForApproval()
        let second = try await waitForApproval()

        try await withTimeout(.seconds(5)) { await first.waitUntilClosed() }
        #expect(prompts.value == 1)

        second.close(reason: "done")
        await fixture.clientNode.close()
        await fixture.hostNode.close()
        await host.value
        fixture.apiServer.stop()
    }

    /// The local server can tell which device a tunneled connection
    /// carries from the connection's source port, and that a connection
    /// some other local process made carries none.
    @Test func localServerCanAttributeTunneledConnections() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let seen = Locked<[String?]>([])
        let serviceBox = Locked<RemoteHostService?>(nil)
        let server = try LoopbackListener(onConnection: { connection in
            seen.value.append(connection.remotePort.flatMap { serviceBox.value?.tunneledDevice(fromLocalPort: $0) })
            Task { await echoUntilFinished(connection) }
        }, onFailure: { _ in })
        let serverPort = try await server.start()
        let service = RemoteHostService(node: fixture.hostNode, environment: RemoteHostService.Environment(
            registry: fixture.registry,
            approvals: fixture.approvals,
            hostName: { "Studio" },
            localPort: { serverPort },
            token: { _ in "token" },
            revokeToken: { _ in },
            requestApproval: { _ in .approved },
            isAcceptingConnections: { true },
            connectionsChanged: { _ in }
        ))
        serviceBox.value = service
        let host = Task { await service.run() }
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder)
        let port = try #require(await recorder.first { $0.connectedPort != nil }.connectedPort)

        #expect(try await echo("tunneled", throughPort: port) == "tunneled")
        #expect(try await echo("local", throughPort: serverPort) == "local")

        #expect(seen.value == [fixture.clientRecord.endpointID, nil])
        server.stop()
        await fixture.tearDown(link: link, host: host)
    }
}

@Suite(.timeLimit(.minutes(1)))
struct DiscoveryTests {
    /// A route to the host's loopback listener, as discovery might report one.
    private func route(to fixture: TunnelFixture) throws -> NWEndpoint {
        let port = try #require(fixture.hostNode.listeningPort.flatMap(NWEndpoint.Port.init(rawValue:)))
        return .hostPort(host: .ipv4(.loopback), port: port)
    }

    /// An advertisement for `route` as the host with `gateKey` publishes one.
    private func advertisement(at route: NWEndpoint, gateKey: Data) -> Advertisement {
        let salt = AccessGate.randomBytes(AccessGate.advertisementSaltLength)
        return Advertisement(endpoint: route, salt: salt, tag: AccessGate.advertisementTag(gateKey: gateKey, salt: salt))
    }

    /// A host found on the local network is dialed at the route discovery
    /// found, even when its registry record lists no address — or only
    /// stale ones — because iCloud Keychain hasn't caught up.
    @Test func discoveredRouteIsDialedWithoutRegistryAddresses() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        var stale = fixture.hostRecord
        stale.directAddresses = ["192.0.2.1:9"]

        let gateKey = try #require(fixture.hostRecord.gateKey)
        fixture.clientNode.discovered([advertisement(at: try route(to: fixture), gateKey: gateKey)])
        let connection = try await fixture.clientNode.connect(to: stale, allowingRelay: false)

        #expect(connection.remoteEndpointID == fixture.hostRecord.endpointID)
        connection.close(reason: "done")
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// Subscribers hear which known hosts gained or changed routes, so
    /// their links can redial at once, and hear nothing when nothing
    /// changed or the advertisement belongs to no host they know.
    @Test func newRoutesAreReported() async throws {
        let fixture = try await TunnelFixture.make()
        let reported = Mutex<[Set<String>]>([])
        fixture.clientNode.onRoutesChange { ids in reported.withLock { $0.append(ids) } }
        fixture.clientNode.remember(host: fixture.hostRecord)
        let gateKey = try #require(fixture.hostRecord.gateKey)
        let ours = advertisement(at: try route(to: fixture), gateKey: gateKey)
        let stranger = advertisement(at: try route(to: fixture), gateKey: AccessGate.randomBytes(32))

        fixture.clientNode.discovered([ours, stranger])
        fixture.clientNode.discovered([ours, stranger])
        fixture.clientNode.discovered([stranger])

        #expect(reported.withLock { $0 } == [[fixture.hostRecord.endpointID]])
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// A host advertising over Bonjour is reached end to end with no
    /// address in its registry record at all.
    @Test func hostFoundOverBonjourIsReached() async throws {
        let fixture = try await TunnelFixture.make(discovery: true)
        try fixture.approveClient()
        let host = fixture.startHost()
        var unpublished = fixture.hostRecord
        unpublished.directAddresses = []
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder, host: unpublished)
        fixture.clientNode.onRoutesChange { _ in Task { await link.routesChanged() } }

        let state = try await withTimeout(.seconds(10)) { await recorder.first { $0.connectedPort != nil } }
        #expect(try await echo("bonjour", throughPort: try #require(state.connectedPort)) == "bonjour")

        await fixture.tearDown(link: link, host: host)
    }

    /// An advertisement names its host only to a device that knows the
    /// host's gate key: it carries a fresh salt and a tag, never the
    /// endpoint ID, and two advertisements from one host share nothing.
    /// Malformed advertisements are ignored, and so is this device's own.
    @Test func advertisementsAreBlinded() throws {
        let ownKey = AccessGate.randomBytes(32)
        let hostKey = AccessGate.randomBytes(32)
        let endpoint = NWEndpoint.service(name: "x", type: "_example._tcp", domain: "local.", interface: nil)
        func txt(_ service: NWListener.Service) throws -> NWTXTRecord {
            try #require(service.txtRecordObject)
        }
        let first = NWListener.Service.tunnel(serviceType: "_example._tcp", gateKey: hostKey)
        let second = NWListener.Service.tunnel(serviceType: "_example._tcp", gateKey: hostKey)

        #expect(first.name != second.name)
        #expect(try txt(first)[ServiceBrowser.saltKey] != txt(second)[ServiceBrowser.saltKey])
        #expect(try txt(first)[ServiceBrowser.tagKey] != txt(second)[ServiceBrowser.tagKey])

        let found = ServiceBrowser.advertisements(
            from: [
                (endpoint, try txt(first)),
                (endpoint, try txt(NWListener.Service.tunnel(serviceType: "_example._tcp", gateKey: ownKey))),
                (endpoint, NWTXTRecord(["s": "zz", "t": "zz"])),
                (endpoint, NWTXTRecord(["id": String(repeating: "b", count: 64)])),
            ],
            excludingGateKey: ownKey
        )

        #expect(found.count == 1)
        #expect(found.first?.isAdvertised(byGateKey: hostKey) == true)
        #expect(found.first?.isAdvertised(byGateKey: AccessGate.randomBytes(32)) == false)
    }
}

/// The exchange in front of SSH that keeps everyone off the account away
/// from a host's SSH server.
@Suite(.timeLimit(.minutes(1)))
struct AccessGateTests {
    /// Reads the host's challenge from a raw connection to its port.
    private func challenge(from stream: TCPStream) async throws -> Data {
        try await stream.readExactly(AccessGate.challengeLength)
    }

    /// Anyone who connects to a host learns nothing that identifies it: the
    /// host's challenge carries neither its endpoint ID nor an SSH banner,
    /// and a wrong answer gets the connection closed without SSH starting.
    @Test func hostRevealsNothingToStrangers() async throws {
        let fixture = try await TunnelFixture.make()
        let port = try #require(fixture.hostNode.listeningPort)
        let stream = try await TCPStream.connectToLoopback(port: port)

        let received = try await challenge(from: stream)
        #expect(received.starts(with: AccessGate.magic))
        let hostKey = try #require(Data(hexEncoded: fixture.hostRecord.endpointID))
        #expect(received.range(of: hostKey) == nil)

        try await stream.write(AccessGate.randomBytes(AccessGate.proofLength))
        let after = try await withTimeout(.seconds(5)) { try await readToEnd(stream) }
        #expect(after.isEmpty)

        await stream.abort()
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// A connection that never answers the challenge is closed after the
    /// gate's timeout instead of holding a slot.
    @Test func silentConnectionIsClosed() async throws {
        let fixture = try await TunnelFixture.make()
        let port = try #require(fixture.hostNode.listeningPort)
        let stream = try await TCPStream.connectToLoopback(port: port)
        _ = try await challenge(from: stream)

        let rest = try await withTimeout(.seconds(10)) { try await readToEnd(stream) }
        #expect(rest.isEmpty)

        await stream.abort()
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// A client that knows the host's gate key passes and reaches SSH: the
    /// host answers a correct proof with its SSH banner.
    @Test func correctProofReachesSSH() async throws {
        let fixture = try await TunnelFixture.make()
        let port = try #require(fixture.hostNode.listeningPort)
        let stream = try await TCPStream.connectToLoopback(port: port)
        let received = try await challenge(from: stream)
        let nonce = received.dropFirst(AccessGate.magic.count).prefix(AccessGate.nonceLength)
        let gateKey = try #require(fixture.hostRecord.gateKey)

        try await stream.write(AccessGate.clientProof(gateKey: gateKey, nonce: Data(nonce)))
        let banner = try await withTimeout(.seconds(5)) { try await stream.readExactly(4) }
        #expect(banner == Data("SSH-".utf8))

        await stream.abort()
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// A device on the account that copies a real host's gate key into a
    /// record under its own key still fails: the gate passes, but SSH finds
    /// the real host's key where the record names another.
    @Test func copiedGateKeyStillFailsTheHostKeyCheck() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        var forged = makeRecord(
            endpointID: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.hexEncoded,
            gateKey: fixture.hostRecord.gateKey,
            canHost: true
        )
        forged.directAddresses = fixture.hostRecord.directAddresses

        await #expect(throws: RemoteAccessError.hostKeyMismatch) {
            _ = try await fixture.clientNode.connect(to: forged, allowingRelay: false)
        }

        await fixture.clientNode.close()
        await fixture.hostNode.close()
        await host.value
        fixture.apiServer.stop()
    }

    /// The limiter keeps each source to its share of waiting connections,
    /// closing its oldest to make way, and counts an IPv6 /64 as one source.
    @Test func limiterBoundsEachSource() throws {
        let a = try SocketAddress(ipAddress: "2001:db8:1:2::1", port: 1)
        let b = try SocketAddress(ipAddress: "2001:db8:1:2::ffff", port: 2)
        let c = try SocketAddress(ipAddress: "2001:db8:1:3::1", port: 3)
        #expect(AccessGateLimiter.source(of: a) == AccessGateLimiter.source(of: b))
        #expect(AccessGateLimiter.source(of: a) != AccessGateLimiter.source(of: c))
        #expect(AccessGateLimiter.source(of: try SocketAddress(ipAddress: "10.0.0.1", port: 1)) == "v4:10.0.0.1")

        let limiter = AccessGateLimiter()
        let channels = (0..<(AccessGateLimiter.maxPerSource + 2)).map { _ in EmbeddedChannel() }
        for channel in channels {
            try channel.connect(to: a).wait()
            limiter.admit(channel)
        }

        #expect(limiter.count() == AccessGateLimiter.maxPerSource)
        #expect(!channels[0].isActive)
        #expect(!channels[1].isActive)
        #expect(channels.last?.isActive == true)
    }

    /// A real connection to the host's listener counts against its own
    /// address while it waits, and stops counting once it closes.
    @Test func waitingConnectionCountsAgainstItsAddress() async throws {
        let fixture = try await TunnelFixture.make()
        let port = try #require(fixture.hostNode.listeningPort)
        let limiter = fixture.hostNode.gateLimiter
        let loopback = AccessGateLimiter.source(of: try SocketAddress(ipAddress: "127.0.0.1", port: 0))
        let stream = try await TCPStream.connectToLoopback(port: port)
        _ = try await challenge(from: stream)

        #expect(limiter.count(from: loopback) == 1)
        #expect(limiter.count(from: "unknown") == 0)

        await stream.abort()
        try await waitUntil { limiter.count() == 0 }
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }
}
