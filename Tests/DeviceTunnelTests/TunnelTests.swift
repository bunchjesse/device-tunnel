import CryptoKit
import Foundation
import Network
import NIOCore
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
            name: "Studio",
            platform: .macOS,
            canHost: true,
            directAddresses: hostNode.address()
        )
        let clientRecord = makeRecord(endpointID: clientIdentity.endpointID, name: "iPhone")

        return TunnelFixture(
            configuration: configuration,
            hostStore: hostStore,
            hostNode: hostNode,
            clientNode: clientNode,
            hostRecord: hostRecord,
            clientRecord: clientRecord,
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
    /// recording its states.
    func startLink(recorder: StateRecorder, host: DeviceRecord? = nil) async -> RemoteHostLink {
        let link = RemoteHostLink(node: clientNode, host: host ?? hostRecord) { state in
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

    /// A server answering at the host's address with a key other than the
    /// one the registry lists is never trusted: the client stays
    /// unreachable instead of sending its hello to an impostor.
    @Test func hostWithTheWrongKeyIsRejected() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        let host = fixture.startHost()
        let impostor = DeviceRecord(
            endpointID: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.hexEncoded,
            name: "Studio",
            platform: .macOS,
            canHost: true,
            directAddresses: fixture.hostRecord.directAddresses
        )
        let recorder = StateRecorder()
        let link = await fixture.startLink(recorder: recorder, host: impostor)

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

    /// Connections that never finish the SSH handshake — anything on the
    /// network can open them — can't fill the host's handshake slots and
    /// lock out a registered device: the oldest of them makes way.
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
}

@Suite(.timeLimit(.minutes(1)))
struct DiscoveryTests {
    /// A route to the host's loopback listener, as discovery might report one.
    private func route(to fixture: TunnelFixture) throws -> NWEndpoint {
        let port = try #require(fixture.hostNode.listeningPort.flatMap(NWEndpoint.Port.init(rawValue:)))
        return .hostPort(host: .ipv4(.loopback), port: port)
    }

    /// A host found on the local network is dialed at the route discovery
    /// found, even when its registry record lists no address — or only
    /// stale ones — because iCloud Keychain hasn't caught up.
    @Test func discoveredRouteIsDialedWithoutRegistryAddresses() async throws {
        let fixture = try await TunnelFixture.make()
        try fixture.approveClient()
        var stale = fixture.hostRecord
        stale.directAddresses = ["192.0.2.1:9"]

        fixture.clientNode.discovered([fixture.hostRecord.endpointID: [try route(to: fixture)]])
        let connection = try await fixture.clientNode.connect(to: stale, allowingRelay: false)

        #expect(connection.remoteEndpointID == fixture.hostRecord.endpointID)
        connection.close(reason: "done")
        await fixture.clientNode.close()
        await fixture.hostNode.close()
    }

    /// Subscribers hear which hosts gained or changed routes, so their
    /// links can redial at once, and hear nothing when nothing changed.
    @Test func newRoutesAreReported() async throws {
        let fixture = try await TunnelFixture.make()
        let reported = Mutex<[Set<String>]>([])
        fixture.clientNode.onRoutesChange { ids in reported.withLock { $0.append(ids) } }
        let routes = [fixture.hostRecord.endpointID: [try route(to: fixture)]]

        fixture.clientNode.discovered(routes)
        fixture.clientNode.discovered(routes)
        fixture.clientNode.discovered([:])

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

    /// A browse result carries the host's endpoint ID in its TXT record;
    /// results without a well-formed one are ignored, and so is this
    /// device's own advertisement.
    @Test func browseResultsAreKeyedByEndpointID() {
        let ownID = String(repeating: "a", count: 64)
        let hostID = String(repeating: "b", count: 64)
        let endpoint = NWEndpoint.service(name: "Studio", type: "_example._tcp", domain: "local.", interface: nil)

        let routes = ServiceBrowser.routes(
            from: [
                (endpoint, NWTXTRecord(["id": hostID])),
                (endpoint, NWTXTRecord(["id": ownID])),
                (endpoint, NWTXTRecord(["id": "not-a-key"])),
                (endpoint, NWTXTRecord([:])),
            ],
            excluding: ownID
        )

        #expect(routes == [hostID: [endpoint]])
    }
}
