import Foundation
import Synchronization
import Testing
@testable import DeviceTunnel

/// An in-memory byte pipe direction, used to stand in for sockets in tests.
actor MemoryChannel {
    private var buffer = Data()
    private var isFinished = false
    private var isAborted = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func write(_ data: Data) throws {
        guard !isFinished, !isAborted else { throw RemoteAccessError.unexpectedEndOfStream }
        buffer.append(data)
        wakeReaders()
    }

    func finish() {
        isFinished = true
        wakeReaders()
    }

    func abort() {
        isAborted = true
        wakeReaders()
    }

    func read(upTo maxLength: Int) async throws -> Data {
        while buffer.isEmpty, !isFinished, !isAborted {
            await withCheckedContinuation { waiters.append($0) }
        }
        if isAborted { throw RemoteAccessError.unexpectedEndOfStream }
        let chunk = buffer.prefix(maxLength)
        buffer.removeFirst(chunk.count)
        return Data(chunk)
    }

    private func wakeReaders() {
        let pending = waiters
        waiters.removeAll()
        pending.forEach { $0.resume() }
    }
}

/// One end of an in-memory duplex pipe.
struct MemoryByteStream: ByteStream {
    let inbound: MemoryChannel
    let outbound: MemoryChannel

    /// Returns two connected ends.
    static func pipe() -> (MemoryByteStream, MemoryByteStream) {
        let aToB = MemoryChannel()
        let bToA = MemoryChannel()
        return (MemoryByteStream(inbound: bToA, outbound: aToB), MemoryByteStream(inbound: aToB, outbound: bToA))
    }

    func read(upTo maxLength: Int) async throws -> Data { try await inbound.read(upTo: maxLength) }
    func write(_ data: Data) async throws { try await outbound.write(data) }
    func finish() async throws { await outbound.finish() }
    func close() async {}
    func abort() async {
        await inbound.abort()
        await outbound.abort()
    }
}

/// Reads until the peer finishes, returning everything received.
func readToEnd(_ stream: some ByteStream) async throws -> Data {
    var received = Data()
    while true {
        let chunk = try await stream.read(upTo: 4096)
        if chunk.isEmpty { return received }
        received.append(chunk)
    }
}

/// Waits `seconds` whether or not the task is cancelled, the way a wait
/// on a SwiftNIO future does.
func uncancellableSleep(seconds: Double) async {
    await withCheckedContinuation { continuation in
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds) {
            continuation.resume()
        }
    }
}

/// Runs `body` in a task that is already cancelled when `body` starts.
func runCancelled<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) async -> Result<T, any Error> {
    await Task {
        withUnsafeCurrentTask { $0?.cancel() }
        do {
            return .success(try await body())
        } catch {
            return .failure(error)
        }
    }.value
}

/// Echoes each chunk `connection` receives as it arrives and finishes
/// once the peer does, standing in for the host's API server. Replying
/// before the peer finishes is what HTTP needs: a client waits for its
/// response with the connection still open.
func echoUntilFinished(_ connection: some ByteStream) async {
    do {
        while true {
            let chunk = try await connection.read(upTo: 65536)
            if chunk.isEmpty { break }
            try await connection.write(chunk)
        }
        try await connection.finish()
    } catch {
        await connection.abort()
    }
}

/// A configuration isolated to one test. With `discovery`, hosts advertise
/// and clients browse for a Bonjour service type no other test uses.
func makeConfiguration(discovery: Bool = false) -> RemoteAccessConfiguration {
    RemoteAccessConfiguration(
        keychainServicePrefix: "test.\(UUID().uuidString)",
        keychainAccessGroup: nil,
        protocolName: "device-tunnel-test/2",
        serviceType: discovery ? "_symt-\(UUID().uuidString.prefix(8).lowercased())._tcp" : nil
    )
}

/// A record for a device with `endpointID`.
func makeRecord(
    endpointID: String,
    name: String = "Test Device",
    platform: DevicePlatform = .iOS,
    canHost: Bool = false,
    directAddresses: [String] = [],
    relayAddress: String? = nil
) -> DeviceRecord {
    DeviceRecord(
        endpointID: endpointID,
        name: name,
        platform: platform,
        canHost: canHost,
        directAddresses: directAddresses,
        relayAddress: relayAddress
    )
}

/// Collects a link's state transitions so a test can wait for one.
actor StateRecorder {
    private(set) var states: [RemoteHostLink.State] = []
    private var waiters: [(predicate: @Sendable (RemoteHostLink.State) -> Bool, continuation: CheckedContinuation<RemoteHostLink.State, Never>)] = []

    func record(_ state: RemoteHostLink.State) {
        states.append(state)
        let matching = waiters.filter { $0.predicate(state) }
        waiters.removeAll { $0.predicate(state) }
        matching.forEach { $0.continuation.resume(returning: state) }
    }

    /// Waits for the first state (already seen or future) matching `predicate`.
    func first(where predicate: @escaping @Sendable (RemoteHostLink.State) -> Bool) async -> RemoteHostLink.State {
        if let seen = states.first(where: predicate) { return seen }
        return await withCheckedContinuation { waiters.append((predicate, $0)) }
    }
}

extension RemoteHostLink.State {
    /// The listener port of a connected state, or nil.
    var connectedPort: UInt16? {
        if case .connected(let port, _, _) = self { return port }
        return nil
    }

    /// The path of a connected state, or nil.
    var connectedPath: ConnectionPath? {
        if case .connected(_, _, let path) = self { return path }
        return nil
    }
}

/// A transport whose dials a test scripts: every `connect(to:allowingRelay:)`
/// is logged and answered by `dial`, which learns whether the relay was allowed.
final class ScriptedTransport: TunnelTransport {
    let dials = DialLog()
    /// Answers each dial, told whether the relay was allowed.
    private let dial: @Sendable (DeviceRecord, _ allowingRelay: Bool) async throws -> any TunnelConnection

    /// A transport that answers every dial with `dial`.
    init(dial: @escaping @Sendable (DeviceRecord) async throws -> any TunnelConnection) {
        self.dial = { record, _ in try await dial(record) }
    }

    /// A transport that answers every dial with `dial`, told whether the
    /// relay was allowed.
    init(dialAllowingRelay dial: @escaping @Sendable (DeviceRecord, _ allowingRelay: Bool) async throws -> any TunnelConnection) {
        self.dial = dial
    }

    func connect(to record: DeviceRecord, allowingRelay: Bool) async throws -> any TunnelConnection {
        await dials.append(record, allowingRelay: allowingRelay)
        return try await dial(record, allowingRelay)
    }

    func nextIncoming() async -> (any IncomingTunnel)? { nil }
}

/// The records a ``ScriptedTransport`` was asked to dial.
actor DialLog {
    private(set) var records: [DeviceRecord] = []
    /// Whether each dial in `records` allowed the relay.
    private(set) var allowedRelay: [Bool] = []
    private var waiters: [(count: Int, continuation: CheckedContinuation<Void, Never>)] = []

    func append(_ record: DeviceRecord, allowingRelay: Bool) {
        records.append(record)
        allowedRelay.append(allowingRelay)
        let ready = waiters.filter { $0.count <= records.count }
        waiters.removeAll { $0.count <= records.count }
        ready.forEach { $0.continuation.resume() }
    }

    /// Waits until at least `count` dials have happened.
    func waitForDials(_ count: Int) async {
        guard records.count < count else { return }
        await withCheckedContinuation { waiters.append((count, $0)) }
    }
}

/// A connection that does nothing but record whether it was closed.
final class FakeConnection: TunnelConnection {
    let remoteEndpointID = "fake"
    /// The path the connection claims to take.
    let path: ConnectionPath

    /// A connection taking `path`.
    init(path: ConnectionPath = .direct) {
        self.path = path
    }
    private let closed = Mutex<(isClosed: Bool, waiters: [CheckedContinuation<Void, Never>])>((false, []))

    var isClosed: Bool { closed.withLock { $0.isClosed } }

    func openStream() async throws -> any ByteStream { throw RemoteAccessError.unexpectedEndOfStream }
    func acceptStream() async throws -> any ByteStream { throw RemoteAccessError.unexpectedEndOfStream }

    func close(reason: String) {
        let waiters = closed.withLock { state -> [CheckedContinuation<Void, Never>] in
            state.isClosed = true
            defer { state.waiters = [] }
            return state.waiters
        }
        waiters.forEach { $0.resume() }
    }

    func waitUntilClosed() async {
        await withCheckedContinuation { continuation in
            let isClosed = closed.withLock { state -> Bool in
                if !state.isClosed { state.waiters.append(continuation) }
                return state.isClosed
            }
            if isClosed { continuation.resume() }
        }
    }
}

/// A one-shot signal a test raises to let a scripted dial proceed.
final class Gate: Sendable {
    private let stream: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation

    init() {
        (stream, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
    }

    func open() { continuation.yield() }

    func wait() async { _ = await stream.first { _ in true } }
}

/// A connection whose far end answers the link's hello with `reply`.
final class ReplyingConnection: TunnelConnection {
    let remoteEndpointID = "fake-host"
    /// The path the connection claims to take.
    let path: ConnectionPath
    private let reply: HostReply
    private let lifetime = FakeConnection()

    /// A connection taking `path` whose host answers with `reply`.
    init(reply: HostReply, path: ConnectionPath = .direct) {
        self.reply = reply
        self.path = path
    }

    /// Whether the link closed this connection.
    var isClosed: Bool { lifetime.isClosed }

    func openStream() async throws -> any ByteStream {
        let (linkEnd, hostEnd) = MemoryByteStream.pipe()
        let reply = reply
        Task {
            _ = try? await FrameCodec.read(ClientHello.self, from: hostEnd)
            try? await FrameCodec.write(reply, to: hostEnd)
            try? await hostEnd.finish()
        }
        return linkEnd
    }

    func acceptStream() async throws -> any ByteStream { throw RemoteAccessError.unexpectedEndOfStream }
    func close(reason: String) { lifetime.close(reason: reason) }
    func waitUntilClosed() async { await lifetime.waitUntilClosed() }
}

/// A value shared across tasks and closures in tests.
final class Locked<Value: Sendable>: Sendable {
    /// The value, behind a lock.
    private let storage: Mutex<Value>

    /// Creates a box holding `value`.
    init(_ value: Value) {
        storage = Mutex(value)
    }

    /// The current value.
    var value: Value {
        get { storage.withLock { $0 } }
        set { storage.withLock { $0 = newValue } }
    }
}

/// Waits until `condition` holds, failing after `timeout`.
func waitUntil(timeout: Duration = .seconds(5), _ condition: @Sendable () -> Bool) async throws {
    let deadline = ContinuousClock.now + timeout
    while !condition() {
        guard ContinuousClock.now < deadline else { throw RemoteAccessError.timedOut }
        try await Task.sleep(for: .milliseconds(20))
    }
}
