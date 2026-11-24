import Foundation
import Testing
@testable import DeviceTunnel

struct FrameCodecTests {
    /// Every host reply survives a write/read round trip over a stream.
    @Test(arguments: [
        HostReply.approved(token: "t0k3n", hostName: "Studio"),
        .pendingApproval(hostName: "Studio"),
        .denied(hostName: "Studio"),
        .unknownDevice,
        .unsupportedProtocol(minimumVersion: 2),
        .unavailable(reason: "Starting"),
    ])
    func hostRepliesRoundTrip(reply: HostReply) async throws {
        let (writer, reader) = MemoryByteStream.pipe()
        try await FrameCodec.write(reply, to: writer)
        #expect(try await FrameCodec.read(HostReply.self, from: reader) == reply)
    }

    /// Consecutive frames on one stream are read back one at a time, which is
    /// how a pending approval is followed by its final answer.
    @Test func consecutiveFramesAreReadInOrder() async throws {
        let (writer, reader) = MemoryByteStream.pipe()
        try await FrameCodec.write(HostReply.pendingApproval(hostName: "Studio"), to: writer)
        try await FrameCodec.write(HostReply.denied(hostName: "Studio"), to: writer)

        #expect(try await FrameCodec.read(HostReply.self, from: reader) == .pendingApproval(hostName: "Studio"))
        #expect(try await FrameCodec.read(HostReply.self, from: reader) == .denied(hostName: "Studio"))
    }

    /// A length header larger than the frame limit is rejected before the
    /// reader tries to buffer the payload.
    @Test func oversizedFrameIsRejected() async throws {
        let (writer, reader) = MemoryByteStream.pipe()
        try await writer.write(Data([0x7F, 0xFF, 0xFF, 0xFF]))

        await #expect(throws: RemoteAccessError.self) {
            _ = try await FrameCodec.read(HostReply.self, from: reader)
        }
    }

    /// A peer that finishes mid-frame produces an end-of-stream error rather
    /// than a partial message.
    @Test func truncatedFrameFails() async throws {
        let (writer, reader) = MemoryByteStream.pipe()
        try await writer.write(Data([0, 0, 0, 10, 1, 2]))
        try await writer.finish()

        await #expect(throws: RemoteAccessError.unexpectedEndOfStream) {
            _ = try await FrameCodec.read(HostReply.self, from: reader)
        }
    }
}

struct StreamSpliceTests {
    /// Bytes flow both ways through a splice, and each side's half-close
    /// reaches the other end, as an HTTP exchange over a tunnel needs.
    @Test func copiesBothDirectionsAndForwardsHalfClose() async throws {
        let (clientEnd, spliceLeft) = MemoryByteStream.pipe()
        let (spliceRight, serverEnd) = MemoryByteStream.pipe()
        let splice = Task { await StreamSplice.run(spliceLeft, spliceRight) }

        try await clientEnd.write(Data("request".utf8))
        try await clientEnd.finish()
        #expect(try await readToEnd(serverEnd) == Data("request".utf8))

        try await serverEnd.write(Data("response".utf8))
        try await serverEnd.finish()
        #expect(try await readToEnd(clientEnd) == Data("response".utf8))

        await splice.value
    }

    /// When one side fails, the splice tears down the other side too instead
    /// of leaving it waiting forever.
    @Test func failureAbortsBothSides() async throws {
        let (clientEnd, spliceLeft) = MemoryByteStream.pipe()
        let (spliceRight, serverEnd) = MemoryByteStream.pipe()
        let splice = Task { await StreamSplice.run(spliceLeft, spliceRight) }

        await clientEnd.abort()
        await splice.value

        await #expect(throws: RemoteAccessError.self) {
            _ = try await serverEnd.read(upTo: 16)
        }
    }
}

struct LoopbackTCPTests {
    /// Tunnel connections notice a dead peer within about half a minute
    /// whether they're idle (keepalives) or waiting on unacknowledged data —
    /// which is the usual case with SSE heartbeats flowing — where
    /// keepalives never fire and TCP would otherwise retransmit for minutes.
    @Test func tunnelConnectionsDropUnresponsivePeers() {
        let options = TunnelSocket.tcpOptions
        #expect(options.enableKeepalive)
        #expect(options.keepaliveIdle + options.keepaliveInterval * options.keepaliveCount <= 30)
        #expect(options.connectionDropTime == 30)
        #expect(options.noDelay)
    }

    /// The loopback legs on either end of a tunnel send small writes
    /// immediately, so Nagle's algorithm can't hold an HTTP request's body
    /// back until the peer's delayed acknowledgment of its headers.
    @Test func loopbackConnectionsDisableNagle() {
        #expect(TunnelSocket.loopbackTCPOptions.noDelay)
    }

    /// A connection to the loopback listener round-trips bytes, and a
    /// half-close from the client arrives at the server as end of stream.
    @Test(.timeLimit(.minutes(1)))
    func loopbackListenerAcceptsAndEchoes() async throws {
        let listener = try LoopbackListener(onConnection: { connection in
            Task { await echoUntilFinished(connection) }
        }, onFailure: { _ in })
        defer { listener.stop() }
        let port = try await listener.start()
        #expect(port > 0)

        let client = try await TCPStream.connectToLoopback(port: port)
        try await client.write(Data("hello".utf8))
        try await client.finish()

        #expect(try await readToEnd(client) == Data("hello".utf8))
        await client.close()
    }

    /// Connecting to a loopback port nobody listens on fails promptly
    /// instead of waiting for the connection to become viable.
    @Test(.timeLimit(.minutes(1)))
    func connectingToClosedPortFails() async throws {
        let listener = try LoopbackListener(onConnection: { _ in }, onFailure: { _ in })
        let port = try await listener.start()
        listener.stop()
        try await Task.sleep(for: .milliseconds(200))

        await #expect(throws: (any Error).self) {
            _ = try await TCPStream.connectToLoopback(port: port, timeout: .seconds(3))
        }
    }
}

struct FirstSuccessTests {
    private typealias Attempt = @Sendable () async throws -> Int

    private static func failing(_ error: RemoteAccessError) -> Attempt {
        { throw error }
    }

    /// The first attempt to succeed wins even when an attempt ahead of it
    /// in preference order is still running.
    @Test func firstSuccessWins() async throws {
        let slow: Attempt = {
            try await Task.sleep(for: .seconds(5))
            return 1
        }
        let fast: Attempt = { 2 }
        let value = try await firstSuccess(of: [slow, fast], discard: { _ in })
        #expect(value == 2)
    }

    /// When every attempt fails, `hostKeyMismatch` wins over other errors:
    /// a path that reached the wrong peer explains more than addresses that
    /// didn't answer. Without one, the first attempt's error is reported.
    @Test func hostKeyMismatchWinsWhenAllFail() async {
        await #expect(throws: RemoteAccessError.hostKeyMismatch) {
            try await firstSuccess(
                of: [Self.failing(.timedOut), Self.failing(.hostKeyMismatch)],
                discard: { _ in }
            )
        }
        await #expect(throws: RemoteAccessError.timedOut) {
            try await firstSuccess(
                of: [Self.failing(.timedOut), Self.failing(.noRoute)],
                discard: { _ in }
            )
        }
    }

    /// A path that reached the right host and was told it doesn't
    /// recognize this device explains the failure better than any other:
    /// `notRecognized` outranks `hostKeyMismatch` and timeouts.
    @Test func notRecognizedWinsWhenAllFail() async {
        await #expect(throws: RemoteAccessError.notRecognized) {
            try await firstSuccess(
                of: [Self.failing(.timedOut), Self.failing(.hostKeyMismatch), Self.failing(.notRecognized)],
                discard: { _ in }
            )
        }
    }

    /// Local Network privacy blocking a path is the one failure only the
    /// user can fix, so it outranks paths that reached the wrong device or
    /// didn't answer.
    @Test func localNetworkDenialOutranksPathsThatDidntAnswer() async {
        await #expect(throws: RemoteAccessError.localNetworkDenied) {
            try await firstSuccess(
                of: [Self.failing(.timedOut), Self.failing(.hostKeyMismatch), Self.failing(.localNetworkDenied)],
                discard: { _ in }
            )
        }
    }

    /// A caller that is already cancelled gets `CancellationError` at once
    /// instead of waiting on attempts that ignore cancellation, as dials
    /// waiting on SwiftNIO futures do.
    @Test func cancelledCallerDoesNotWaitForAttempts() async {
        let slow: Attempt = {
            await uncancellableSleep(seconds: 3)
            return 1
        }
        let started = ContinuousClock.now
        let outcome = await runCancelled { try await firstSuccess(of: [slow, slow], discard: { _ in }) }
        #expect(throws: CancellationError.self) { try outcome.get() }
        #expect(ContinuousClock.now - started < .seconds(1))
    }
}

struct TimeoutTests {
    /// A caller that is already cancelled gets `CancellationError` at once
    /// instead of waiting out an operation that ignores cancellation.
    @Test func cancelledCallerDoesNotWaitForTheOperation() async {
        let started = ContinuousClock.now
        let outcome = await runCancelled {
            try await withTimeout(.seconds(30)) { await uncancellableSleep(seconds: 3) }
        }
        #expect(throws: CancellationError.self) { try outcome.get() }
        #expect(ContinuousClock.now - started < .seconds(1))
    }

    /// An operation that outlives its deadline fails with `timedOut` even
    /// though it ignores the cancellation it's sent.
    @Test func deadlinePassesEvenWhenTheOperationIgnoresCancellation() async {
        let started = ContinuousClock.now
        await #expect(throws: RemoteAccessError.timedOut) {
            try await withTimeout(.milliseconds(100)) { await uncancellableSleep(seconds: 3) }
        }
        #expect(ContinuousClock.now - started < .seconds(1))
    }

    /// A result that arrives after the deadline goes to `discard`, so a
    /// connection dialed too late is closed instead of left open.
    @Test func lateResultIsDiscarded() async throws {
        let discarded = LockedCounter()
        await #expect(throws: RemoteAccessError.timedOut) {
            try await withTimeout(.milliseconds(50), discardingLateResult: { _ in discarded.increment() }) {
                await uncancellableSleep(seconds: 0.2)
                return 1
            }
        }
        try await Task.sleep(for: .milliseconds(400))
        #expect(discarded.value == 1)
    }
}

struct AsyncInboxTests {
    /// A consumer whose task is cancelled while it waits — as `withTimeout`
    /// does to a wait it abandons — returns nil, and the element pushed
    /// afterwards goes to the next consumer instead of vanishing into the
    /// abandoned wait.
    @Test func cancelledWaiterDoesNotSwallowTheNextElement() async throws {
        let inbox = AsyncInbox<Int>()
        let abandoned = Task { await inbox.next() }
        try await Task.sleep(for: .milliseconds(50))
        abandoned.cancel()
        #expect(try await withTimeout(.seconds(2)) { await abandoned.value } == nil)

        inbox.push(7)
        #expect(try await withTimeout(.seconds(2)) { await inbox.next() } == 7)
    }

    /// Elements come out in the order they went in, and a finished inbox
    /// still hands out what it holds before reporting the end.
    @Test func deliversInOrderThenEnds() async {
        let inbox = AsyncInbox<Int>()
        inbox.push(1)
        inbox.push(2)
        inbox.finish()
        #expect(!inbox.push(3))

        #expect(await inbox.next() == 1)
        #expect(await inbox.next() == 2)
        #expect(await inbox.next() == nil)
    }
}
