import Foundation
import Network
import NIOCore
import NIOEmbedded
import NIOTransportServices
import Testing
@testable import DeviceTunnel

struct ByteStreamHandlerTests {
    /// A channel with a ``ByteStreamHandler`` installed.
    private func makeChannel() throws -> (EmbeddedChannel, ByteStreamHandler) {
        let channel = EmbeddedChannel()
        let handler = ByteStreamHandler()
        try channel.pipeline.syncOperations.addHandler(handler)
        return (channel, handler)
    }

    /// Starts a read and returns a closure reporting its result once it has one.
    private func startRead(on channel: EmbeddedChannel, handler: ByteStreamHandler) -> () -> Result<ByteBuffer, any Error>? {
        let promise = channel.eventLoop.makePromise(of: ByteBuffer.self)
        nonisolated(unsafe) var result: Result<ByteBuffer, any Error>?
        promise.futureResult.whenComplete { result = $0 }
        handler.read(upTo: 16, promise: promise)
        return { result }
    }

    /// Bytes that arrived before the channel closed are read out before
    /// the end of stream is reported.
    @Test func bufferedBytesAreReadBeforeTheEnd() throws {
        let (channel, handler) = try makeChannel()
        let first = startRead(on: channel, handler: handler)
        channel.pipeline.fireChannelRead(ByteBuffer(string: "first"))
        channel.pipeline.fireChannelRead(ByteBuffer(string: "second"))
        channel.pipeline.fireChannelInactive()
        #expect(try #require(first()).get() == ByteBuffer(string: "first"))

        let second = startRead(on: channel, handler: handler)
        #expect(try #require(second()).get() == ByteBuffer(string: "second"))

        let third = startRead(on: channel, handler: handler)
        #expect(try #require(third()).get().readableBytes == 0)
    }

    /// An error after the peer's end of stream — NIOSSH raises one when
    /// this side then finishes — doesn't turn that end of stream into a
    /// failed read: every byte the peer sent has already arrived.
    @Test func errorAfterEndOfInputStillReadsAsTheEnd() throws {
        let (channel, handler) = try makeChannel()
        channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
        channel.pipeline.fireErrorCaught(RemoteAccessError.protocolViolation("late"))

        let read = startRead(on: channel, handler: handler)
        #expect(try #require(read()).get().readableBytes == 0)
    }

    /// An error before the end of input fails the read.
    @Test func errorBeforeEndOfInputFailsTheRead() throws {
        let (channel, handler) = try makeChannel()
        channel.pipeline.fireErrorCaught(RemoteAccessError.protocolViolation("broken"))

        let read = startRead(on: channel, handler: handler)
        #expect(throws: RemoteAccessError.protocolViolation("broken")) { try #require(read()).get() }
    }
}

struct PathWatcherTests {
    private func makeChannel(active: Bool = true) throws -> (EmbeddedChannel, DialDiagnosis) {
        let channel = EmbeddedChannel()
        let diagnosis = DialDiagnosis()
        try channel.pipeline.syncOperations.addHandler(PathWatcher(diagnosis: diagnosis, unsatisfiedReason: { _ in nil }))
        if active {
            try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait()
        }
        return (channel, diagnosis)
    }

    /// A tunnel told a better path exists — Wi-Fi joined while it runs over
    /// cellular, or Ethernet while it runs over Wi-Fi — closes, so the link
    /// redials over the better path.
    @Test func betterPathClosesTheTunnel() throws {
        let (channel, _) = try makeChannel()
        channel.pipeline.fireUserInboundEventTriggered(NIOTSNetworkEvents.BetterPathAvailable())
        #expect(!channel.isActive)
    }

    /// A tunnel whose path stops being viable gets a grace period to
    /// recover — a Wi-Fi blip or roaming between access points — and closes
    /// only if it doesn't.
    @Test func unviablePathClosesTheTunnelAfterAGracePeriod() throws {
        let (channel, _) = try makeChannel()
        channel.pipeline.fireUserInboundEventTriggered(NIOTSNetworkEvents.ViabilityUpdate(isViable: false))
        channel.embeddedEventLoop.advanceTime(by: PathWatcher.unviableGrace - .seconds(1))
        #expect(channel.isActive)

        channel.embeddedEventLoop.advanceTime(by: .seconds(1))
        #expect(!channel.isActive)
    }

    /// A path that recovers within the grace period keeps the tunnel.
    @Test func pathThatRecoversKeepsTheTunnel() throws {
        let (channel, _) = try makeChannel()
        channel.pipeline.fireUserInboundEventTriggered(NIOTSNetworkEvents.ViabilityUpdate(isViable: false))
        channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        channel.pipeline.fireUserInboundEventTriggered(NIOTSNetworkEvents.ViabilityUpdate(isViable: true))
        channel.embeddedEventLoop.advanceTime(by: PathWatcher.unviableGrace * 2)
        #expect(channel.isActive)
        try channel.close().wait()
    }

    /// A dial that has to wait for connectivity — refused, no route, or
    /// blocked by Local Network privacy — fails at once with the reason,
    /// instead of sitting out the connect timeout and reporting that.
    @Test func dialWaitingForConnectivityFailsFastWithTheReason() throws {
        let (channel, diagnosis) = try makeChannel(active: false)
        channel.pipeline.fireUserInboundEventTriggered(
            NIOTSNetworkEvents.WaitingForConnectivity(transientError: .posix(.ECONNREFUSED))
        )
        #expect(throws: ChannelError.alreadyClosed) { try channel.close().wait() }
        #expect(diagnosis.error as? NWError == .posix(.ECONNREFUSED))
    }

    /// Path events that arrive while a dial is still connecting don't
    /// close it; only an established tunnel reacts to them.
    @Test func pathEventsDuringTheDialAreIgnored() throws {
        let (channel, _) = try makeChannel(active: false)
        channel.pipeline.fireUserInboundEventTriggered(NIOTSNetworkEvents.BetterPathAvailable())
        channel.pipeline.fireUserInboundEventTriggered(NIOTSNetworkEvents.ViabilityUpdate(isViable: false))
        channel.embeddedEventLoop.advanceTime(by: PathWatcher.unviableGrace * 2)
        #expect(throws: Never.self) { try channel.close().wait() }
    }
}

struct DialFailureTests {
    /// A dial Local Network privacy blocked is reported as such, whether
    /// the path says so or Bonjour resolution was refused by policy.
    @Test func localNetworkDenialIsRecognized() {
        #expect(dialFailure(waitingOn: .posix(.ENETUNREACH), unsatisfiedReason: .localNetworkDenied) as? RemoteAccessError == .localNetworkDenied)
        #expect(dialFailure(waitingOn: .dns(DNSServiceErrorType(kDNSServiceErr_PolicyDenied)), unsatisfiedReason: nil) as? RemoteAccessError == .localNetworkDenied)
    }

    /// Any other reason to wait is passed on unchanged.
    @Test func otherReasonsPassThrough() {
        #expect(dialFailure(waitingOn: .posix(.ECONNREFUSED), unsatisfiedReason: nil) as? NWError == .posix(.ECONNREFUSED))
        #expect(dialFailure(waitingOn: .posix(.ENETDOWN), unsatisfiedReason: .notAvailable) as? NWError == .posix(.ENETDOWN))
    }
}
