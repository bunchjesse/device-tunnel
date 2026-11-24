import Foundation
import NIOCore
import NIOSSH

/// ``ByteStream`` over an SSH channel through a tunnel, whose pipeline ends
/// in a ``ByteStreamHandler``.
///
/// Reads are demand-driven — the channel's `autoRead` is off and each
/// `read(upTo:)` asks for more only when nothing is buffered — so a slow
/// consumer holds back the peer through SSH's flow control.
final class ChannelByteStream: ByteStream {
    private let channel: any Channel
    private let handler: NIOLoopBound<ByteStreamHandler>

    private init(channel: any Channel, handler: ByteStreamHandler) {
        self.channel = channel
        self.handler = NIOLoopBound(handler, eventLoop: channel.eventLoop)
    }

    /// Adds SSH channel-data framing and a ``ByteStreamHandler`` to an SSH
    /// child channel. Must be called on the channel's event loop.
    static func installOnSSHChannel(_ channel: any Channel) throws -> ChannelByteStream {
        let handler = ByteStreamHandler()
        try channel.pipeline.syncOperations.addHandlers([SSHChannelDataCodec(), handler])
        return ChannelByteStream(channel: channel, handler: handler)
    }

    func read(upTo maxLength: Int) async throws -> Data {
        let promise = channel.eventLoop.makePromise(of: ByteBuffer.self)
        let handler = handler
        channel.eventLoop.execute {
            handler.value.read(upTo: maxLength, promise: promise)
        }
        let buffer = try await promise.futureResult.get()
        return Data(buffer.readableBytesView)
    }

    func write(_ data: Data) async throws {
        try await channel.writeAndFlush(channel.allocator.buffer(bytes: data)).get()
    }

    /// Half-closes the output. NIOSSH can't send `EOF` once the peer has sent
    /// one, so the side of a stream that finishes second closes it instead,
    /// and ``ByteStreamHandler`` reads that close as the end of input.
    func finish() async throws {
        do {
            try await channel.close(mode: .output).get()
        } catch let error as NIOSSHError where error.type == .protocolViolation {
            // NIOSSH (through at least 0.15) refuses to send `EOF` once the
            // peer has sent its own — `sendChannelEOF` has its half-closed
            // cases swapped — and closes the channel instead. Both
            // directions are done by then, so that close is the right end.
            await close()
        }
    }

    func close() async {
        try? await channel.close().get()
    }

    func abort() async {
        try? await channel.close().get()
    }
}

/// Buffers a channel's input for ``ChannelByteStream`` and hands it out on
/// request. Lives on the channel's event loop.
///
/// A close ends the input like an SSH `EOF` does, and an end of input is
/// reported ahead of any error that follows it. A bare close must not fail
/// reads: that would abort the second half of every normal stream.
final class ByteStreamHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private var buffered: ByteBuffer?
    private var inputEnded = false
    private var failure: (any Error)?
    private var pendingRead: (maxLength: Int, promise: EventLoopPromise<ByteBuffer>)?
    private var context: ChannelHandlerContext?

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        context.channel.setOption(ChannelOptions.autoRead, value: false).assumeIsolated().whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        pendingRead?.promise.fail(ChannelError.ioOnClosedChannel)
        pendingRead = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        if buffered == nil {
            buffered = incoming
        } else {
            buffered!.writeBuffer(&incoming)
        }
        fulfillPendingRead()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case ChannelEvent.inputClosed = event {
            inputEnded = true
            fulfillPendingRead()
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        // A close ends the input like an SSH `EOF` does: the side of a
        // stream that finishes second can only close (see
        // `ChannelByteStream.finish()`), so a close is how a normal stream
        // ends as often as an aborted one. A close that follows an error
        // leaves that error to be reported.
        if failure == nil {
            inputEnded = true
        }
        fulfillPendingRead()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        failure = failure ?? error
        fulfillPendingRead()
        context.close(promise: nil)
    }

    /// Completes `promise` with up to `maxLength` buffered bytes, an empty
    /// buffer at end of input, or the channel's error. An error that
    /// arrives after the end of input doesn't fail reads: every byte the
    /// peer sent has already arrived.
    func read(upTo maxLength: Int, promise: EventLoopPromise<ByteBuffer>) {
        guard pendingRead == nil else {
            promise.fail(RemoteAccessError.protocolViolation("concurrent reads"))
            return
        }
        pendingRead = (maxLength, promise)
        fulfillPendingRead()
        if pendingRead != nil {
            guard let context else {
                fulfill(with: .failure(ChannelError.ioOnClosedChannel))
                return
            }
            context.read()
        }
    }

    private func fulfillPendingRead() {
        guard let pending = pendingRead else { return }
        if var buffered, buffered.readableBytes > 0 {
            let chunk = buffered.readSlice(length: min(pending.maxLength, buffered.readableBytes))!
            self.buffered = buffered.readableBytes > 0 ? buffered : nil
            fulfill(with: .success(chunk))
        } else if inputEnded {
            fulfill(with: .success(ByteBuffer()))
        } else if let failure {
            fulfill(with: .failure(failure))
        }
    }

    private func fulfill(with result: Result<ByteBuffer, any Error>) {
        guard let pending = pendingRead else { return }
        pendingRead = nil
        pending.promise.completeWith(result)
    }
}

@available(*, unavailable)
extension ByteStreamHandler: Sendable {}

/// Converts an SSH channel's data messages to and from plain byte buffers,
/// and lets the peer half-close the channel (SSH's `EOF`).
final class SSHChannelDataCodec: ChannelDuplexHandler, Sendable {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).assumeIsolated().whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        // Only the main data stream carries bytes; there's no stderr here.
        guard message.type == .channel, case .byteBuffer(let bytes) = message.data else { return }
        context.fireChannelRead(wrapInboundOut(bytes))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let bytes = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(bytes))), promise: promise)
    }
}
