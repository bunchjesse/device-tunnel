import Foundation
import RendezvousRelayProtocol
import Synchronization

/// Failures specific to the remote-access tunnel.
public enum RemoteAccessError: Error, LocalizedError, Equatable {
    /// An operation didn't finish in time.
    case timedOut
    /// The peer sent something the protocol doesn't allow.
    case protocolViolation(String)
    /// The peer finished its stream in the middle of a message.
    case unexpectedEndOfStream
    /// A local TCP listener or connection failed.
    case localSocketFailed(String)
    /// The device that answered isn't the host the record names: it
    /// couldn't prove the host's gate key, or presented another SSH key.
    case hostKeyMismatch
    /// The host turned the device's key away: its copy of the registry
    /// doesn't list this device yet, or it couldn't read its Keychain.
    case notRecognized
    /// The host's record lists no address to reach it at.
    case noRoute
    /// Local Network privacy blocked the connection.
    case localNetworkDenied
    /// The relay turned the connection down.
    case relayRefused(RelayRefusal)
    /// The other device's record lacks what this protocol revision needs
    /// to reach it, because it runs an older build.
    case outdatedPeer

    public var errorDescription: String? {
        switch self {
        case .timedOut: "The connection timed out."
        case .protocolViolation(let detail): "The other device sent an invalid message (\(detail))."
        case .unexpectedEndOfStream: "The other device closed the connection unexpectedly."
        case .localSocketFailed(let detail): "A local connection failed: \(detail)"
        case .hostKeyMismatch: "The other device didn't prove its identity."
        case .notRecognized: "The other device doesn't recognize this one yet."
        case .noRoute: "The other device hasn't published an address yet."
        case .localNetworkDenied: "Local Network access is turned off."
        case .relayRefused(.hostOffline): "The other device isn't connected to its relay."
        case .relayRefused(.hostDidNotAnswer): "The other device didn't answer through the relay."
        case .relayRefused(.busy): "The relay is busy."
        case .relayRefused(.namespaceNotAllowed): "The relay doesn't serve this app."
        case .relayRefused: "The relay refused the connection."
        case .outdatedPeer: "The other device needs a newer version of the app."
        }
    }
}

/// One direction-pair of a byte-oriented connection: a TCP socket or an SSH
/// channel.
protocol ByteStream: Sendable {
    /// Returns up to `maxLength` bytes. An empty result means the peer
    /// finished sending.
    func read(upTo maxLength: Int) async throws -> Data

    /// Sends `data`, returning once the transport has accepted it.
    func write(_ data: Data) async throws

    /// Signals that this side won't send anything more (a half-close).
    func finish() async throws

    /// Releases the stream after both directions completed normally,
    /// without discarding data that is still in flight.
    func close() async

    /// Tears the stream down immediately.
    func abort() async
}

extension ByteStream {
    /// Reads exactly `count` bytes, failing if the peer finishes first.
    func readExactly(_ count: Int) async throws -> Data {
        var buffer = Data()
        buffer.reserveCapacity(count)
        while buffer.count < count {
            let chunk = try await read(upTo: count - buffer.count)
            guard !chunk.isEmpty else { throw RemoteAccessError.unexpectedEndOfStream }
            buffer.append(chunk)
        }
        return buffer
    }
}

/// Joins two byte streams, copying each one's input to the other's output.
enum StreamSplice {
    static let chunkSize = 64 * 1024

    /// Copies in both directions until both finish, forwarding each
    /// half-close as it happens. A failure in either direction aborts both.
    static func run(_ first: some ByteStream, _ second: some ByteStream) async {
        let succeeded = await withTaskGroup(of: Bool.self) { group in
            group.addTask { await pump(from: first, to: second) }
            group.addTask { await pump(from: second, to: first) }
            var allSucceeded = true
            for await directionSucceeded in group where !directionSucceeded {
                allSucceeded = false
                // Aborting unblocks the other direction's pending read.
                await first.abort()
                await second.abort()
            }
            return allSucceeded
        }
        if succeeded {
            await first.close()
            await second.close()
        }
    }

    private static func pump(from source: some ByteStream, to sink: some ByteStream) async -> Bool {
        do {
            while true {
                let chunk = try await source.read(upTo: chunkSize)
                if chunk.isEmpty {
                    try await sink.finish()
                    return true
                }
                try await sink.write(chunk)
            }
        } catch {
            RemoteLog.link.debug("Stream splice ended: \(String(describing: error), privacy: .public)")
            return false
        }
    }
}

/// Runs `operation`, failing with ``RemoteAccessError/timedOut`` if it takes
/// longer than `duration`.
///
/// Unlike a task group, this returns as soon as the deadline passes even when
/// the operation ignores cancellation, which waits on SwiftNIO futures do.
/// The abandoned operation is cancelled and left to finish on its own; a
/// result it still produces goes to `discard`, so the caller can close a
/// connection or stream it never received.
func withTimeout<T: Sendable>(
    _ duration: Duration,
    discardingLateResult discard: @escaping @Sendable (T) -> Void = { _ in },
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    let race = RaceOutcome<T>()
    return try await race.run {
        [
            Task {
                do {
                    let value = try await operation()
                    if !race.settle(with: .success(value)) {
                        discard(value)
                    }
                } catch {
                    race.settle(with: .failure(error))
                }
            },
            Task {
                guard (try? await Task.sleep(for: duration)) != nil else { return }
                race.settle(with: .failure(RemoteAccessError.timedOut))
            },
        ]
    }
}

/// Returns the result of whichever of `first` and `second` finishes first.
///
/// Neither is cancelled: the other keeps running to completion on its own,
/// which suits waits that ignore cancellation, like one on another task's
/// value or a SwiftNIO future. That's why it doesn't use ``RaceOutcome``,
/// which cancels the loser.
func firstFinished<T: Sendable>(
    _ first: @escaping @Sendable () async -> T,
    _ second: @escaping @Sendable () async -> T
) async -> T {
    let continuation = Mutex<CheckedContinuation<T, Never>?>(nil)
    return await withCheckedContinuation { resume in
        continuation.withLock { $0 = resume }
        for operation in [first, second] {
            Task {
                let value = await operation()
                continuation.withLock { $0.take() }?.resume(returning: value)
            }
        }
    }
}

/// Resumes one waiting caller exactly once, with the first result any of
/// its racing tasks reports, and cancels the tasks still running.
///
/// The caller returns the moment the race settles, even when the losing
/// tasks ignore cancellation. A caller cancelled before the race starts
/// gets `CancellationError` without starting it.
final class RaceOutcome<T: Sendable>: Sendable {
    private struct State {
        var continuation: CheckedContinuation<T, any Error>?
        var tasks: [Task<Void, Never>] = []
        var isSettled = false
    }

    private let state = Mutex(State())

    /// Starts the tasks `makeTasks` returns and waits for one of them to
    /// settle the race, or for the caller to be cancelled.
    func run(_ makeTasks: () -> [Task<Void, Never>]) async throws -> T {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let isOpen = state.withLock { state -> Bool in
                    guard !state.isSettled else { return false }
                    state.continuation = continuation
                    return true
                }
                // Only a cancellation can settle the race before it starts.
                guard isOpen else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                let tasks = makeTasks()
                let settledMeanwhile = state.withLock { state -> Bool in
                    state.tasks = tasks
                    return state.isSettled
                }
                if settledMeanwhile {
                    tasks.forEach { $0.cancel() }
                }
            }
        } onCancel: {
            settle(with: .failure(CancellationError()))
        }
    }

    /// Ends the race with `result` unless it has already ended. Returns
    /// whether this call ended it.
    @discardableResult
    func settle(with result: Result<T, any Error>) -> Bool {
        let settled = state.withLock { state -> (CheckedContinuation<T, any Error>?, [Task<Void, Never>])? in
            guard !state.isSettled else { return nil }
            state.isSettled = true
            defer {
                state.continuation = nil
                state.tasks = []
            }
            return (state.continuation, state.tasks)
        }
        guard let (continuation, tasks) = settled else { return false }
        tasks.forEach { $0.cancel() }
        continuation?.resume(with: result)
        return true
    }
}
