import Foundation
import Network
import Synchronization

/// Socket settings shared by tunnel connections.
enum TunnelSocket {
    /// TCP for the tunnel itself, which notices a dead peer or network
    /// within about half a minute: keepalives cover an idle connection, and
    /// the drop time covers one waiting on unacknowledged data — the usual
    /// state with SSE heartbeats flowing, where keepalives never fire and
    /// TCP would otherwise retransmit for minutes.
    static var tcpOptions: NWProtocolTCP.Options {
        let options = NWProtocolTCP.Options()
        options.noDelay = true
        options.enableKeepalive = true
        options.keepaliveIdle = 15
        options.keepaliveInterval = 5
        options.keepaliveCount = 3
        options.connectionDropTime = 30
        return options
    }

    /// TCP for the loopback legs at either end of a tunnel. Small writes go
    /// out at once, so Nagle's algorithm can't hold back an HTTP request's
    /// body until the delayed acknowledgment of its headers.
    static var loopbackTCPOptions: NWProtocolTCP.Options {
        let options = NWProtocolTCP.Options()
        options.noDelay = true
        return options
    }
}

/// ``ByteStream`` over a TCP `NWConnection`.
final class TCPStream: ByteStream {
    private enum Readiness {
        case pending([CheckedContinuation<Void, any Error>])
        case ready
        case failed(String)
    }

    private let connection: NWConnection
    private let readiness = Mutex(Readiness.pending([]))
    private let receivedEnd = Mutex(false)

    /// Wraps and starts a connection accepted by ``LoopbackListener``.
    init(accepted connection: NWConnection) {
        self.connection = connection
        start()
    }

    private init(outbound connection: NWConnection) {
        self.connection = connection
        start()
    }

    /// Opens a TCP connection to `127.0.0.1:port`.
    static func connectToLoopback(port: UInt16, timeout: Duration = .seconds(5)) async throws -> TCPStream {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw RemoteAccessError.localSocketFailed("invalid port \(port)")
        }
        let stream = TCPStream(outbound: NWConnection(
            host: .ipv4(.loopback),
            port: nwPort,
            using: NWParameters(tls: nil, tcp: TunnelSocket.loopbackTCPOptions)
        ))
        do {
            try await withTimeout(timeout) { try await stream.waitUntilReady() }
        } catch {
            await stream.abort()
            throw error
        }
        return stream
    }

    private func start() {
        connection.stateUpdateHandler = { [weak self] state in
            self?.handle(state)
        }
        connection.start(queue: Self.queue)
    }

    /// Delivers every stream's callbacks. They only resume continuations,
    /// so one queue serves them all without a thread per connection.
    private static let queue = DispatchQueue(label: "dev.bunch.DeviceTunnel.tcp")

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            settle(.ready)
        case .failed(let error), .waiting(let error):
            // A loopback connection that has to wait (e.g. connection
            // refused) isn't going to recover; fail fast instead.
            settle(.failed(error.localizedDescription))
        case .cancelled:
            settle(.failed("cancelled"))
        default:
            break
        }
    }

    private func settle(_ outcome: Readiness) {
        let waiters = readiness.withLock { readiness -> [CheckedContinuation<Void, any Error>] in
            guard case .pending(let waiters) = readiness else { return [] }
            readiness = outcome
            return waiters
        }
        for waiter in waiters {
            if case .failed(let reason) = outcome {
                waiter.resume(throwing: RemoteAccessError.localSocketFailed(reason))
            } else {
                waiter.resume()
            }
        }
    }

    private func waitUntilReady() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let outcome = readiness.withLock { readiness -> Readiness? in
                guard case .pending(var waiters) = readiness else { return readiness }
                waiters.append(continuation)
                readiness = .pending(waiters)
                return nil
            }
            switch outcome {
            case .ready?: continuation.resume()
            case .failed(let reason)?: continuation.resume(throwing: RemoteAccessError.localSocketFailed(reason))
            case .pending?, nil: break
            }
        }
    }

    func read(upTo maxLength: Int) async throws -> Data {
        while true {
            if receivedEnd.withLock({ $0 }) { return Data() }
            let chunk = try await receive(maxLength: maxLength)
            if !chunk.isEmpty || receivedEnd.withLock({ $0 }) { return chunk }
        }
    }

    private func receive(maxLength: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { content, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                if isComplete {
                    self.receivedEnd.withLock { $0 = true }
                }
                continuation.resume(returning: content ?? Data())
            }
        }
    }

    func write(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func finish() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func close() async {
        connection.cancel()
    }

    func abort() async {
        connection.forceCancel()
    }
}

/// Accepts TCP connections on the loopback interface only.
///
/// The client side of a tunnel exposes each host as `http://127.0.0.1:<port>`
/// through one of these, so the app's existing `URLSession` code reaches a
/// remote Mac without knowing about the tunnel.
final class LoopbackListener: Sendable {
    private let listener: NWListener
    private let startup = Mutex<CheckedContinuation<UInt16, any Error>?>(nil)
    private let onFailure: @Sendable (String) -> Void

    /// Creates a listener that hands every accepted connection to
    /// `onConnection`, and reports a failure after startup (for example
    /// when iOS reclaims the socket of a suspended app) through `onFailure`.
    init(
        onConnection: @escaping @Sendable (TCPStream) -> Void,
        onFailure: @escaping @Sendable (String) -> Void
    ) throws {
        let parameters = NWParameters(tls: nil, tcp: TunnelSocket.loopbackTCPOptions)
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters)
        self.onFailure = onFailure
        listener.newConnectionHandler = { connection in
            onConnection(TCPStream(accepted: connection))
        }
    }

    /// Starts listening and returns the bound port.
    func start() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { continuation in
            startup.withLock { $0 = continuation }
            listener.stateUpdateHandler = { [weak self] state in
                self?.handle(state)
            }
            listener.start(queue: DispatchQueue(label: "dev.bunch.DeviceTunnel.listener"))
        }
    }

    /// Stops accepting connections.
    func stop() {
        listener.cancel()
    }

    private func handle(_ state: NWListener.State) {
        switch state {
        case .ready:
            let port = listener.port?.rawValue ?? 0
            startup.withLock { continuation in
                continuation?.resume(returning: port)
                continuation = nil
            }
        case .failed(let error), .waiting(let error):
            let wasStarting = startup.withLock { continuation -> Bool in
                guard let pending = continuation else { return false }
                pending.resume(throwing: RemoteAccessError.localSocketFailed(error.localizedDescription))
                continuation = nil
                return true
            }
            listener.cancel()
            if !wasStarting {
                onFailure(error.localizedDescription)
            }
        default:
            break
        }
    }
}
