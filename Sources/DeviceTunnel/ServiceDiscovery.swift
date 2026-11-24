import Foundation
import Network
import Synchronization

/// Finds hosts on the local network by the Bonjour service they advertise,
/// and reports where each one — keyed by endpoint ID — can be reached now.
///
/// Discovery only supplies routes. Identity still rides on the host's key,
/// which the SSH handshake checks against the registry, so an impostor
/// advertising another host's endpoint ID fails to connect like any stale
/// address does.
final class ServiceBrowser: Sendable {
    /// The TXT record key a host's advertisement carries its endpoint ID in.
    static let endpointIDKey = "id"

    private struct State {
        var browser: NWBrowser?
        var retryDelay: Duration = ServiceBrowser.initialRetryDelay
        var isCancelled = false
    }

    private static let initialRetryDelay: Duration = .seconds(1)
    private static let queue = DispatchQueue(label: "dev.bunch.DeviceTunnel.discovery")

    private let serviceType: String
    private let ownEndpointID: String
    private let onChange: @Sendable ([String: [NWEndpoint]]) -> Void
    private let state = Mutex(State())

    /// Browses for `serviceType`, calling `onChange` with every host's
    /// routes each time they change. Results for `ownEndpointID` are left
    /// out. Call ``start()`` to begin.
    init(serviceType: String, ownEndpointID: String, onChange: @escaping @Sendable ([String: [NWEndpoint]]) -> Void) {
        self.serviceType = serviceType
        self.ownEndpointID = ownEndpointID
        self.onChange = onChange
    }

    /// Starts browsing, replacing any browser already running. The routes
    /// found so far stand until the new browser reports its own.
    func start() {
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: serviceType, domain: nil), using: .tcp)
        let (isCancelled, previous) = state.withLock { state -> (Bool, NWBrowser?) in
            guard !state.isCancelled else { return (true, nil) }
            defer { state.browser = browser }
            return (false, state.browser)
        }
        guard !isCancelled else { return }
        previous?.cancel()

        let ownEndpointID = ownEndpointID
        let onChange = onChange
        browser.browseResultsChangedHandler = { results, _ in
            let found = results.compactMap { result -> (NWEndpoint, NWTXTRecord)? in
                guard case .bonjour(let txt) = result.metadata else { return nil }
                return (result.endpoint, txt)
            }
            onChange(Self.routes(from: found, excluding: ownEndpointID))
        }
        browser.stateUpdateHandler = { [weak self, weak browser] state in
            guard let self, let browser else { return }
            self.handle(state, of: browser)
        }
        browser.start(queue: Self.queue)
    }

    /// Stops browsing for good.
    func cancel() {
        let browser = state.withLock { state -> NWBrowser? in
            state.isCancelled = true
            defer { state.browser = nil }
            return state.browser
        }
        browser?.cancel()
    }

    /// Every endpoint ID advertised in `results` and the endpoints it was
    /// found at, leaving out `ownEndpointID` and advertisements without a
    /// well-formed endpoint ID.
    static func routes(from results: [(NWEndpoint, NWTXTRecord)], excluding ownEndpointID: String) -> [String: [NWEndpoint]] {
        var routes: [String: [NWEndpoint]] = [:]
        for (endpoint, txt) in results {
            guard let endpointID = txt[endpointIDKey]?.lowercased(),
                  endpointID != ownEndpointID,
                  endpointID.count == 64,
                  Data(hexEncoded: endpointID) != nil
            else { continue }
            routes[endpointID, default: []].append(endpoint)
        }
        return routes
    }

    private func handle(_ newState: NWBrowser.State, of browser: NWBrowser) {
        switch newState {
        case .ready:
            state.withLock { $0.retryDelay = Self.initialRetryDelay }
        case .waiting(let error):
            // Network framework resumes a waiting browser on its own, e.g.
            // once the user allows Local Network access.
            RemoteLog.discovery.info("Browsing is waiting: \(error.localizedDescription, privacy: .public)")
        case .failed(let error):
            RemoteLog.discovery.error("Browsing failed: \(error.localizedDescription, privacy: .public)")
            let delay = state.withLock { state -> Duration? in
                guard !state.isCancelled, state.browser === browser else { return nil }
                defer { state.retryDelay = min(state.retryDelay * 2, .seconds(30)) }
                return state.retryDelay
            }
            browser.cancel()
            guard let delay else { return }
            Task { [weak self] in
                try? await Task.sleep(for: delay)
                self?.start()
            }
        default:
            break
        }
    }
}

extension NWListener.Service {
    /// The advertisement a host publishes for clients to find it by:
    /// `serviceType`, under the Mac's own name, with its endpoint ID.
    static func tunnel(serviceType: String, endpointID: String) -> NWListener.Service {
        NWListener.Service(type: serviceType, txtRecord: NWTXTRecord([ServiceBrowser.endpointIDKey: endpointID]))
    }
}
