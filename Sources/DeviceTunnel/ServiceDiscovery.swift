import Foundation
import Network
import Synchronization

/// One host advertisement found on the local network: where it can be
/// reached, and the blinded tag that says which host it is to a device that
/// knows the host's gate key.
struct Advertisement: Sendable, Hashable {
    /// Where the advertised listener can be reached.
    let endpoint: NWEndpoint
    /// The random salt the host chose for this advertisement.
    let salt: Data
    /// ``AccessGate/advertisementTag(gateKey:salt:)`` under the host's gate key.
    let tag: Data

    /// Whether the host whose gate key is `gateKey` published this.
    func isAdvertised(byGateKey gateKey: Data) -> Bool {
        AccessGate.matches(tag, AccessGate.advertisementTag(gateKey: gateKey, salt: salt))
    }
}

/// Finds hosts on the local network by the Bonjour service they advertise.
///
/// Advertisements are blinded: a host advertises under a random instance
/// name, with a fresh random salt and a tag over it keyed by its gate key,
/// so only a device on the account can tell which host an advertisement
/// belongs to (``Advertisement/isAdvertised(byGateKey:)``), and nobody else
/// can follow a host from network to network.
///
/// Discovery only supplies routes. Identity still rides on the host's key,
/// which the access gate and SSH handshake check, so an impostor replaying
/// another host's advertisement fails to connect like any stale address does.
final class ServiceBrowser: Sendable {
    /// The TXT record key a host's advertisement carries its salt in.
    static let saltKey = "s"
    /// The TXT record key a host's advertisement carries its tag in.
    static let tagKey = "t"

    private struct State {
        var browser: NWBrowser?
        var retryDelay: Duration = ServiceBrowser.initialRetryDelay
        var isCancelled = false
    }

    private static let initialRetryDelay: Duration = .seconds(1)
    private static let queue = DispatchQueue(label: "dev.bunch.DeviceTunnel.discovery")

    private let serviceType: String
    private let ownGateKey: Data
    private let onChange: @Sendable ([Advertisement]) -> Void
    private let state = Mutex(State())

    /// Browses for `serviceType`, calling `onChange` with every
    /// advertisement found each time they change. This device's own,
    /// recognized by `ownGateKey`, is left out. Call ``start()`` to begin.
    init(serviceType: String, ownGateKey: Data, onChange: @escaping @Sendable ([Advertisement]) -> Void) {
        self.serviceType = serviceType
        self.ownGateKey = ownGateKey
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

        let ownGateKey = ownGateKey
        let onChange = onChange
        browser.browseResultsChangedHandler = { results, _ in
            let found = results.compactMap { result -> (NWEndpoint, NWTXTRecord)? in
                guard case .bonjour(let txt) = result.metadata else { return nil }
                return (result.endpoint, txt)
            }
            onChange(Self.advertisements(from: found, excludingGateKey: ownGateKey))
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

    /// Every well-formed advertisement in `results`, leaving out the ones
    /// `ownGateKey` publishes.
    static func advertisements(from results: [(NWEndpoint, NWTXTRecord)], excludingGateKey ownGateKey: Data) -> [Advertisement] {
        results.compactMap { endpoint, txt in
            guard let salt = txt[saltKey].flatMap({ Data(hexEncoded: $0) }),
                  let tag = txt[tagKey].flatMap({ Data(hexEncoded: $0) }),
                  salt.count == AccessGate.advertisementSaltLength,
                  tag.count == AccessGate.advertisementTagLength
            else { return nil }
            let advertisement = Advertisement(endpoint: endpoint, salt: salt, tag: tag)
            return advertisement.isAdvertised(byGateKey: ownGateKey) ? nil : advertisement
        }
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
    /// A fresh blinded advertisement for the host whose gate key is
    /// `gateKey`: a random instance name instead of the device's own, and a
    /// new random salt with its tag. A host publishes a new one whenever its
    /// network changes, so nothing in one advertisement names the next; the
    /// listener's port, which a host keeps when it can, still may.
    static func tunnel(serviceType: String, gateKey: Data) -> NWListener.Service {
        let salt = AccessGate.randomBytes(AccessGate.advertisementSaltLength)
        return NWListener.Service(
            name: AccessGate.randomBytes(AccessGate.advertisementNameLength).hexEncoded,
            type: serviceType,
            txtRecord: NWTXTRecord([
                ServiceBrowser.saltKey: salt.hexEncoded,
                ServiceBrowser.tagKey: AccessGate.advertisementTag(gateKey: gateKey, salt: salt).hexEncoded,
            ])
        )
    }
}
