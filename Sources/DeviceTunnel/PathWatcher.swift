import Foundation
import Network
import NIOCore
import NIOTransportServices
import Synchronization

/// Watches a dialed tunnel's network path.
///
/// While the dial is connecting, a wait for connectivity — refused, no
/// route, or blocked by Local Network privacy — fails it at once with the
/// reason, recorded in a ``DialDiagnosis``, instead of sitting out the
/// connect timeout. Once the tunnel is up, a better path or one that stays
/// unviable past ``unviableGrace`` closes it, so the link redials over
/// whatever works now instead of waiting for TCP to give up.
///
/// Must be the first handler in the pipeline: NIOSSH doesn't pass Network
/// framework events along.
final class PathWatcher: ChannelInboundHandler {
    typealias InboundIn = Any

    /// How long a tunnel's path may stay unviable before the tunnel closes.
    /// Long enough to ride out a Wi-Fi blip or roaming between access points.
    static let unviableGrace: TimeAmount = .seconds(10)

    private let diagnosis: DialDiagnosis
    private let unsatisfiedReason: (any Channel) -> NWPath.UnsatisfiedReason?
    private var isActive = false
    private var unviableClose: Scheduled<Void>?

    /// Creates a watcher that records a failed dial's reason in `diagnosis`.
    /// `unsatisfiedReason` reads why a channel's path is unsatisfied.
    init(
        diagnosis: DialDiagnosis,
        unsatisfiedReason: @escaping (any Channel) -> NWPath.UnsatisfiedReason? = PathWatcher.currentUnsatisfiedReason
    ) {
        self.diagnosis = diagnosis
        self.unsatisfiedReason = unsatisfiedReason
    }

    /// Why `channel`'s current Network framework path is unsatisfied.
    static func currentUnsatisfiedReason(of channel: any Channel) -> NWPath.UnsatisfiedReason? {
        (try? channel.syncOptions?.getOption(NIOTSChannelOptions.currentPath))?.unsatisfiedReason
    }

    func channelActive(context: ChannelHandlerContext) {
        isActive = true
        context.fireChannelActive()
    }

    func channelInactive(context: ChannelHandlerContext) {
        isActive = false
        unviableClose?.cancel()
        unviableClose = nil
        context.fireChannelInactive()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let waiting as NIOTSNetworkEvents.WaitingForConnectivity where !isActive:
            diagnosis.record(dialFailure(waitingOn: waiting.transientError, unsatisfiedReason: unsatisfiedReason(context.channel)))
            context.close(promise: nil)
        case is NIOTSNetworkEvents.BetterPathAvailable where isActive:
            RemoteLog.link.info("A better network path is available; redialing")
            context.close(promise: nil)
        case let update as NIOTSNetworkEvents.ViabilityUpdate where isActive:
            viabilityChanged(update.isViable, context: context)
        default:
            break
        }
        context.fireUserInboundEventTriggered(event)
    }

    private func viabilityChanged(_ isViable: Bool, context: ChannelHandlerContext) {
        guard !isViable else {
            unviableClose?.cancel()
            unviableClose = nil
            return
        }
        guard unviableClose == nil else { return }
        unviableClose = context.eventLoop.assumeIsolated().scheduleTask(in: Self.unviableGrace) {
            RemoteLog.link.info("The tunnel's network path stayed unviable; redialing")
            context.close(promise: nil)
        }
    }
}

@available(*, unavailable)
extension PathWatcher: Sendable {}

/// Why a dial stopped waiting for connectivity, recorded by its
/// ``PathWatcher`` for the code that started the dial.
final class DialDiagnosis: Sendable {
    private let recorded = Mutex<(any Error)?>(nil)

    /// The reason recorded, if the dial had to wait.
    var error: (any Error)? {
        recorded.withLock { $0 }
    }

    /// Keeps `error` unless a reason was already recorded.
    func record(_ error: any Error) {
        recorded.withLock { $0 = $0 ?? error }
    }
}

/// The failure to report for a dial that had to wait for connectivity with
/// `error`, on a path left unsatisfied for `unsatisfiedReason`. Local
/// Network privacy gets its own error, because only the user can fix it.
func dialFailure(waitingOn error: NWError, unsatisfiedReason: NWPath.UnsatisfiedReason?) -> any Error {
    if unsatisfiedReason == .localNetworkDenied {
        return RemoteAccessError.localNetworkDenied
    }
    if case .dns(let code) = error, code == DNSServiceErrorType(kDNSServiceErr_PolicyDenied) {
        return RemoteAccessError.localNetworkDenied
    }
    return error
}
