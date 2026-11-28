import Foundation

/// The hosts this client has decided to trust, or not.
///
/// A client pins whatever key a host's registry record names, and any
/// device on the account can publish a record claiming to host under any
/// name. So a ``RemoteHostLink`` dials only a host its user trusts here,
/// after comparing the host's ``DeviceRecord/fingerprint`` with the one the
/// host shows. Stored in the local Keychain and never synchronized, so no
/// device on the account can make itself trusted.
public struct TrustedHosts: Sendable {
    private let decisions: DeviceApprovals

    /// Creates a trust store over `store`.
    public init(store: any KeychainStoring, configuration: RemoteAccessConfiguration) {
        decisions = DeviceApprovals(store: store, service: configuration.trustedHostsService)
    }

    /// Every recorded decision, most recent first.
    public func all() throws -> [DeviceApproval] {
        try decisions.all()
    }

    /// The decision recorded for the host `endpointID`, or nil if its user
    /// hasn't decided.
    public func decision(for endpointID: String) throws -> ApprovalDecision? {
        try decisions.decision(for: endpointID)
    }

    /// Trusts `host`, so links to it connect.
    public func trust(_ host: DeviceRecord) throws {
        try decisions.record(DeviceApproval(endpointID: host.endpointID, deviceName: host.name, decision: .approved))
    }

    /// Distrusts `host`, so links to it stay stopped.
    public func distrust(_ host: DeviceRecord) throws {
        try decisions.record(DeviceApproval(endpointID: host.endpointID, deviceName: host.name, decision: .denied))
    }

    /// Forgets the decision about the host `endpointID`.
    public func remove(endpointID: String) throws {
        try decisions.remove(endpointID: endpointID)
    }

    /// Distrusts every revoked host for good. Returns the endpoint IDs it
    /// distrusted; reconnect links to them so they stop.
    @discardableResult
    public func applyRevocations(_ revocations: [DeviceRevocation]) throws -> [String] {
        try decisions.applyRevocations(revocations)
    }
}
