import Foundation

/// A host's decision about one device.
public enum ApprovalDecision: String, Codable, Sendable {
    case approved
    case denied
}

/// A host's recorded decision about a device on the account.
public struct DeviceApproval: Codable, Sendable, Hashable, Identifiable {
    public var id: String { endpointID }

    /// The device's endpoint ID.
    public let endpointID: String

    /// The device's name when the decision was made.
    public var deviceName: String

    /// Whether the device may connect.
    public var decision: ApprovalDecision

    /// When the decision was made.
    public var decidedAt: Date

    /// Creates an approval entry.
    public init(endpointID: String, deviceName: String, decision: ApprovalDecision, decidedAt: Date = Date()) {
        self.endpointID = endpointID
        self.deviceName = deviceName
        self.decision = decision
        self.decidedAt = decidedAt
    }
}

/// The one-time approvals a host has granted or refused.
///
/// Stored in the host's local Keychain and never synchronized: every device
/// on the account can write the synchronized registry, so a decision stored
/// there could be granted by the device asking for it.
public struct DeviceApprovals: Sendable {
    private let store: any KeychainStoring
    private let service: String

    /// Creates an approval store over `store`.
    public init(store: any KeychainStoring, configuration: RemoteAccessConfiguration) {
        self.store = store
        self.service = configuration.approvalsService
    }

    /// Every recorded decision, most recent first.
    public func all() throws -> [DeviceApproval] {
        try store.readAll(service: service, synchronized: false)
            .compactMap { try? Self.decoder.decode(DeviceApproval.self, from: $0.data) }
            .sorted { $0.decidedAt > $1.decidedAt }
    }

    /// The decision recorded for `endpointID`, or nil if the device has never asked.
    public func decision(for endpointID: String) throws -> ApprovalDecision? {
        guard let data = try store.read(service: service, account: endpointID, synchronized: false) else {
            return nil
        }
        return try? Self.decoder.decode(DeviceApproval.self, from: data).decision
    }

    /// Records a decision, replacing any earlier one for the same device.
    public func record(_ approval: DeviceApproval) throws {
        let data = try Self.encoder.encode(approval)
        try store.write(data, service: service, account: approval.endpointID, synchronized: false)
    }

    /// Forgets the decision for `endpointID`, so the device must ask again.
    public func remove(endpointID: String) throws {
        try store.delete(service: service, account: endpointID, synchronized: false)
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
