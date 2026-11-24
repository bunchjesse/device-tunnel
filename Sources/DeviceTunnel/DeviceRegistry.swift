import Foundation

/// The platform a device runs.
public enum DevicePlatform: String, Codable, Sendable, CaseIterable {
    case macOS
    case iOS
    case visionOS
}

/// One device on the account, as published in the synchronized registry.
public struct DeviceRecord: Codable, Sendable, Hashable, Identifiable {
    /// Revision of the tunnel protocol this build speaks. Bump it on every
    /// protocol change and, if older clients can't be served, raise
    /// `RemoteHostService.minimumProtocolVersion` too.
    public static let currentProtocolVersion = 2

    public var id: String { endpointID }

    /// The device's endpoint ID (its Ed25519 public key, lowercase hex).
    public let endpointID: String

    /// User-visible device name, e.g. "Jesse's MacBook Pro".
    public var name: String

    /// The platform the device runs.
    public var platform: DevicePlatform

    /// Whether the device accepts tunnels, serving other devices.
    public var canHost: Bool

    /// Last-known direct addresses as `host:port` (IPv6 in brackets): IP
    /// addresses, then their confirmed DNS names.
    public var directAddresses: [String]

    /// The relay (`host:port`) the device registers with, so devices that
    /// can't reach it directly can connect through the relay; nil when it
    /// uses none, which is also how a record without the key decodes.
    public var relayAddress: String?

    /// Tunnel protocol revision the device speaks.
    public var protocolVersion: Int

    /// When the device last changed its record.
    public var updatedAt: Date

    /// Creates a record.
    public init(
        endpointID: String,
        name: String,
        platform: DevicePlatform,
        canHost: Bool,
        directAddresses: [String],
        relayAddress: String? = nil,
        protocolVersion: Int = DeviceRecord.currentProtocolVersion,
        updatedAt: Date = Date()
    ) {
        self.endpointID = endpointID
        self.name = name
        self.platform = platform
        self.canHost = canHost
        self.directAddresses = directAddresses
        self.relayAddress = relayAddress
        self.protocolVersion = protocolVersion
        self.updatedAt = updatedAt
    }

    /// Whether the two records differ only in `updatedAt`.
    func hasSameContent(as other: DeviceRecord) -> Bool {
        var normalized = other
        normalized.updatedAt = updatedAt
        return normalized == self
    }
}

/// The account's device list.
///
/// Each device owns one synchronized Keychain item holding its
/// ``DeviceRecord``. iCloud Keychain syncs those items end to end encrypted
/// to every device signed in to the same Apple Account, and a new device can
/// only join that sync after being approved with the passcode of one of the
/// account's existing devices. Membership in this list is what makes a device
/// eligible to ask a host for access.
public struct DeviceRegistry: Sendable {
    private let store: any KeychainStoring
    private let service: String

    /// Creates a registry over `store`.
    public init(store: any KeychainStoring, configuration: RemoteAccessConfiguration) {
        self.store = store
        self.service = configuration.registryService
    }

    /// Every readable record on the account, sorted by name.
    public func records() throws -> [DeviceRecord] {
        try store.readAll(service: service, synchronized: true)
            .compactMap { Self.record(from: $0.data, account: $0.account) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The record for `endpointID`, if the device is on the account.
    public func record(for endpointID: String) throws -> DeviceRecord? {
        guard let data = try store.read(service: service, account: endpointID, synchronized: true) else {
            return nil
        }
        return Self.record(from: data, account: endpointID)
    }

    /// Decodes the record stored under `account`. Each device writes its
    /// record under its own endpoint ID, so a record naming another one is
    /// corrupt or forged, and is ignored like an unreadable one.
    private static func record(from data: Data, account: String) -> DeviceRecord? {
        guard let record = try? decoder.decode(DeviceRecord.self, from: data), record.endpointID == account else {
            return nil
        }
        return record
    }

    /// Publishes this device's record.
    ///
    /// Writes nothing when only `updatedAt` would change, so an unchanged
    /// device doesn't generate iCloud Keychain traffic on every launch.
    public func publish(_ record: DeviceRecord) throws {
        if let current = try self.record(for: record.endpointID), current.hasSameContent(as: record) {
            return
        }
        let data = try Self.encoder.encode(record)
        try store.write(data, service: service, account: record.endpointID, synchronized: true)
    }

    /// Removes a device's record from every device on the account.
    public func remove(endpointID: String) throws {
        try store.delete(service: service, account: endpointID, synchronized: true)
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
