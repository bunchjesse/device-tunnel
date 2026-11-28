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
    public static let currentProtocolVersion = 3

    public var id: String { endpointID }

    /// The device's endpoint ID (its Ed25519 public key, lowercase hex).
    public let endpointID: String

    /// The device's ``DeviceIdentity/gateKey``, which a client proves it
    /// knows before the device, as a host, runs SSH with it. Nil in records
    /// from builds older than protocol 3, which can't be reached.
    public var gateKey: Data?

    /// User-visible device name, e.g. "Jesse's MacBook Pro". Any device on
    /// the account can write any name, so show ``fingerprint`` wherever a
    /// person decides whether to trust the device.
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

    /// Creates a record. Pass the device's ``DeviceIdentity/gateKey`` as
    /// `gateKey`, or other devices can't reach it.
    public init(
        endpointID: String,
        gateKey: Data?,
        name: String,
        platform: DevicePlatform,
        canHost: Bool,
        directAddresses: [String],
        relayAddress: String? = nil,
        protocolVersion: Int = DeviceRecord.currentProtocolVersion,
        updatedAt: Date = Date()
    ) {
        self.endpointID = endpointID
        self.gateKey = gateKey
        self.name = name
        self.platform = platform
        self.canHost = canHost
        self.directAddresses = directAddresses
        self.relayAddress = relayAddress
        self.protocolVersion = protocolVersion
        self.updatedAt = updatedAt
    }

    /// A short code naming this device's key, e.g. `3f2a-91c0-77de-0b45`.
    /// Unlike ``name``, no other device can copy it, so an approval prompt
    /// should show it for the user to compare with the
    /// ``DeviceIdentity/fingerprint`` the asking device shows.
    public var fingerprint: String {
        DeviceFingerprint.of(endpointID: endpointID)
    }

    /// Whether the two records differ only in `updatedAt`.
    func hasSameContent(as other: DeviceRecord) -> Bool {
        var normalized = other
        normalized.updatedAt = updatedAt
        return normalized == self
    }
}

/// An account-wide notice that a device must no longer be trusted, written
/// with ``DeviceRegistry/revoke(_:)``.
///
/// Every device on the account can write the registry, the revoked one
/// included, so a revocation can be deleted again. Each host and client
/// therefore turns the revocations it sees into permanent local decisions
/// (``DeviceApprovals/applyRevocations(_:)``, ``TrustedHosts/applyRevocations(_:)``)
/// that no synchronized write can undo.
public struct DeviceRevocation: Codable, Sendable, Hashable, Identifiable {
    public var id: String { endpointID }

    /// The revoked device's endpoint ID.
    public let endpointID: String

    /// The device's name when it was revoked.
    public var deviceName: String

    /// When the device was revoked.
    public var revokedAt: Date

    /// Creates a revocation.
    public init(endpointID: String, deviceName: String, revokedAt: Date = Date()) {
        self.endpointID = endpointID
        self.deviceName = deviceName
        self.revokedAt = revokedAt
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
///
/// A device can be revoked across the account (``revoke(_:)``); its record
/// is then hidden on every device, whether or not it publishes it again.
public struct DeviceRegistry: Sendable {
    private let store: any KeychainStoring
    private let service: String
    private let revocationsService: String

    /// Creates a registry over `store`.
    public init(store: any KeychainStoring, configuration: RemoteAccessConfiguration) {
        self.store = store
        self.service = configuration.registryService
        self.revocationsService = configuration.revocationsService
    }

    /// Every readable record on the account, sorted by name, leaving out
    /// revoked devices.
    public func records() throws -> [DeviceRecord] {
        let revoked = Set(try revocations().map(\.endpointID))
        return try store.readAll(service: service, synchronized: true)
            .compactMap { Self.record(from: $0.data, account: $0.account) }
            .filter { !revoked.contains($0.endpointID) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The record for `endpointID`, if the device is on the account and
    /// hasn't been revoked.
    public func record(for endpointID: String) throws -> DeviceRecord? {
        guard try revocation(for: endpointID) == nil else { return nil }
        return try storedRecord(for: endpointID)
    }

    /// Whether the registry knows `endpointID` at all: it has a record, or
    /// was revoked. A host admits such a device's key to SSH so that its
    /// control stream can turn a revoked device away explicitly.
    func knows(endpointID: String) throws -> Bool {
        try revocation(for: endpointID) != nil || storedRecord(for: endpointID) != nil
    }

    private func storedRecord(for endpointID: String) throws -> DeviceRecord? {
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
        if let current = try storedRecord(for: record.endpointID), current.hasSameContent(as: record) {
            return
        }
        let data = try Self.encoder.encode(record)
        try store.write(data, service: service, account: record.endpointID, synchronized: true)
    }

    /// Removes a device's record from every device on the account. The
    /// device can publish it again; use ``revoke(_:)`` to cut it off.
    public func remove(endpointID: String) throws {
        try store.delete(service: service, account: endpointID, synchronized: true)
    }

    /// Revokes a device across the account: hides its record everywhere and
    /// tells every host and client to stop trusting it for good, as for a
    /// lost or stolen device.
    public func revoke(_ revocation: DeviceRevocation) throws {
        let data = try Self.encoder.encode(revocation)
        try store.write(data, service: revocationsService, account: revocation.endpointID, synchronized: true)
        try remove(endpointID: revocation.endpointID)
    }

    /// Withdraws a revocation. Devices that already applied it keep their
    /// local decisions, which their users must reverse one by one.
    public func unrevoke(endpointID: String) throws {
        try store.delete(service: revocationsService, account: endpointID, synchronized: true)
    }

    /// Every revocation on the account, most recent first.
    public func revocations() throws -> [DeviceRevocation] {
        try store.readAll(service: revocationsService, synchronized: true)
            .compactMap { Self.revocation(from: $0.data, account: $0.account) }
            .sorted { $0.revokedAt > $1.revokedAt }
    }

    /// The revocation for `endpointID`, if the device was revoked.
    public func revocation(for endpointID: String) throws -> DeviceRevocation? {
        guard let data = try store.read(service: revocationsService, account: endpointID, synchronized: true) else {
            return nil
        }
        return Self.revocation(from: data, account: endpointID)
    }

    /// Decodes the revocation stored under `account`, ignoring one that
    /// names another device, as ``record(from:account:)`` does.
    private static func revocation(from data: Data, account: String) -> DeviceRevocation? {
        guard let revocation = try? decoder.decode(DeviceRevocation.self, from: data), revocation.endpointID == account else {
            return nil
        }
        return revocation
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
