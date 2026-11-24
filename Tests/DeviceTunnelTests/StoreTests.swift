import Foundation
import Synchronization
import Testing
@testable import DeviceTunnel

/// Keeps a count of synchronized writes so tests can assert on sync churn.
final class CountingKeychainStore: KeychainStoring {
    let base: InMemoryKeychainStore
    private let writes = LockedCounter()

    init(base: InMemoryKeychainStore) { self.base = base }

    var synchronizedWrites: Int { writes.value }

    func read(service: String, account: String, synchronized: Bool) throws -> Data? {
        try base.read(service: service, account: account, synchronized: synchronized)
    }

    func readAll(service: String, synchronized: Bool) throws -> [KeychainItem] {
        try base.readAll(service: service, synchronized: synchronized)
    }

    func write(_ data: Data, service: String, account: String, synchronized: Bool) throws {
        if synchronized { writes.increment() }
        try base.write(data, service: service, account: account, synchronized: synchronized)
    }

    func delete(service: String, account: String, synchronized: Bool) throws {
        try base.delete(service: service, account: account, synchronized: synchronized)
    }
}

final class LockedCounter: Sendable {
    private let count = Mutex(0)

    var value: Int { count.withLock { $0 } }
    func increment() { count.withLock { $0 += 1 } }
}

/// A switch tests flip while a host is running.
final class LockedFlag: Sendable {
    private let state: Mutex<Bool>

    init(_ value: Bool) { state = Mutex(value) }

    var value: Bool {
        get { state.withLock { $0 } }
        set { state.withLock { $0 = newValue } }
    }
}

struct KeychainStoreTests {
    /// Local and synchronized items live in separate namespaces, and a second
    /// store sharing the synchronized storage (a second device on the same
    /// account) sees only the synchronized one.
    @Test func localAndSynchronizedItemsAreSeparate() throws {
        let synced = InMemoryKeychainStore.SyncedStorage()
        let mac = InMemoryKeychainStore(synced: synced)
        let phone = InMemoryKeychainStore(synced: synced)

        try mac.write(Data("local".utf8), service: "s", account: "a", synchronized: false)
        try mac.write(Data("synced".utf8), service: "s", account: "a", synchronized: true)

        #expect(try mac.read(service: "s", account: "a", synchronized: false) == Data("local".utf8))
        #expect(try mac.read(service: "s", account: "a", synchronized: true) == Data("synced".utf8))
        #expect(try phone.read(service: "s", account: "a", synchronized: false) == nil)
        #expect(try phone.read(service: "s", account: "a", synchronized: true) == Data("synced".utf8))
    }

    /// Deleting removes only the addressed item, and deleting a missing
    /// item is not an error.
    @Test func deleteRemovesOnlyTheAddressedItem() throws {
        let store = InMemoryKeychainStore()
        try store.write(Data([1]), service: "s", account: "a", synchronized: true)
        try store.write(Data([2]), service: "s", account: "b", synchronized: true)

        try store.delete(service: "s", account: "a", synchronized: true)
        try store.delete(service: "s", account: "missing", synchronized: true)

        #expect(try store.readAll(service: "s", synchronized: true).map(\.account) == ["b"])
    }
}

struct DeviceIdentityTests {
    /// The first call creates and stores a key; later calls return the same
    /// identity instead of minting a new one.
    @Test func identityIsCreatedOnceAndReloaded() throws {
        let store = InMemoryKeychainStore()
        let configuration = makeConfiguration()

        let first = try DeviceIdentity.loadOrCreate(store: store, configuration: configuration)
        let second = try DeviceIdentity.loadOrCreate(store: store, configuration: configuration)

        #expect(first.secretKey.count == 32)
        #expect(first.endpointID == second.endpointID)
        #expect(first.endpointID.count == 64)
    }

    /// The private key is stored as a local item, so iCloud Keychain never
    /// carries it to another device.
    @Test func secretKeyIsNeverSynchronized() throws {
        let synced = InMemoryKeychainStore.SyncedStorage()
        let store = InMemoryKeychainStore(synced: synced)
        let configuration = makeConfiguration()

        _ = try DeviceIdentity.loadOrCreate(store: store, configuration: configuration)

        let otherDevice = InMemoryKeychainStore(synced: synced)
        #expect(try otherDevice.readAll(service: configuration.identityService, synchronized: true).isEmpty)
    }
}

struct DeviceRegistryTests {
    /// A published record is visible to another device on the account, and
    /// records come back sorted by name.
    @Test func publishedRecordsAreVisibleToOtherDevices() throws {
        let synced = InMemoryKeychainStore.SyncedStorage()
        let configuration = makeConfiguration()
        let macRegistry = DeviceRegistry(store: InMemoryKeychainStore(synced: synced), configuration: configuration)
        let phoneRegistry = DeviceRegistry(store: InMemoryKeychainStore(synced: synced), configuration: configuration)

        try macRegistry.publish(makeRecord(endpointID: "b", name: "Studio", platform: .macOS, canHost: true))
        try phoneRegistry.publish(makeRecord(endpointID: "a", name: "iPhone"))

        #expect(try phoneRegistry.records().map(\.name) == ["iPhone", "Studio"])
        #expect(try phoneRegistry.record(for: "b")?.canHost == true)
    }

    /// Republishing a record whose only change is its timestamp writes
    /// nothing, so an unchanged device doesn't cause iCloud sync traffic.
    @Test func unchangedRecordIsNotRewritten() throws {
        let store = CountingKeychainStore(base: InMemoryKeychainStore())
        let registry = DeviceRegistry(store: store, configuration: makeConfiguration())
        var record = makeRecord(endpointID: "a")

        try registry.publish(record)
        record.updatedAt = record.updatedAt.addingTimeInterval(60)
        try registry.publish(record)
        record.name = "Renamed"
        try registry.publish(record)

        #expect(store.synchronizedWrites == 2)
    }

    /// A record stored under another device's account — a corrupt or
    /// forged item — is ignored rather than trusted, so it can't show up as
    /// a second host with a borrowed endpoint ID.
    @Test func recordUnderTheWrongAccountIsIgnored() throws {
        let store = InMemoryKeychainStore()
        let configuration = makeConfiguration()
        let registry = DeviceRegistry(store: store, configuration: configuration)
        try registry.publish(makeRecord(endpointID: "a", name: "Studio"))
        let forged = try JSONEncoder.registry.encode(makeRecord(endpointID: "a", name: "Impostor"))
        try store.write(forged, service: configuration.registryService, account: "b", synchronized: true)

        #expect(try registry.records().map(\.name) == ["Studio"])
        #expect(try registry.record(for: "b") == nil)
    }

    /// Removing a record deletes it for every device on the account.
    @Test func removeDeletesRecord() throws {
        let registry = DeviceRegistry(store: InMemoryKeychainStore(), configuration: makeConfiguration())
        try registry.publish(makeRecord(endpointID: "a"))

        try registry.remove(endpointID: "a")

        #expect(try registry.record(for: "a") == nil)
    }
}

struct DeviceApprovalsTests {
    /// Decisions round-trip, and forgetting one makes the device ask again.
    @Test func decisionsAreRecordedAndForgotten() throws {
        let approvals = DeviceApprovals(store: InMemoryKeychainStore(), configuration: makeConfiguration())

        try approvals.record(DeviceApproval(endpointID: "a", deviceName: "iPhone", decision: .approved))
        try approvals.record(DeviceApproval(endpointID: "b", deviceName: "iPad", decision: .denied))
        #expect(try approvals.decision(for: "a") == .approved)
        #expect(try approvals.decision(for: "b") == .denied)
        #expect(try approvals.decision(for: "c") == nil)

        try approvals.remove(endpointID: "a")
        #expect(try approvals.decision(for: "a") == nil)
    }

    /// Approvals are local to the host and never reach another device on
    /// the account, so no device can grant itself access through sync.
    @Test func approvalsNeverSynchronize() throws {
        let synced = InMemoryKeychainStore.SyncedStorage()
        let configuration = makeConfiguration()
        let host = DeviceApprovals(store: InMemoryKeychainStore(synced: synced), configuration: configuration)
        try host.record(DeviceApproval(endpointID: "a", deviceName: "iPhone", decision: .approved))

        let otherDevice = DeviceApprovals(store: InMemoryKeychainStore(synced: synced), configuration: configuration)
        #expect(try otherDevice.all().isEmpty)
    }
}

extension JSONEncoder {
    /// Encodes records the way the registry stores them.
    static var registry: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}
