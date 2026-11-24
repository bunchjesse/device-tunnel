import Foundation
import Security
import Synchronization

/// One generic-password item returned by ``KeychainStoring/readAll(service:synchronized:)``.
public struct KeychainItem: Sendable, Hashable {
    /// The item's account attribute.
    public let account: String
    /// The item's secret data.
    public let data: Data
}

/// Generic-password storage for the remote-access stores.
///
/// An item is either *local*, never leaving this device, or *synchronized*,
/// which iCloud Keychain carries end to end encrypted to every device signed
/// in to the same Apple Account. The two are separate namespaces: a local and
/// a synchronized item with the same service and account are different items.
public protocol KeychainStoring: Sendable {
    /// Returns the item's data, or nil when there is no such item.
    func read(service: String, account: String, synchronized: Bool) throws -> Data?
    /// Returns every item stored under `service`.
    func readAll(service: String, synchronized: Bool) throws -> [KeychainItem]
    /// Creates or replaces an item.
    func write(_ data: Data, service: String, account: String, synchronized: Bool) throws
    /// Deletes an item. Deleting a missing item is not an error.
    func delete(service: String, account: String, synchronized: Bool) throws
}

/// A Keychain failure carrying the Security framework status.
public struct KeychainError: Error, LocalizedError, Equatable {
    /// The Security framework result code.
    public let status: OSStatus

    /// Creates an error for a Security framework result code.
    public init(status: OSStatus) {
        self.status = status
    }

    /// True when the build lacks the entitlement the data protection Keychain
    /// requires, which is the case for ad-hoc signed builds.
    public var isMissingEntitlement: Bool { status == errSecMissingEntitlement }

    public var errorDescription: String? {
        if isMissingEntitlement {
            return "This build isn't signed with the Keychain entitlement remote access needs."
        }
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return "Keychain error: \(message)"
    }
}

/// ``KeychainStoring`` backed by the data protection Keychain.
public struct SystemKeychainStore: KeychainStoring {
    private let accessGroup: String?

    /// Creates a store scoped to `accessGroup`, or to the app's default group when nil.
    public init(accessGroup: String?) {
        self.accessGroup = accessGroup
    }

    public func read(service: String, account: String, synchronized: Bool) throws -> Data? {
        var query = baseQuery(service: service, synchronized: synchronized)
        query[kSecAttrAccount as String] = account
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw KeychainError(status: status)
        }
    }

    public func readAll(service: String, synchronized: Bool) throws -> [KeychainItem] {
        var query = baseQuery(service: service, synchronized: synchronized)
        query[kSecReturnAttributes as String] = true
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            let items = result as? [[String: Any]] ?? []
            return items.compactMap { attributes in
                guard let account = attributes[kSecAttrAccount as String] as? String,
                      let data = attributes[kSecValueData as String] as? Data else { return nil }
                return KeychainItem(account: account, data: data)
            }
        case errSecItemNotFound:
            return []
        default:
            throw KeychainError(status: status)
        }
    }

    public func write(_ data: Data, service: String, account: String, synchronized: Bool) throws {
        var query = baseQuery(service: service, synchronized: synchronized)
        query[kSecAttrAccount as String] = account
        let updateStatus = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        switch updateStatus {
        case errSecSuccess: return
        case errSecItemNotFound: break
        default: throw KeychainError(status: updateStatus)
        }

        query[kSecValueData as String] = data
        // A local item must never migrate to another device through a
        // backup restore, so it's pinned to this device.
        query[kSecAttrAccessible as String] = synchronized
            ? kSecAttrAccessibleAfterFirstUnlock
            : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeychainError(status: addStatus) }
    }

    public func delete(service: String, account: String, synchronized: Bool) throws {
        var query = baseQuery(service: service, synchronized: synchronized)
        query[kSecAttrAccount as String] = account
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }

    private func baseQuery(service: String, synchronized: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
            // An explicit `false` keeps local queries from matching
            // synchronized items, and vice versa.
            kSecAttrSynchronizable as String: synchronized,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

/// ``KeychainStoring`` held in memory, for tests.
///
/// Stores created with the same ``SyncedStorage`` behave like two devices on
/// one Apple Account: synchronized items written through one are visible
/// through the other, while local items stay private to each store.
public final class InMemoryKeychainStore: KeychainStoring {
    /// Synchronized items shared by every store created with it.
    public final class SyncedStorage: Sendable {
        fileprivate let items = Mutex<[ItemKey: Data]>([:])

        /// Creates an empty synchronized namespace.
        public init() {}
    }

    fileprivate struct ItemKey: Hashable {
        let service: String
        let account: String
    }

    private let localItems = Mutex<[ItemKey: Data]>([:])
    private let synced: SyncedStorage

    /// Creates a store whose synchronized items live in `synced`.
    public init(synced: SyncedStorage = SyncedStorage()) {
        self.synced = synced
    }

    public func read(service: String, account: String, synchronized: Bool) throws -> Data? {
        let key = ItemKey(service: service, account: account)
        return items(synchronized) { $0[key] }
    }

    public func readAll(service: String, synchronized: Bool) throws -> [KeychainItem] {
        items(synchronized) { items in
            items.filter { $0.key.service == service }
                .map { KeychainItem(account: $0.key.account, data: $0.value) }
        }
    }

    public func write(_ data: Data, service: String, account: String, synchronized: Bool) throws {
        let key = ItemKey(service: service, account: account)
        items(synchronized) { $0[key] = data }
    }

    public func delete(service: String, account: String, synchronized: Bool) throws {
        let key = ItemKey(service: service, account: account)
        items(synchronized) { $0[key] = nil }
    }

    private func items<T>(_ synchronized: Bool, _ body: (inout [ItemKey: Data]) -> T) -> T {
        if synchronized {
            return synced.items.withLock { body(&$0) }
        }
        return localItems.withLock { body(&$0) }
    }
}
