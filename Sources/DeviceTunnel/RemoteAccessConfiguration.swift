import Foundation

/// Names that keep each build flavor in its own trust domain.
///
/// Debug and Release builds must never see each other's devices, so every
/// Keychain service name derives from the build's prefix, and the protocol
/// name, Bonjour service type, and relay namespace keep the flavors apart on
/// the network. The access group is the Keychain group shared by an app's
/// variants on each platform; it is team-prefixed, so they must all be
/// signed by one team.
public struct RemoteAccessConfiguration: Sendable, Hashable {
    /// Prefix for every Keychain service name, e.g. `com.example.app`.
    public let keychainServicePrefix: String

    /// Team-prefixed Keychain access group shared by the app's variants, or
    /// nil to use the calling app's default group.
    public let keychainAccessGroup: String?

    /// Names this flavor's tunnel protocol: the SSH user name a client
    /// authenticates as, keeping build flavors apart on the wire. It must
    /// never change with the protocol's revision — that travels in
    /// `ClientHello`, where a host can explain a mismatch — because a
    /// different user name fails authentication without a reason.
    public let protocolName: String

    /// The Bonjour service type hosts advertise and clients browse for,
    /// e.g. `_example._tcp`; nil turns local-network discovery off. It
    /// must be listed in the app's `NSBonjourServices`.
    public let serviceType: String?

    /// Names one of several processes of the same build on one Mac, giving
    /// each its own identity, approvals, and trusted hosts so they act as
    /// different devices. The registry stays shared. Nil for a normal install.
    public let localInstance: String?

    /// Creates a configuration. `protocolName` and `serviceType` should
    /// differ between build flavors.
    public init(
        keychainServicePrefix: String,
        keychainAccessGroup: String?,
        protocolName: String,
        serviceType: String? = nil,
        localInstance: String? = nil
    ) {
        self.keychainServicePrefix = keychainServicePrefix
        self.keychainAccessGroup = keychainAccessGroup
        self.protocolName = protocolName
        self.serviceType = serviceType
        self.localInstance = localInstance
    }

    private var localSuffix: String { localInstance.map { ".\($0)" } ?? "" }

    /// The namespace a host registers in at a relay, and that clients ask
    /// for it in: the Keychain prefix (`com.example.app`,
    /// `com.example.app.debug`), so build flavors stay apart on a shared
    /// relay and a relay can admit them by name.
    public var relayNamespace: String { keychainServicePrefix }

    /// Service holding this device's private key. Never synchronized.
    var identityService: String { keychainServicePrefix + ".remote.identity" + localSuffix }

    /// Service holding one synchronized record per device on the account.
    var registryService: String { keychainServicePrefix + ".remote.devices" }

    /// Service holding one synchronized revocation per revoked device.
    var revocationsService: String { keychainServicePrefix + ".remote.revoked" }

    /// Service holding this host's approval decisions. Never synchronized,
    /// so a device on the account can't approve itself.
    var approvalsService: String { keychainServicePrefix + ".remote.approvals" + localSuffix }

    /// Service holding this client's decisions about hosts. Never
    /// synchronized, so a device on the account can't make itself trusted.
    var trustedHostsService: String { keychainServicePrefix + ".remote.trusted-hosts" + localSuffix }
}
