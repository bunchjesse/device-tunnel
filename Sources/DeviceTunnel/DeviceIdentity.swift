import CryptoKit
import Foundation

/// This device's long-lived remote-access identity.
///
/// The private key is an Ed25519 seed kept in the local, never-synchronized
/// Keychain, pinned to this device (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`)
/// so a backup restore never moves it to another one. Its public key is the
/// device's endpoint ID — the SSH key it proves in every tunnel, and the
/// identity a host approves.
public struct DeviceIdentity: Sendable {
    /// The 32-byte Ed25519 private key seed.
    public let secretKey: Data

    /// Lowercase hex encoding of the public key — the endpoint ID.
    public let endpointID: String

    private static let account = "secret-key"

    /// Wraps an existing Ed25519 seed.
    public init(secretKey: Data) throws {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: secretKey)
        self.secretKey = secretKey
        self.endpointID = key.publicKey.rawRepresentation.hexEncoded
    }

    /// Returns this device's identity, creating and storing one on first use.
    public static func loadOrCreate(
        store: any KeychainStoring,
        configuration: RemoteAccessConfiguration
    ) throws -> DeviceIdentity {
        let service = configuration.identityService
        if let existing = try store.read(service: service, account: account, synchronized: false) {
            return try DeviceIdentity(secretKey: existing)
        }
        let generated = Curve25519.Signing.PrivateKey().rawRepresentation
        try store.write(generated, service: service, account: account, synchronized: false)
        return try DeviceIdentity(secretKey: generated)
    }
}
