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

    /// The secret a device must prove it knows before this device, as a
    /// host, runs SSH with it, and that keys this device's Bonjour
    /// advertisement (``AccessGate``). Derived from the private key, so it
    /// needs no storage of its own; publish it in this device's
    /// ``DeviceRecord`` so the account's other devices can reach it.
    public let gateKey: Data

    /// The code people compare to confirm this device's key; see
    /// ``DeviceRecord/fingerprint``.
    public var fingerprint: String {
        DeviceFingerprint.of(endpointID: endpointID)
    }

    private static let account = "secret-key"

    /// Wraps an existing Ed25519 seed.
    public init(secretKey: Data) throws {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: secretKey)
        self.secretKey = secretKey
        self.endpointID = key.publicKey.rawRepresentation.hexEncoded
        self.gateKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secretKey),
            salt: Data("device-tunnel".utf8),
            info: Data("gate-key/1".utf8),
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
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

/// Short codes that name a device's key for people to compare.
///
/// A device's name is whatever its record says, and any device on the
/// account can write any record, so a name proves nothing. A fingerprint is
/// the first 64 bits of a hash of the key, shown as four groups of four hex
/// digits: matching one with a key of an attacker's choosing takes about
/// 2⁶⁴ tries.
enum DeviceFingerprint {
    /// The fingerprint of the key `endpointID` names. An endpoint ID that
    /// isn't hex is hashed as text under its own marker, so it can't share
    /// a key's fingerprint.
    static func of(endpointID: String) -> String {
        var input = Data("device-tunnel-fingerprint/1".utf8)
        if let key = Data(hexEncoded: endpointID) {
            input.append(0)
            input.append(key)
        } else {
            input.append(1)
            input.append(Data(endpointID.utf8))
        }
        let hex = Data(SHA256.hash(data: input).prefix(8)).hexEncoded
        return stride(from: 0, to: hex.count, by: 4).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            return String(hex[start..<hex.index(start, offsetBy: 4)])
        }.joined(separator: "-")
    }
}
