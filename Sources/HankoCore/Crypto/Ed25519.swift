// Crypto/Ed25519.swift — Ed25519 signing and verification for Hanko protocol
//
// Uses CryptoKit (Apple platforms) via Curve25519.Signing.
// No third-party crypto dependencies.
//
// Parity with Go's hanko/crypto package (gh:FJ-Studios/hanko, commit b91dd0fc):
//   - GenerateKeyPair  → Ed25519.generateKeyPair()
//   - Sign             → Ed25519.sign(body:privateKey:)
//   - Verify           → Ed25519.verify(body:signature:publicKey:)
//   - GenerateNonce    → Ed25519.generateNonce()

import CryptoKit
import Foundation

/// Ed25519 helpers for Hanko signing and verification.
public enum Ed25519 {

    // MARK: - Key generation

    /// Generates a fresh Ed25519 key pair.
    ///
    /// Returns (publicKeyBytes: Data[32], privateKey: Curve25519.Signing.PrivateKey).
    /// The public key Data is the raw 32-byte representation matching Go's ed25519.PublicKey.
    public static func generateKeyPair() throws -> (publicKey: Data, privateKey: Curve25519.Signing.PrivateKey) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey.rawRepresentation // 32 bytes
        return (publicKey, privateKey)
    }

    /// Restores a public key from its raw 32-byte representation.
    public static func publicKey(from rawBytes: Data) throws -> Curve25519.Signing.PublicKey {
        try Curve25519.Signing.PublicKey(rawRepresentation: rawBytes)
    }

    // MARK: - Sign

    /// Signs the canonical JSON representation of body (all fields except any
    /// "signature" key) with privateKey. Returns the raw 64-byte signature.
    ///
    /// This mirrors Go's `hcrypto.Sign(body map[string]any, priv ed25519.PrivateKey)`.
    public static func sign(body: [String: Any], privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        let canonical = try canonicalJSON(body)
        return try privateKey.signature(for: canonical)
    }

    // MARK: - Verify

    /// Verifies that signature is a valid Ed25519 signature over the canonical
    /// JSON of body using publicKey. Throws on failure.
    ///
    /// This mirrors Go's `hcrypto.Verify(body map[string]any, sig []byte, pub ed25519.PublicKey)`.
    public static func verify(body: [String: Any], signature: Data, publicKey: Data) throws {
        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        let canonical = try canonicalJSON(body)
        guard pubKey.isValidSignature(signature, for: canonical) else {
            throw VerifyError(
                code: "signature_invalid",
                message: "Ed25519 signature verification failed"
            )
        }
    }

    // MARK: - Nonce

    /// Generates 16 cryptographically random bytes for use as a CapabilityToken
    /// nonce (per spec §2.1 OQ-4: per-token one-time-use).
    ///
    /// Mirrors Go's `hcrypto.GenerateNonce()`.
    public static func generateNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 {
            bytes[i] = UInt8.random(in: 0...255)
        }
        return Data(bytes)
    }
}
