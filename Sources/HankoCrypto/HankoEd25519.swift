// HankoEd25519.swift
// HankoCrypto — Ed25519 sign/verify wrapper using CryptoKit.
//
// Mirrors crypto/ed25519.go (Go ref impl).
//
// Uses `Curve25519.Signing.PrivateKey` / `PublicKey` from CryptoKit.

import CryptoKit
import Foundation

// MARK: - HankoEd25519

public enum HankoEd25519 {

    // MARK: Errors

    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidSeedLength(Int)
        case invalidPublicKeyLength(Int)
        case invalidSignatureLength(Int)
        case signatureInvalid
    }

    // MARK: Key generation

    /// Generate a fresh Ed25519 keypair.
    ///
    /// - Returns: (publicKey, privateKey) — 32 bytes pub, 32 bytes seed.
    public static func generateKeyPair() -> (publicKey: Data, privateKey: Data) {
        let priv = Curve25519.Signing.PrivateKey()
        return (Data(priv.publicKey.rawRepresentation), Data(priv.rawRepresentation))
    }

    /// Derive a keypair from a deterministic 32-byte seed.
    ///
    /// Used for parity test vectors — both Go (`ed25519.NewKeyFromSeed`)
    /// and Swift must produce the same public key bytes from the same seed.
    ///
    /// CRITICAL parity check: the Swift pubkey from a given seed must
    /// match Go's ed25519.NewKeyFromSeed(seed).Public() exactly.
    /// Verified via `Tests/HankoCryptoTests/Fixtures/sign-verify.json`.
    ///
    /// - Parameter seed: 32 bytes.
    /// - Returns: (publicKey, privateKey).
    public static func keyPair(fromSeed seed: Data) throws -> (publicKey: Data, privateKey: Data) {
        guard seed.count == 32 else { throw Error.invalidSeedLength(seed.count) }
        let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return (Data(priv.publicKey.rawRepresentation), seed)
    }

    // MARK: Sign / verify

    /// Sign `message` with the given Ed25519 private key seed.
    ///
    /// - Parameters:
    ///   - message: Arbitrary bytes (typically canonical JSON).
    ///   - privateKey: 32-byte Ed25519 seed.
    /// - Returns: 64-byte Ed25519 signature.
    public static func sign(_ message: Data, privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else { throw Error.invalidSeedLength(privateKey.count) }
        let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        return try Data(priv.signature(for: message))
    }

    /// Verify an Ed25519 signature.
    ///
    /// - Parameters:
    ///   - signature: 64-byte signature.
    ///   - message: Original message bytes.
    ///   - publicKey: 32-byte Ed25519 public key.
    /// - Throws: `Error.signatureInvalid` if verification fails.
    public static func verify(signature: Data, message: Data, publicKey: Data) throws {
        guard signature.count == 64 else { throw Error.invalidSignatureLength(signature.count) }
        guard publicKey.count == 32 else { throw Error.invalidPublicKeyLength(publicKey.count) }
        let pub = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        guard pub.isValidSignature(signature, for: message) else { throw Error.signatureInvalid }
    }
}
