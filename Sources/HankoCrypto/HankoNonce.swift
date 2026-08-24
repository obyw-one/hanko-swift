// HankoNonce.swift
// HankoCrypto — 16-byte nonce generation for replay protection.
//
// Mirrors crypto/nonce.go (Go ref impl).

import Foundation

// MARK: - HankoNonce

/// 16-byte nonce generator for capability tokens and attestations.
///
/// Per Hanko v0.1 spec §10 OQ-4, each capability token carries a per-token
/// nonce used for replay protection. The verifier maintains a cache of
/// recently-seen nonces and rejects duplicates.
public enum HankoNonce {
    /// Generate a fresh 16-byte cryptographic random nonce via
    /// `SystemRandomNumberGenerator`.
    ///
    /// - Returns: 16 random bytes.
    public static func generate() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        var rng = SystemRandomNumberGenerator()
        for i in 0..<16 {
            bytes[i] = UInt8.random(in: .min ... .max, using: &rng)
        }
        return Data(bytes)
    }
}
