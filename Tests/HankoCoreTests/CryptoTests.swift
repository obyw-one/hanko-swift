// CryptoTests.swift — 5 crypto tests
// Mirrors Go's crypto/ed25519_test.go (gh:FJ-Studios/hanko, commit b91dd0fc).
//
// Test mapping:
//   TestGenerateKeyPair          → testGenerateKeyPair
//   TestSignVerifyRoundTrip      → testSignVerifyRoundTrip
//   TestVerifyTamperedBody       → testVerifyTamperedBody
//   TestCanonicalJSONDeterminism → testCanonicalJSONDeterminism
//   TestGenerateNonce            → testGenerateNonce

import Testing
import Foundation
@testable import HankoCore

@Suite("Crypto tests")
struct CryptoTests {

    /// Mirrors Go TestGenerateKeyPair.
    @Test("GenerateKeyPair returns 32-byte public key")
    func testGenerateKeyPair() throws {
        let (pub, priv) = try Ed25519.generateKeyPair()
        #expect(pub.count == 32, "public key must be 32 bytes, got \(pub.count)")
        // CryptoKit Curve25519 private key raw representation is 32 bytes;
        // Go ed25519.PrivateKey is 64 bytes (seed+pub). We verify the key is usable.
        let testData = Data("test".utf8)
        let sig = try priv.signature(for: testData)
        #expect(sig.count == 64, "Ed25519 signature must be 64 bytes")
    }

    /// Mirrors Go TestSignVerifyRoundTrip.
    @Test("Sign + Verify round-trip succeeds")
    func testSignVerifyRoundTrip() throws {
        let (pub, priv) = try Ed25519.generateKeyPair()

        let body: [String: Any] = [
            "version": "hanko/v0.1",
            "sigil_id": "11111111-1111-1111-1111-111111111111",
            "issuer": "hanko-broker@obyw.one",
        ]

        let sig = try Ed25519.sign(body: body, privateKey: priv)
        #expect(sig.count == 64, "signature length must be 64 bytes")

        // Must not throw.
        try Ed25519.verify(body: body, signature: sig, publicKey: pub)
    }

    /// Mirrors Go TestVerifyTamperedBody.
    @Test("Verify rejects tampered body")
    func testVerifyTamperedBody() throws {
        let (pub, priv) = try Ed25519.generateKeyPair()

        let body: [String: Any] = [
            "version": "hanko/v0.1",
            "sigil_id": "11111111-1111-1111-1111-111111111111",
        ]

        let sig = try Ed25519.sign(body: body, privateKey: priv)

        let tampered: [String: Any] = [
            "version": "hanko/v0.1",
            "sigil_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ]

        var threw = false
        do {
            try Ed25519.verify(body: tampered, signature: sig, publicKey: pub)
        } catch {
            threw = true
        }
        #expect(threw, "Verify must throw on tampered body")
    }

    /// Mirrors Go TestCanonicalJSONDeterminism.
    @Test("CanonicalJSON produces identical bytes regardless of insertion order")
    func testCanonicalJSONDeterminism() throws {
        let a: [String: Any] = ["z": 1, "a": 2, "m": 3]
        let b: [String: Any] = ["m": 3, "z": 1, "a": 2]

        let ca = try canonicalJSON(a)
        let cb = try canonicalJSON(b)

        #expect(ca == cb, "canonical JSON must be deterministic regardless of input key order")

        // Expected: {"a":2,"m":3,"z":1} — matches Go test assertion.
        let expected = Data(#"{"a":2,"m":3,"z":1}"#.utf8)
        #expect(ca == expected, "canonical form mismatch: got \(String(data: ca, encoding: .utf8) ?? "?"), want {\"a\":2,\"m\":3,\"z\":1}")
    }

    /// Mirrors Go TestGenerateNonce.
    @Test("GenerateNonce produces 16 bytes; two calls produce distinct nonces")
    func testGenerateNonce() {
        let n1 = Ed25519.generateNonce()
        #expect(n1.count == 16, "nonce must be 16 bytes")

        let n2 = Ed25519.generateNonce()
        // Two nonces should not be equal (with overwhelming probability).
        #expect(n1 != n2, "two generated nonces must not be identical — entropy failure")
    }
}
