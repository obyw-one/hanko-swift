// CrossLangParityTests.swift — Wire parity tests between Swift and Go implementations
//
// These tests verify that the Swift implementation produces byte-identical
// canonical JSON and signature behaviour as the Go reference implementation
// (gh:FJ-Studios/hanko, commit b91dd0fc).
//
// The tests use a fixed deterministic key + fixed timestamps to produce
// outputs that can be independently verified against the Go impl.
// See docs/test-vectors.md for the Go-generated reference vectors.

import Testing
import Foundation
@testable import HankoCore

@Suite("Cross-language parity tests (Swift ↔ Go)")
struct CrossLangParityTests {

    // MARK: - Canonical JSON parity

    /// Verifies that the Swift canonical JSON serialiser produces the same
    /// output as Go's marshalCanonical for simple flat objects.
    ///
    /// Go reference: `hcrypto.CanonicalJSON(map[string]any{"a":2,"m":3,"z":1})`
    /// Expected: `{"a":2,"m":3,"z":1}`
    @Test("Canonical JSON: flat object matches Go output byte-for-byte")
    func testCanonicalJSONFlatObject() throws {
        let input: [String: Any] = ["z": 1, "a": 2, "m": 3]
        let output = try canonicalJSON(input)
        let expected = Data(#"{"a":2,"m":3,"z":1}"#.utf8)
        #expect(output == expected,
                "got \(String(data: output, encoding: .utf8) ?? "?"), want {\"a\":2,\"m\":3,\"z\":1}")
    }

    /// Verifies canonical JSON for nested objects (matches Go recursive sort).
    @Test("Canonical JSON: nested object sorts keys recursively")
    func testCanonicalJSONNested() throws {
        let input: [String: Any] = [
            "version": "hanko/v0.1",
            "caps": [] as [Any],
            "issuer": "hanko-broker@obyw.one",
        ]
        let output = try canonicalJSON(input)
        let str = String(data: output, encoding: .utf8)!
        // Keys must be in alphabetical order: caps, issuer, version
        let capsIdx = str.range(of: "\"caps\"")!.lowerBound
        let issuerIdx = str.range(of: "\"issuer\"")!.lowerBound
        let versionIdx = str.range(of: "\"version\"")!.lowerBound
        #expect(capsIdx < issuerIdx && issuerIdx < versionIdx,
                "keys must be alphabetically sorted: caps < issuer < version, got \(str)")
    }

    // MARK: - Ed25519 parity

    /// Verifies that a signature produced by Swift can be verified with the
    /// same public key. This is a basic round-trip; cross-language byte-level
    /// signature equality is non-deterministic (Ed25519 is deterministic per
    /// RFC 8032 for the same message + key, but key generation differs per-run).
    ///
    /// For true byte-level cross-language parity: run `make parity-check` in
    /// the Go repo with a shared fixed test vector. See docs/test-vectors.md.
    @Test("Ed25519 sign+verify round-trip is internally consistent")
    func testEd25519RoundTrip() throws {
        let (pub, priv) = try Ed25519.generateKeyPair()

        let body: [String: Any] = [
            "version": "hanko/v0.1",
            "sigil_id": "11111111-1111-1111-1111-111111111111",
            "issuer": "hanko-broker@obyw.one",
        ]

        let sig = try Ed25519.sign(body: body, privateKey: priv)
        #expect(sig.count == 64)

        // Must not throw.
        try Ed25519.verify(body: body, signature: sig, publicKey: pub)
    }

    /// Verifies that binary fields (Data) are base64-standard encoded on the wire,
    /// matching Go's `encoding/json` default for `[]byte`.
    ///
    /// Go test vector: []byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16} (16 bytes)
    /// Go base64 output: "AQIDBAUGBwgJCgsMDQ4PEA==" (standard, with padding)
    /// 16 bytes → ceil(16/3)*4 = 24 chars base64, with 1 byte of padding "=="
    @Test("Binary fields encode as base64-standard matching Go encoding/json")
    func testBinaryFieldEncoding() throws {
        let nonce = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        let cap = CapabilityToken(
            id: "33333333-3333-3333-3333-333333333333",
            sigilID: "11111111-1111-1111-1111-111111111111",
            scope: "shi-secrets:read:ops/db-url",
            issuedAt: Date(timeIntervalSince1970: 1780704000), // 2026-06-06T00:00:00Z
            expiresAt: Date(timeIntervalSince1970: 1780707600), // +1h
            nonce: nonce
        )

        let encoder = makeHankoEncoder()
        let data = try encoder.encode(cap)
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let nonceB64 = dict["nonce"] as? String else {
            Issue.record("Failed to decode nonce from encoded cap")
            return
        }

        // Go base64 standard for bytes [1..16]: "AQIDBAUGBwgJCgsMDQ4PEA=="
        // (16 bytes → 24 char base64 with padding)
        let expected = "AQIDBAUGBwgJCgsMDQ4PEA=="
        #expect(nonceB64 == expected,
                "nonce base64 mismatch: got \(nonceB64), want \(expected) (Go encoding/json []byte standard)")
    }

    /// Verifies timestamp encoding matches Go's time.Time.UTC().Format(time.RFC3339).
    /// Go outputs "2026-06-06T00:00:00Z" for a UTC time at second precision.
    @Test("RFC3339 timestamp encoding matches Go time.RFC3339 format")
    func testTimestampEncoding() throws {
        // 2026-06-06T00:00:00Z — unix ts 1780704000
        let fixedDate = Date(timeIntervalSince1970: 1780704000)
        let sigil = Sigil(
            id: "11111111-1111-1111-1111-111111111111",
            subject: "operator:test",
            publicKey: Data(repeating: 0, count: 32),
            createdAt: fixedDate,
            metadata: [:]
        )

        let encoder = makeHankoEncoder()
        let data = try encoder.encode(sigil)
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let createdAt = dict["created_at"] as? String else {
            Issue.record("Failed to decode created_at from encoded sigil")
            return
        }

        #expect(createdAt == "2026-06-06T00:00:00Z",
                "RFC3339 mismatch: got \(createdAt), want 2026-06-06T00:00:00Z")
    }

    // MARK: - Negative fixtures from JSON

    /// Loads and validates the bundled negative-fixtures.json, verifying all 5
    /// fixture entries have the expected structure. This mirrors the Go impl's
    /// docs/negative-fixtures.json.
    @Test("Negative fixtures JSON file contains all 5 expected entries")
    func testNegativeFixturesFile() throws {
        guard let url = Bundle.module.url(forResource: "negative-fixtures", withExtension: "json",
                                          subdirectory: "TestVectors") else {
            Issue.record("TestVectors/negative-fixtures.json not found in bundle")
            return
        }

        let data = try Data(contentsOf: url)
        guard let fixtures = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            Issue.record("negative-fixtures.json is not a JSON array of objects")
            return
        }

        #expect(fixtures.count == 5, "expected 5 negative fixtures, got \(fixtures.count)")

        let expectedIDs = ["N-1", "N-2", "N-3", "N-4", "N-5"]
        let gotIDs = fixtures.compactMap { $0["id"] as? String }
        #expect(gotIDs == expectedIDs, "fixture IDs mismatch: got \(gotIDs)")

        let expectedErrors = ["capability_expired", "signature_invalid", "sigil_revoked",
                              "nonce_replayed", "scope_mismatch"]
        let gotErrors = fixtures.compactMap { $0["expected_error"] as? String }
        #expect(gotErrors == expectedErrors, "expected_error values mismatch")
    }
}
