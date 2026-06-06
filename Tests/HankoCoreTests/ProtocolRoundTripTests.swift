// ProtocolRoundTripTests.swift — 5 protocol round-trip tests
// Mirrors Go's protocol/types_test.go (gh:FJ-Studios/hanko, commit b91dd0fc).
//
// Test mapping:
//   TestSigilRoundTrip              → testSigilRoundTrip
//   TestSigilNullExpiry             → testSigilNullExpiry
//   TestCapabilityTokenRoundTrip    → testCapabilityTokenRoundTrip
//   TestAttestationEnvelopeRoundTrip → testAttestationEnvelopeRoundTrip
//   TestRevocationListRoundTrip     → testRevocationListRoundTrip

import Testing
import Foundation
@testable import HankoCore

@Suite("Protocol round-trip tests")
struct ProtocolRoundTripTests {

    private let encoder = makeHankoEncoder()
    private let decoder = makeHankoDecoder()

    /// Mirrors Go TestSigilRoundTrip.
    @Test("Sigil JSON round-trip preserves all fields")
    func testSigilRoundTrip() throws {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970)) // truncate sub-second
        let exp = now.addingTimeInterval(8760 * 3600)
        let orig = Sigil(
            id: "11111111-1111-1111-1111-111111111111",
            subject: "operator:shikki@obyw.one",
            publicKey: Data("ed25519-pubkey-32-bytes-placeholder!".utf8),
            createdAt: now,
            expiresAt: exp,
            metadata: ["workspace": "obyw-one", "tier": "operator"]
        )

        let raw = try encoder.encode(orig)
        let got = try decoder.decode(Sigil.self, from: raw)

        #expect(got.id == orig.id)
        #expect(got.subject == orig.subject)
        #expect(got.publicKey == orig.publicKey)
        // Compare at second resolution (RFC3339 no sub-second).
        #expect(abs(got.createdAt.timeIntervalSince(orig.createdAt)) < 1)
        #expect(got.expiresAt != nil)
        if let gotExp = got.expiresAt {
            #expect(abs(gotExp.timeIntervalSince(exp)) < 1)
        }
        #expect(got.metadata["workspace"] == "obyw-one")
        #expect(got.metadata["tier"] == "operator")
    }

    /// Mirrors Go TestSigilNullExpiry.
    @Test("Long-lived operator sigil serializes without expires_at field")
    func testSigilNullExpiry() throws {
        let s = Sigil(
            id: "22222222-2222-2222-2222-222222222222",
            subject: "operator:shikki@obyw.one",
            publicKey: Data("pubkey".utf8),
            createdAt: Date(),
            expiresAt: nil,
            metadata: [:]
        )

        let raw = try encoder.encode(s)
        guard let dict = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
            Issue.record("expected JSON object")
            return
        }
        #expect(dict["expires_at"] == nil, "expires_at must be absent for long-lived operator sigil")
    }

    /// Mirrors Go TestCapabilityTokenRoundTrip.
    @Test("CapabilityToken JSON round-trip preserves all fields including nonce")
    func testCapabilityTokenRoundTrip() throws {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let orig = CapabilityToken(
            id: "33333333-3333-3333-3333-333333333333",
            sigilID: "11111111-1111-1111-1111-111111111111",
            scope: "shi-secrets:read:ops/db-url",
            issuedAt: now,
            expiresAt: now.addingTimeInterval(3600),
            nonce: Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        )

        let raw = try encoder.encode(orig)
        let got = try decoder.decode(CapabilityToken.self, from: raw)

        #expect(got.id == orig.id)
        #expect(got.scope == orig.scope)
        #expect(got.nonce == orig.nonce, "nonce must round-trip exactly")
        #expect(got.sigilID == orig.sigilID)
    }

    /// Mirrors Go TestAttestationEnvelopeRoundTrip.
    @Test("AttestationEnvelope JSON round-trip preserves version and issuer")
    func testAttestationEnvelopeRoundTrip() throws {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let orig = AttestationEnvelope(
            version: hankoVersion,
            sigilID: "11111111-1111-1111-1111-111111111111",
            caps: [],
            issuer: "hanko-broker@obyw.one",
            issuedAt: now,
            expiresAt: now.addingTimeInterval(1800),
            signature: Data("fake-sig-64-bytes-placeholder!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!".utf8)
        )

        let raw = try encoder.encode(orig)
        let got = try decoder.decode(AttestationEnvelope.self, from: raw)

        #expect(got.version == hankoVersion)
        #expect(got.issuer == "hanko-broker@obyw.one")
        #expect(got.sigilID == orig.sigilID)
    }

    /// Mirrors Go TestRevocationListRoundTrip.
    @Test("RevocationList JSON round-trip preserves entries")
    func testRevocationListRoundTrip() throws {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let orig = RevocationList(entries: [
            RevocationEntry(
                id: "44444444-4444-4444-4444-444444444444",
                targetType: "sigil",
                reason: "key compromise",
                revokedAt: now,
                revokedBy: "55555555-5555-5555-5555-555555555555"
            )
        ])

        let raw = try encoder.encode(orig)
        let got = try decoder.decode(RevocationList.self, from: raw)

        #expect(got.entries.count == 1)
        #expect(got.entries[0].targetType == "sigil")
        #expect(got.entries[0].reason == "key compromise")
        #expect(got.entries[0].revokedBy == "55555555-5555-5555-5555-555555555555")
    }
}
