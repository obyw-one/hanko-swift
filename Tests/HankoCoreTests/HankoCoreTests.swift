// HankoCoreTests.swift
// Smoke tests for HankoCore wire types Codable behavior.

import Foundation
import Testing
@testable import HankoCore

@Suite("HankoCore wire types — Codable round-trip")
struct HankoCoreTests {
    private func roundTrip<T: Codable & Equatable>(_ value: T) throws -> T {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(T.self, from: data)
    }

    @Test func sigilRoundTrip() throws {
        let sigil = HankoSigil(
            id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            subject: "operator:shikki@obyw.one",
            publicKey: Data([UInt8](repeating: 7, count: 32)),
            createdAt: Date(timeIntervalSince1970: 1_780_747_200),
            expiresAt: nil,
            metadata: ["workspace": "obyw-one"]
        )
        #expect(try roundTrip(sigil) == sigil)
    }

    @Test func capabilityTokenRoundTrip() throws {
        let cap = HankoCapabilityToken(
            id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            sigilID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            scope: "sigma:portfolio:read",
            issuedAt: Date(timeIntervalSince1970: 1_780_747_200),
            expiresAt: Date(timeIntervalSince1970: 1_780_750_800),
            nonce: Data((1...16).map { UInt8($0) }),
            audience: "sigma-backend@majeluce.com"
        )
        #expect(try roundTrip(cap) == cap)
    }

    @Test func capabilityTokenOmitsEmptyAudienceOnWire() throws {
        // Go's protocol/types.go has no audience field yet — an empty
        // audience must not appear on the wire, and its absence decodes as "".
        let cap = HankoCapabilityToken(
            id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            sigilID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            scope: "sigma:portfolio:read",
            issuedAt: Date(timeIntervalSince1970: 1_780_747_200),
            expiresAt: Date(timeIntervalSince1970: 1_780_750_800),
            nonce: Data((1...16).map { UInt8($0) }),
            audience: ""
        )
        let data = try JSONEncoder().encode(cap)
        let json = try #require(String(bytes: data, encoding: .utf8))
        #expect(!json.contains("audience"))
        #expect(try roundTrip(cap) == cap)
    }

    @Test func revocationEntryRoundTrip() throws {
        let entry = HankoRevocationEntry(
            id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
            targetType: "sigil",
            reason: nil,
            revokedAt: Date(timeIntervalSince1970: 1_780_747_200),
            revokedBy: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        #expect(try roundTrip(entry) == entry)
    }

    @Test func attestationEnvelopeRoundTrip() throws {
        let envelope = HankoAttestationEnvelope(
            sigilID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            caps: [],
            issuer: "hanko-broker@obyw.one",
            issuedAt: Date(timeIntervalSince1970: 1_780_747_200),
            expiresAt: Date(timeIntervalSince1970: 1_780_750_800),
            signature: Data([UInt8](repeating: 9, count: 64))
        )
        #expect(try roundTrip(envelope) == envelope)
    }

    @Test func unsignedBodyStripsSignature() throws {
        let envelope = HankoAttestationEnvelope(
            sigilID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            caps: [],
            issuer: "hanko-broker@obyw.one",
            issuedAt: Date(timeIntervalSince1970: 1_780_747_200),
            expiresAt: Date(timeIntervalSince1970: 1_780_750_800),
            signature: Data([UInt8](repeating: 9, count: 64))
        )
        #expect(envelope.unsignedBody().signature.isEmpty)
        // Per spec §2.1 the unsigned body also omits the key on the wire.
        let data = try JSONEncoder().encode(envelope.unsignedBody())
        let json = try #require(String(bytes: data, encoding: .utf8))
        #expect(!json.contains("signature"))
    }
}
