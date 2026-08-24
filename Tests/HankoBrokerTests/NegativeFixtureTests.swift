// NegativeFixtureTests.swift
// Mirror of Go's tests/negative/negative_test.go — 5 canonical denial cases.
//
// Source: ~/.shikki/tmp/wt-hanko-w5-2026-06-06/tests/negative/negative_test.go
//
// All 5 fixtures must produce a DENIED outcome (HankoVerifyError) with the
// correct code. Mirrors the Go contract exactly.

import Foundation
import Testing
@testable import HankoBroker
@testable import HankoCore
@testable import HankoCrypto

@Suite("Negative fixtures — must all DENY")
struct NegativeFixtureTests {
    private func expectDenied(
        _ outcome: HankoVerifier.Outcome,
        code: String,
        _ label: String
    ) {
        guard case let .denied(error) = outcome else {
            Issue.record("\(label): expected denial, got \(outcome)")
            return
        }
        #expect(error.code == code, Comment(rawValue: label))
    }

    @Test func expiredCapIsRejected() async throws {
        let s = try await EnvelopeFactory.make(capExpiresIn: -60)
        let outcome = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:read",
            audience: EnvelopeFactory.defaultAudience
        )
        expectDenied(outcome, code: "capability_expired", "expired cap")
    }

    @Test func tamperedAttestationIsRejected() async throws {
        let s = try await EnvelopeFactory.make()
        var tamperedSig = s.envelope.signature
        tamperedSig[0] ^= 0x01
        let tampered = HankoAttestationEnvelope(
            sigilID: s.envelope.sigilID,
            caps: s.envelope.caps,
            issuer: s.envelope.issuer,
            issuedAt: s.envelope.issuedAt,
            expiresAt: s.envelope.expiresAt,
            signature: tamperedSig
        )
        let outcome = try await s.verifier.verify(
            envelope: tampered,
            requestedScope: "sigma:portfolio:read",
            audience: EnvelopeFactory.defaultAudience
        )
        expectDenied(outcome, code: "signature_invalid", "tampered signature")
    }

    @Test func revokedSigilIsRejected() async throws {
        let s = try await EnvelopeFactory.make()
        try await s.store.revoke(HankoRevocationEntry(
            id: s.sigil.id,
            targetType: "sigil",
            reason: "test revocation",
            revokedAt: Date(),
            revokedBy: "test-suite"
        ))
        let outcome = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:read",
            audience: EnvelopeFactory.defaultAudience
        )
        expectDenied(outcome, code: "sigil_revoked", "revoked sigil")
    }

    @Test func replayAttackIsRejected() async throws {
        let s = try await EnvelopeFactory.make()
        let first = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:read",
            audience: EnvelopeFactory.defaultAudience
        )
        guard case .ok = first else {
            Issue.record("first verification should succeed, got \(first)")
            return
        }
        let second = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:read",
            audience: EnvelopeFactory.defaultAudience
        )
        expectDenied(second, code: "nonce_replayed", "nonce replay")
    }

    @Test func scopeMismatchIsRejected() async throws {
        let s = try await EnvelopeFactory.make(scope: "sigma:portfolio:read")
        let outcome = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:write",
            audience: EnvelopeFactory.defaultAudience
        )
        expectDenied(outcome, code: "scope_mismatch", "scope mismatch")
    }
}
