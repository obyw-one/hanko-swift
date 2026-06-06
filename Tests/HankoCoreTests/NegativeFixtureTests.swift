// NegativeFixtureTests.swift — 5 canonical negative fixture tests
// Mirrors Go's tests/negative/negative_test.go (gh:FJ-Studios/hanko, commit b91dd0fc).
//
// All 5 fixtures from spec §7 MUST produce DENIED outcomes.
//
// Fixture mapping:
//   N-1: expired-cap          → testN1ExpiredCap
//   N-2: tampered-attestation → testN2TamperedAttestation
//   N-3: revoked-sigil        → testN3RevokedSigil
//   N-4: replay-attack        → testN4ReplayAttack
//   N-5: scope-mismatch       → testN5ScopeMismatch

import Testing
import Foundation
@testable import HankoCore

// MARK: - Helpers

private func makeBroker() throws -> (Broker, MemStore) {
    let (_, priv) = try Ed25519.generateKeyPair()
    let store = MemStore()
    return (Broker(store: store, privateKey: priv), store)
}

private func subjectKey() throws -> Data {
    let (pub, _) = try Ed25519.generateKeyPair()
    return pub
}

// MARK: - Negative fixtures

@Suite("Negative fixture tests (N-1 through N-5) — all MUST produce DENIED")
struct NegativeFixtureTests {

    // ─────────────────────────────────────────────────────────────
    // N-1: Expired capability rejection
    // "A cap token whose expires_at is in the past MUST be rejected"
    // Expected error: capability_expired (exit code 3)
    // ─────────────────────────────────────────────────────────────

    @Test("N-1: Expired cap is rejected with capability_expired")
    func testN1ExpiredCap() async throws {
        let (broker, _) = try makeBroker()
        let pubKey = try subjectKey()

        let sigil = try await broker.issueSigil(subject: "agent:test", publicKey: pubKey)

        // Manually construct an expired cap with a past expiresAt.
        let past = Date(timeIntervalSince1970: 0) // 1970-01-01T00:00:00Z — well in the past
        let expiredCap = CapabilityToken(
            id: "expired-cap-fixture-0000000000001",
            sigilID: sigil.id,
            scope: "shi-secrets:read:ops/db-url",
            issuedAt: past,
            expiresAt: past, // EXPIRED
            nonce: Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        )

        let env = try await broker.issueAttestation(
            sigilID: sigil.id,
            caps: [expiredCap],
            expiresAt: Date().addingTimeInterval(3600)
        )

        var caughtError: VerifyError?
        do {
            try await broker.verifyAttestation(env)
        } catch let e as VerifyError {
            caughtError = e
        }

        #expect(caughtError != nil, "N-1: expected DENIED for expired cap, got nil error")
        #expect(caughtError?.code == "capability_expired",
                "N-1: expected code 'capability_expired', got '\(caughtError?.code ?? "nil")'")
    }

    // ─────────────────────────────────────────────────────────────
    // N-2: Tampered attestation rejection
    // "An attestation envelope whose signature does not match the canonical JSON
    //  body MUST be rejected"
    // Expected error: signature_invalid (exit code 1)
    // ─────────────────────────────────────────────────────────────

    @Test("N-2: Tampered attestation is rejected with signature_invalid")
    func testN2TamperedAttestation() async throws {
        let (broker, _) = try makeBroker()
        let pubKey = try subjectKey()

        let sigil = try await broker.issueSigil(subject: "agent:test", publicKey: pubKey)

        var env = try await broker.issueAttestation(
            sigilID: sigil.id,
            caps: [],
            expiresAt: Date().addingTimeInterval(3600)
        )

        // Tamper: replace signature with 64 zero bytes.
        env.signature = Data(repeating: 0, count: 64)

        var caughtError: VerifyError?
        do {
            try await broker.verifyAttestation(env)
        } catch let e as VerifyError {
            caughtError = e
        }

        #expect(caughtError != nil, "N-2: expected DENIED for tampered attestation, got nil error")
        #expect(caughtError?.code == "signature_invalid",
                "N-2: expected code 'signature_invalid', got '\(caughtError?.code ?? "nil")'")
    }

    // ─────────────────────────────────────────────────────────────
    // N-3: Revoked sigil rejection
    // "An attestation whose root sigil appears in hanko_revocations MUST be
    //  rejected even if signature is valid"
    // Expected error: sigil_revoked (exit code 2)
    // ─────────────────────────────────────────────────────────────

    @Test("N-3: Revoked sigil is rejected with sigil_revoked")
    func testN3RevokedSigil() async throws {
        let (broker, _) = try makeBroker()
        let pubKey = try subjectKey()

        let sigil = try await broker.issueSigil(subject: "agent:test", publicKey: pubKey)

        // Issue valid attestation BEFORE revoking.
        let env = try await broker.issueAttestation(
            sigilID: sigil.id,
            caps: [],
            expiresAt: Date().addingTimeInterval(3600)
        )

        // Revoke the sigil.
        try await broker.revokeSigil(sigilID: sigil.id, reason: "key compromise", revokedBy: sigil.id)

        // Verify should now fail with sigil_revoked.
        var caughtError: VerifyError?
        do {
            try await broker.verifyAttestation(env)
        } catch let e as VerifyError {
            caughtError = e
        }

        #expect(caughtError != nil, "N-3: expected DENIED for revoked sigil, got nil error")
        #expect(caughtError?.code == "sigil_revoked",
                "N-3: expected code 'sigil_revoked', got '\(caughtError?.code ?? "nil")'")
    }

    // ─────────────────────────────────────────────────────────────
    // N-4: Replay attack rejection
    // "A cap token whose nonce has already been seen MUST be rejected on second use"
    // Expected error: nonce_replayed (exit code 1)
    // ─────────────────────────────────────────────────────────────

    @Test("N-4: Replayed nonce is rejected with nonce_replayed")
    func testN4ReplayAttack() async throws {
        let (broker, _) = try makeBroker()
        let pubKey = try subjectKey()

        let sigil = try await broker.issueSigil(subject: "agent:test", publicKey: pubKey)

        let cap = try await broker.issueCap(
            sigilID: sigil.id,
            scope: "shi-secrets:read:ops/db-url",
            expiresAt: Date().addingTimeInterval(3600)
        )

        // First use — should pass and consume the nonce.
        let env1 = try await broker.issueAttestation(
            sigilID: sigil.id,
            caps: [cap],
            expiresAt: Date().addingTimeInterval(3600)
        )
        try await broker.verifyAttestation(env1)

        // Second use — same cap (same nonce bytes) must be rejected as replayed.
        let env2 = try await broker.issueAttestation(
            sigilID: sigil.id,
            caps: [cap],
            expiresAt: Date().addingTimeInterval(3600)
        )

        var caughtError: VerifyError?
        do {
            try await broker.verifyAttestation(env2)
        } catch let e as VerifyError {
            caughtError = e
        }

        #expect(caughtError != nil, "N-4: expected DENIED for replayed nonce, got nil error")
        #expect(caughtError?.code == "nonce_replayed",
                "N-4: expected code 'nonce_replayed', got '\(caughtError?.code ?? "nil")'")
    }

    // ─────────────────────────────────────────────────────────────
    // N-5: Scope mismatch rejection
    // "A cap token presented for a scope the caller was never granted MUST be rejected"
    // Expected error: scope_mismatch (exit code 1)
    // ─────────────────────────────────────────────────────────────

    @Test("N-5: Scope mismatch is rejected with scope_mismatch")
    func testN5ScopeMismatch() throws {
        let cap = CapabilityToken(
            id: "scope-mismatch-fixture-000000000001",
            sigilID: "11111111-1111-1111-1111-111111111111",
            scope: "garage:write:obyw-media", // granted scope
            issuedAt: Date(),
            expiresAt: Date().addingTimeInterval(3600),
            nonce: Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5])
        )

        // Caller requests a DIFFERENT scope than granted.
        let requestedAction = "garage:write:obyw-backups"

        var caughtError: VerifyError?
        do {
            try Broker.verifyCapScope(cap, requestedAction: requestedAction)
        } catch let e as VerifyError {
            caughtError = e
        }

        #expect(caughtError != nil, "N-5: expected DENIED for scope mismatch, got nil error")
        #expect(caughtError?.code == "scope_mismatch",
                "N-5: expected code 'scope_mismatch', got '\(caughtError?.code ?? "nil")'")
    }
}
