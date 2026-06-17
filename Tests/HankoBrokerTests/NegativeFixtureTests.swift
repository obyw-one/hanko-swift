// NegativeFixtureTests.swift
// Mirror of Go's tests/negative/negative_test.go — 5 canonical denial cases.
//
// Source: ~/.shikki/tmp/wt-hanko-w5-2026-06-06/tests/negative/negative_test.go
//
// All 5 fixtures must produce a DENIED outcome (HankoVerifyError) with the
// correct code. Mirrors the Go contract exactly.

import Testing
import Foundation
@testable import HankoBroker
@testable import HankoCore
@testable import HankoCrypto

@Suite("Negative fixtures — must all DENY")
struct NegativeFixtureTests {

    @Test func expiredCapIsRejected() async throws {
        // TODO(W3.3): cap.expires_at in the past → .denied(.capExpired)
    }

    @Test func tamperedAttestationIsRejected() async throws {
        // TODO(W3.3): Flip 1 byte in signature → .denied(.signatureInvalid)
    }

    @Test func revokedSigilIsRejected() async throws {
        // TODO(W3.3): store.revoke(sigil.id) before verify → .denied(.sigilRevoked)
    }

    @Test func replayAttackIsRejected() async throws {
        // TODO(W3.3): Same cap.nonce verified twice → second attempt .denied(.nonceReplayed)
    }

    @Test func scopeMismatchIsRejected() async throws {
        // TODO(W3.3): Granted "sigma:portfolio:read", requested
        // "sigma:portfolio:write" → .denied(.scopeMismatch)
    }
}
