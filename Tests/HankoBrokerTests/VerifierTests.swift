// VerifierTests.swift
// Happy-path verifier scenarios.

import Testing
import Foundation
@testable import HankoBroker
@testable import HankoCore
@testable import HankoCrypto

@Suite("HankoVerifier — happy path")
struct VerifierTests {

    @Test func validEnvelopeWithMatchingScopeIsAccepted() async throws {
        let s = try await EnvelopeFactory.make(scope: "sigma:portfolio:read")
        let outcome = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:read",
            audience: EnvelopeFactory.defaultAudience
        )
        guard case .ok(let sigil) = outcome else {
            Issue.record("expected .ok, got \(outcome)")
            return
        }
        #expect(sigil.id == s.sigil.id)
    }

    @Test func wildcardScopeMatchesSpecificRequest() async throws {
        let s = try await EnvelopeFactory.make(scope: "sigma:portfolio:*")
        let outcome = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:read",
            audience: EnvelopeFactory.defaultAudience
        )
        guard case .ok = outcome else {
            Issue.record("expected .ok for wildcard grant, got \(outcome)")
            return
        }
    }

    @Test func deepWildcardMatchesMultiLevel() async throws {
        let s = try await EnvelopeFactory.make(scope: "sigma:**")
        let outcome = try await s.verifier.verify(
            envelope: s.envelope,
            requestedScope: "sigma:portfolio:export",
            audience: EnvelopeFactory.defaultAudience
        )
        guard case .ok = outcome else {
            Issue.record("expected .ok for deep wildcard, got \(outcome)")
            return
        }
    }
}
