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
        // TODO(W3.2):
        //   1. Generate keypair
        //   2. Register Sigil in InMemoryHankoStore
        //   3. Build a CapabilityToken with scope "sigma:portfolio:read",
        //      audience "sigma-backend@majeluce.com"
        //   4. Build AttestationEnvelope around it
        //   5. Compute canonical body, sign with privkey
        //   6. Verify with the same scope + audience → .ok(sigil)
    }

    @Test func wildcardScopeMatchesSpecificRequest() async throws {
        // TODO(W3.2): Granted scope "sigma:portfolio:*" should match
        // requested "sigma:portfolio:read".
    }

    @Test func deepWildcardMatchesMultiLevel() async throws {
        // TODO(W3.2): Granted "sigma:**" matches "sigma:portfolio:export".
    }
}
