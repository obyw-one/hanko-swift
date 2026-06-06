// BrokerTests.swift — 4 broker happy-path tests
// Mirrors Go's broker/broker_test.go (gh:FJ-Studios/hanko, commit b91dd0fc).
//
// Test mapping:
//   TestIssueSigil               → testIssueSigil
//   TestIssueCap                 → testIssueCap
//   TestIssueAndVerifyAttestation → testIssueAndVerifyAttestation
//   TestVerifyCapScope           → testVerifyCapScope

import Testing
import Foundation
@testable import HankoCore

// MARK: - Helpers

private func makeBroker() throws -> (Broker, MemStore) {
    let (_, privateKey) = try Ed25519.generateKeyPair()
    let store = MemStore()
    return (Broker(store: store, privateKey: privateKey), store)
}

private func subjectKey() throws -> Data {
    let (pub, _) = try Ed25519.generateKeyPair()
    return pub
}

// MARK: - Tests

@Suite("Broker happy-path tests")
struct BrokerTests {

    /// Mirrors Go TestIssueSigil.
    @Test("IssueSigil creates sigil with expected fields")
    func testIssueSigil() async throws {
        let (broker, _) = try makeBroker()
        let pubKey = try subjectKey()

        let sigil = try await broker.issueSigil(
            subject: "operator:shikki@obyw.one",
            publicKey: pubKey,
            metadata: ["workspace": "obyw-one"]
        )

        #expect(!sigil.id.isEmpty, "sigil.id must not be empty")
        #expect(sigil.subject == "operator:shikki@obyw.one")
        #expect(sigil.expiresAt == nil, "long-lived operator sigil must have nil expiresAt")
        #expect(sigil.metadata["workspace"] == "obyw-one")
    }

    /// Mirrors Go TestIssueCap.
    @Test("IssueCap creates cap bound to sigil with 16-byte nonce")
    func testIssueCap() async throws {
        let (broker, _) = try makeBroker()
        let pubKey = try subjectKey()

        let sigil = try await broker.issueSigil(
            subject: "service:garage-s3",
            publicKey: pubKey
        )

        let cap = try await broker.issueCap(
            sigilID: sigil.id,
            scope: "garage:write:obyw-media",
            expiresAt: Date().addingTimeInterval(3600)
        )

        #expect(cap.sigilID == sigil.id)
        #expect(cap.nonce.count == 16, "nonce must be 16 bytes")
        #expect(cap.scope == "garage:write:obyw-media")
    }

    /// Mirrors Go TestIssueAndVerifyAttestation.
    @Test("IssueAttestation produces 64-byte signature; first verify passes")
    func testIssueAndVerifyAttestation() async throws {
        let (broker, _) = try makeBroker()
        let pubKey = try subjectKey()

        let sigil = try await broker.issueSigil(
            subject: "agent:shi-flow",
            publicKey: pubKey
        )

        let cap = try await broker.issueCap(
            sigilID: sigil.id,
            scope: "shi-flow:probe:read",
            expiresAt: Date().addingTimeInterval(3600)
        )

        let env = try await broker.issueAttestation(
            sigilID: sigil.id,
            caps: [cap],
            expiresAt: Date().addingTimeInterval(1800)
        )

        #expect(env.signature.count == 64, "Ed25519 signature must be 64 bytes")
        #expect(env.version == hankoVersion)

        // First verify should pass and consume the nonce.
        try await broker.verifyAttestation(env)
    }

    /// Mirrors Go TestVerifyCapScope.
    @Test("VerifyCapScope: exact match passes; mismatch throws scope_mismatch")
    func testVerifyCapScope() async throws {
        let cap = CapabilityToken(
            id: "33333333-3333-3333-3333-333333333333",
            sigilID: "11111111-1111-1111-1111-111111111111",
            scope: "garage:write:obyw-media",
            issuedAt: Date(),
            expiresAt: Date().addingTimeInterval(3600),
            nonce: Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        )

        // Exact match — must succeed.
        try Broker.verifyCapScope(cap, requestedAction: "garage:write:obyw-media")

        // Mismatch — must throw scope_mismatch.
        var caughtScopeMismatch = false
        do {
            try Broker.verifyCapScope(cap, requestedAction: "garage:write:obyw-backups")
        } catch let e as VerifyError where e.code == "scope_mismatch" {
            caughtScopeMismatch = true
        }
        #expect(caughtScopeMismatch, "expected scope_mismatch error for mismatched requestedAction")
    }
}
