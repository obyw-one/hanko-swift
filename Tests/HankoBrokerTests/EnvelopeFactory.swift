// EnvelopeFactory.swift
// Shared helpers for building signed test envelopes.

import Foundation
@testable import HankoBroker
@testable import HankoCore
@testable import HankoCrypto

/// A fully-wired verification scenario: a registered Sigil, its signed
/// envelope, the backing store, and a verifier over that store.
struct TestScenario {
    let envelope: HankoAttestationEnvelope
    let sigil: HankoSigil
    let privateKey: Data
    let store: InMemoryHankoStore
    let verifier: HankoVerifier
}

enum EnvelopeFactory {
    static let defaultAudience = "sigma-backend@majeluce.com"

    static func randomNonce() -> Data {
        HankoNonce.generate()
    }

    /// Build a signed envelope with one capability and register its Sigil.
    static func make(
        scope: String = "sigma:portfolio:read",
        audience: String = defaultAudience,
        capExpiresIn: TimeInterval = 3600,
        envelopeExpiresIn: TimeInterval = 3600
    ) async throws -> TestScenario {
        let (pub, priv) = HankoEd25519.generateKeyPair()
        let sigil = HankoSigil(
            id: UUID().uuidString.lowercased(),
            subject: "client:test@sigma",
            publicKey: pub,
            createdAt: Date()
        )
        let store = InMemoryHankoStore()
        await store.register(sigil)

        let now = Date()
        let cap = HankoCapabilityToken(
            id: UUID().uuidString.lowercased(),
            sigilID: sigil.id,
            scope: scope,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(capExpiresIn),
            nonce: randomNonce(),
            audience: audience
        )
        let unsigned = HankoAttestationEnvelope(
            sigilID: sigil.id,
            caps: [cap],
            issuer: "hanko-broker@obyw.one",
            issuedAt: now,
            expiresAt: now.addingTimeInterval(envelopeExpiresIn)
        )
        let body = try HankoCanonicalJSON.encode(unsigned.unsignedBody())
        let signature = try HankoEd25519.sign(body, privateKey: priv)
        let envelope = HankoAttestationEnvelope(
            sigilID: unsigned.sigilID,
            caps: unsigned.caps,
            issuer: unsigned.issuer,
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            signature: signature
        )
        return TestScenario(
            envelope: envelope,
            sigil: sigil,
            privateKey: priv,
            store: store,
            verifier: HankoVerifier(store: store)
        )
    }
}
