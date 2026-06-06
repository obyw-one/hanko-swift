// Broker/Broker.swift — Hanko v0.1 issue / verify / revoke logic
//
// Mirrors Go's hanko/broker package (gh:FJ-Studios/hanko, commit b91dd0fc).
// For v0.1 the broker is stateless: callers inject a HankoStore for
// persistence and revocation checks. The Postgres-backed store ships in W4;
// v0.1 ships MemStore used by tests.
//
// Swift 6 concurrency: Broker is an actor. Store operations are async.

import CryptoKit
import Foundation

/// Orchestrates all Hanko protocol operations: issue / verify / revoke.
/// Mirrors Go's `broker.Broker` struct.
public actor Broker {

    private let store: any HankoStore
    private let signerPrivateKey: Curve25519.Signing.PrivateKey
    /// Raw 32-byte public key used for verification.
    public let signerPublicKey: Data

    /// Creates a Broker backed by the given store.
    /// signerPrivateKey is the issuer key used to sign AttestationEnvelopes.
    public init(store: any HankoStore, privateKey: Curve25519.Signing.PrivateKey) {
        self.store = store
        self.signerPrivateKey = privateKey
        self.signerPublicKey = privateKey.publicKey.rawRepresentation
    }

    // MARK: - IssueSigil

    /// Creates and persists a new Sigil.
    /// Mirrors Go's `broker.Broker.IssueSigil`.
    public func issueSigil(
        subject: String,
        publicKey: Data,
        expiresAt: Date? = nil,
        metadata: [String: String] = [:]
    ) async throws -> Sigil {
        let sigil = Sigil(
            id: UUID().uuidString.lowercased(),
            subject: subject,
            publicKey: publicKey,
            createdAt: Date(),
            expiresAt: expiresAt,
            metadata: metadata
        )
        try await store.saveSigil(sigil)
        return sigil
    }

    // MARK: - IssueCap

    /// Creates and persists a CapabilityToken bound to sigilID.
    /// Mirrors Go's `broker.Broker.IssueCap`.
    public func issueCap(
        sigilID: String,
        scope: String,
        expiresAt: Date
    ) async throws -> CapabilityToken {
        // Verify the sigil exists.
        _ = try await store.getSigil(sigilID)
        let cap = CapabilityToken(
            id: UUID().uuidString.lowercased(),
            sigilID: sigilID,
            scope: scope,
            issuedAt: Date(),
            expiresAt: expiresAt,
            nonce: Ed25519.generateNonce()
        )
        try await store.saveCap(cap)
        return cap
    }

    // MARK: - IssueAttestation

    /// Creates a signed AttestationEnvelope for sigilID carrying the given caps.
    /// The signature covers the canonical JSON body (all fields except "signature")
    /// per spec §2.1 and wire-format.md.
    ///
    /// Mirrors Go's `broker.Broker.IssueAttestation`.
    public func issueAttestation(
        sigilID: String,
        caps: [CapabilityToken],
        expiresAt: Date
    ) async throws -> AttestationEnvelope {
        let now = Date()
        // Build a temporary envelope without signature to compute the body.
        var env = AttestationEnvelope(
            version: hankoVersion,
            sigilID: sigilID,
            caps: caps,
            issuer: issuerName,
            issuedAt: now,
            expiresAt: expiresAt,
            signature: Data()
        )

        let body = try envelopeBody(env)
        let signature = try Ed25519.sign(body: body, privateKey: signerPrivateKey)
        env.signature = signature
        return env
    }

    // MARK: - VerifyAttestation

    /// Fully validates an AttestationEnvelope. Mirrors Go's `broker.Broker.VerifyAttestation`.
    ///
    /// Verification order (matches Go):
    ///   1. Signature valid          → HankoError.signatureInvalid (exit 1)
    ///   2. Sigil not revoked        → HankoError.sigilRevoked     (exit 2)
    ///   3. Envelope not expired     → HankoError.capExpired       (exit 3)
    ///   4. Each cap not expired     → HankoError.capExpired       (exit 3)
    ///   5. Each cap nonce not used  → HankoError.nonceReplayed    (exit 1)
    ///
    /// On success, nonces are consumed (one-time-use per OQ-4).
    public func verifyAttestation(_ env: AttestationEnvelope) async throws {
        // 1. Signature check.
        let body = try envelopeBody(env)
        do {
            try Ed25519.verify(body: body, signature: env.signature, publicKey: signerPublicKey)
        } catch {
            throw HankoError.signatureInvalid
        }

        // 2. Revocation check on the root sigil.
        let rl = await store.revocationList()
        for entry in rl.entries where entry.targetType == "sigil" && entry.id == env.sigilID {
            throw HankoError.sigilRevoked
        }

        // 3. Envelope expiry.
        if Date() > env.expiresAt {
            throw HankoError.capExpired
        }

        // 4+5. Per-cap checks.
        for cap in env.caps {
            if Date() > cap.expiresAt {
                throw HankoError.capExpired
            }
            if await store.nonceUsed(cap.nonce) {
                throw HankoError.nonceReplayed
            }
        }

        // All checks passed — consume nonces (OQ-4: per-token one-time-use).
        for cap in env.caps {
            await store.recordNonce(cap.nonce)
        }
    }

    // MARK: - VerifyCapScope

    /// Checks that a CapabilityToken's scope covers requestedAction.
    /// Scope matching is exact for v0.1 (prefix/wildcard deferred to v0.2).
    /// Mirrors Go's `broker.VerifyCapScope`.
    public static func verifyCapScope(_ cap: CapabilityToken, requestedAction: String) throws {
        guard cap.scope == requestedAction else {
            throw HankoError.scopeMismatch
        }
    }

    // MARK: - RevokeSigil

    /// Adds a revocation entry for sigilID.
    /// Mirrors Go's `broker.Broker.RevokeSigil`.
    public func revokeSigil(sigilID: String, reason: String, revokedBy: String) async throws {
        let entry = RevocationEntry(
            id: sigilID, // Re-use target sigil's UUID as the entry ID for direct lookup (matches Go).
            targetType: "sigil",
            reason: reason,
            revokedAt: Date(),
            revokedBy: revokedBy
        )
        try await store.revoke(entry)
    }
}

// MARK: - Internal helpers

/// Converts an AttestationEnvelope to a [String: Any] map without the
/// "signature" key, ready for canonical JSON signing.
/// Mirrors Go's `broker.envelopeBody`.
private func envelopeBody(_ env: AttestationEnvelope) throws -> [String: Any] {
    let encoder = makeHankoEncoder()
    let data = try encoder.encode(env)
    guard var dict = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
        throw BrokerError.serializationFailed("envelopeBody: expected JSON object")
    }
    dict.removeValue(forKey: "signature")
    return dict
}

/// Broker-specific errors.
public enum BrokerError: Error {
    case serializationFailed(String)
    case keyError(String)
}
