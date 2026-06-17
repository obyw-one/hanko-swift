// HankoVerifier.swift
// HankoBroker — Attestation verification orchestrator.
//
// Mirrors broker/verifier.go (Go ref impl).
//
// Verification pipeline (in order, fail-fast):
//   1. Envelope expiry: envelope.expires_at > now
//   2. Signature: Ed25519.verify(canonical_body, signature, signer_pubkey)
//   3. Sigil revocation: not in revocation list
//   4. Each cap: not expired, not revoked, audience match
//   5. Requested scope: matches at least one cap's scope
//   6. Nonce replay: cap.nonce not previously observed
//
// On any failure: throws HankoVerifyError with the structured code.

import Foundation
import HankoCore
import HankoCrypto

// MARK: - HankoVerifier

public actor HankoVerifier {

    public let store: any HankoStore
    public let nonceCache: HankoNonceCache

    public init(store: any HankoStore, nonceCache: HankoNonceCache = HankoNonceCache()) {
        self.store = store
        self.nonceCache = nonceCache
    }

    // MARK: Verify

    public enum Outcome: Sendable {
        case ok(HankoSigil)
        case denied(HankoVerifyError)
    }

    /// Verify an attestation envelope against a requested scope + audience.
    ///
    /// - Parameters:
    ///   - envelope: The signed envelope to verify.
    ///   - requestedScope: The scope the caller is asking authorization for.
    ///   - audience: The expected audience (e.g. "sigma-backend@majeluce.com").
    /// - Returns: `.ok(signing Sigil)` if everything checks out, else
    ///   `.denied(error)` with the structured reason.
    public func verify(
        envelope: HankoAttestationEnvelope,
        requestedScope: String,
        audience: String
    ) async throws -> Outcome {
        // TODO(W3.2): Implement the full pipeline.
        //
        // Reference (Go) — broker/verifier.go:
        //
        //   1. if envelope.IsExpired() { return .denied(.capExpired) }
        //
        //   2. let sigil = try await store.sigil(byID: envelope.sigilID)
        //      guard let sigil else { return .denied(.unknown("sigil_unknown")) }
        //      let body = try HankoCanonicalJSON.encode(envelope.unsignedBody())
        //      do { try HankoEd25519.verify(signature: envelope.signature, message: body, publicKey: sigil.publicKey) }
        //      catch { return .denied(.signatureInvalid) }
        //
        //   3. if try await store.isRevoked(sigil.id) { return .denied(.sigilRevoked) }
        //
        //   4. for cap in envelope.caps {
        //        if cap.isExpired { return .denied(.capExpired) }
        //        if try await store.isRevoked(cap.id) { return .denied(.sigilRevoked) }
        //        if cap.audience != audience { return .denied(.audienceMismatch(...)) }
        //        let isNew = await nonceCache.observe(cap.nonce)
        //        if !isNew { return .denied(.nonceReplayed) }
        //      }
        //
        //   5. let req = HankoScope(requestedScope)
        //      let granted = envelope.caps.first { HankoScope($0.scope).matches(req) }
        //      guard granted != nil else { return .denied(.scopeMismatch(requested: requestedScope, granted: ...)) }
        //
        //   6. return .ok(sigil)
        //
        fatalError("HankoVerifier.verify: not yet implemented (W3.2 sprint)")
    }
}
