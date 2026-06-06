// Protocol/Types.swift — Hanko v0.1 wire types (Swift reference implementation)
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own pre-existing internal
// codename, conceived independently. The German startup teamhanko/hanko
// (a passkey/passwordless auth project, AGPL-3, first commit 2022) is a
// completely unrelated third-party project. There is zero code, dependency, or
// design inheritance between this codebase and teamhanko/hanko. The phonetic
// choice (Mo-to / Han-ko) was operator-intentional; the collision is irrelevant
// because Hanko is not customer-facing. This codebase is NOT customer-facing.
//
// Wire format: canonical JSON (RFC 8785 key ordering, RFC3339 timestamps,
// base64-standard encoding for binary fields). See CanonicalJSON.swift.
//
// Parity target: gh:FJ-Studios/hanko (Go reference implementation, commit b91dd0fc)

import Foundation

// MARK: - Protocol version

/// The Hanko protocol version string embedded in every AttestationEnvelope.
/// Must match the Go constant `protocol.Version`.
public let hankoVersion = "hanko/v0.1"

/// The canonical issuer string embedded in AttestationEnvelopes.
/// Must match the Go constant `broker.IssuerName`.
public let issuerName = "hanko-broker@obyw.one"

// MARK: - Sigil

/// A stable, cryptographically-bound identity assertion for an operator, agent,
/// or service. The id is stable across renewals.
///
/// Wire format: canonical JSON, binary fields base64-standard encoded.
public struct Sigil: Codable, Sendable {
    /// Stable UUID across renewals.
    public var id: String
    /// e.g. "operator:shikki@obyw.one", "agent:shi-flow", "service:garage-s3"
    public var subject: String
    /// Ed25519 public key (32 bytes), base64-standard encoded on the wire.
    public var publicKey: Data
    /// RFC3339 UTC timestamp.
    public var createdAt: Date
    /// nil = long-lived operator sigil (revocable via RevokeSigil).
    public var expiresAt: Date?
    /// Arbitrary metadata, e.g. {"workspace": "obyw-one", "tier": "operator"}.
    public var metadata: [String: String]

    public init(
        id: String,
        subject: String,
        publicKey: Data,
        createdAt: Date,
        expiresAt: Date? = nil,
        metadata: [String: String] = [:]
    ) {
        self.id = id
        self.subject = subject
        self.publicKey = publicKey
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.metadata = metadata
    }

    enum CodingKeys: String, CodingKey {
        case id
        case subject
        case publicKey = "public_key"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case metadata
    }
}

// MARK: - CapabilityToken

/// A scoped, time-bounded authorization grant tied to a Sigil.
/// The nonce provides replay protection (per-token one-time-use, per OQ-4).
///
/// Per spec §2.1: expiresAt is ALWAYS bounded — no immortal cap tokens.
public struct CapabilityToken: Codable, Sendable {
    /// UUID.
    public var id: String
    /// UUID of the bound Sigil.
    public var sigilID: String
    /// e.g. "shi-secrets:read:ns/key", "garage:write:obyw-media"
    public var scope: String
    /// RFC3339 UTC.
    public var issuedAt: Date
    /// RFC3339 UTC — always set; no immortal cap tokens.
    public var expiresAt: Date
    /// 16 random bytes for replay protection (base64-standard on the wire).
    public var nonce: Data

    public init(
        id: String,
        sigilID: String,
        scope: String,
        issuedAt: Date,
        expiresAt: Date,
        nonce: Data
    ) {
        self.id = id
        self.sigilID = sigilID
        self.scope = scope
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.nonce = nonce
    }

    enum CodingKeys: String, CodingKey {
        case id
        case sigilID = "sigil_id"
        case scope
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case nonce
    }
}

// MARK: - AttestationEnvelope

/// A signed wrapper binding a Sigil + capability list + issuer + expiry into a
/// single verifiable unit.
///
/// The signature covers the canonical JSON of all fields except "signature"
/// itself, per spec §2.1 and wire-format.md.
public struct AttestationEnvelope: Codable, Sendable {
    /// Protocol version string, always "hanko/v0.1".
    public var version: String
    /// UUID of the root Sigil.
    public var sigilID: String
    /// Capability list bound to this attestation.
    public var caps: [CapabilityToken]
    /// Canonical issuer, always "hanko-broker@obyw.one".
    public var issuer: String
    /// RFC3339 UTC.
    public var issuedAt: Date
    /// RFC3339 UTC.
    public var expiresAt: Date
    /// Ed25519 signature (64 bytes) over canonical JSON body excluding this field.
    /// base64-standard encoded on the wire.
    public var signature: Data

    public init(
        version: String = hankoVersion,
        sigilID: String,
        caps: [CapabilityToken],
        issuer: String = issuerName,
        issuedAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.version = version
        self.sigilID = sigilID
        self.caps = caps
        self.issuer = issuer
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.signature = signature
    }

    enum CodingKeys: String, CodingKey {
        case version
        case sigilID = "sigil_id"
        case caps
        case issuer
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case signature
    }
}

// MARK: - RevocationList

/// An append-only log of revoked Sigils and capability tokens.
/// Pull model for v0.1; push (NATS) deferred to v0.2 per spec §9 / OQ-3.
public struct RevocationList: Codable, Sendable {
    public var entries: [RevocationEntry]

    public init(entries: [RevocationEntry] = []) {
        self.entries = entries
    }
}

/// A single revocation record.
public struct RevocationEntry: Codable, Sendable {
    /// UUID of the revoked entity (sigil, cap, or attestation).
    public var id: String
    /// "sigil" | "cap" | "attestation"
    public var targetType: String
    /// Human-readable revocation reason.
    public var reason: String
    /// RFC3339 UTC.
    public var revokedAt: Date
    /// UUID of the issuer sigil that performed the revocation.
    public var revokedBy: String

    public init(
        id: String,
        targetType: String,
        reason: String = "",
        revokedAt: Date,
        revokedBy: String
    ) {
        self.id = id
        self.targetType = targetType
        self.reason = reason
        self.revokedAt = revokedAt
        self.revokedBy = revokedBy
    }

    enum CodingKeys: String, CodingKey {
        case id
        case targetType = "target_type"
        case reason
        case revokedAt = "revoked_at"
        case revokedBy = "revoked_by"
    }
}

// MARK: - VerifyError

/// Structured denial from the broker. Matches Go's protocol.VerifyError.
public struct VerifyError: Error, Sendable, CustomStringConvertible {
    /// Machine-readable code, e.g. "capability_expired". Matches Go sentinel codes.
    public let code: String
    /// Human-readable message.
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }

    public var description: String { "\(code): \(message)" }
}

// MARK: - Sentinel errors (matching Go broker sentinel values)

public enum HankoError {
    public static let signatureInvalid = VerifyError(
        code: "signature_invalid",
        message: "attestation signature does not match canonical JSON body"
    )
    public static let sigilRevoked = VerifyError(
        code: "sigil_revoked",
        message: "sigil has been revoked"
    )
    public static let capExpired = VerifyError(
        code: "capability_expired",
        message: "capability token is expired"
    )
    public static let nonceReplayed = VerifyError(
        code: "nonce_replayed",
        message: "capability token nonce has already been used"
    )
    public static let scopeMismatch = VerifyError(
        code: "scope_mismatch",
        message: "capability token scope does not cover the requested action"
    )
}
