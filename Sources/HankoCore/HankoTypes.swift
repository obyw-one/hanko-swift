// HankoTypes.swift
// HankoCore — Hanko v0.1 Swift wire types.
//
// Mirrors protocol/types.go from gh:FJ-Studios/hanko exactly.
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own internal codename.
// Not related to teamhanko/hanko (passkey project). See package PROVENANCE.
//
// Spec: hanko-v0.1-protocol (§2 wire types)
// Version: hanko/v0.1

import CryptoKit
import Foundation

// MARK: - Protocol Version

public let HankoProtocolVersion = "hanko/v0.1"

// MARK: - HankoSigil

/// A stable, cryptographically-bound identity assertion for an operator,
/// agent, or service. The id is stable across renewals.
///
/// Wire format: canonical JSON (RFC 8785 key ordering, RFC3339 timestamps,
/// base64url-no-padding for publicKey).
///
/// Mirrors protocol/types.go `Sigil`.
public struct HankoSigil: Sendable, Codable, Equatable {
    /// UUID — stable across key rotations.
    public let id: String
    /// Human-readable subject (e.g. "operator:shikki@obyw.one").
    public let subject: String
    /// Ed25519 public key bytes (32 bytes).
    public let publicKey: Data
    /// Creation timestamp.
    public let createdAt: Date
    /// Expiry — nil for long-lived operator sigils.
    public let expiresAt: Date?
    /// Arbitrary string metadata (e.g. workspace, environment).
    public let metadata: [String: String]

    public init(
        id: String,
        subject: String,
        publicKey: Data,
        createdAt: Date,
        expiresAt: Date? = nil,
        metadata: [String: String] = [:]
    ) {
        self.id         = id
        self.subject    = subject
        self.publicKey  = publicKey
        self.createdAt  = createdAt
        self.expiresAt  = expiresAt
        self.metadata   = metadata
    }

    enum CodingKeys: String, CodingKey {
        case id
        case subject
        case publicKey  = "public_key"
        case createdAt  = "created_at"
        case expiresAt  = "expires_at"
        case metadata
    }

    /// SHA-256 fingerprint of the public key bytes (first 16 hex chars for display).
    public var fingerprint: String {
        let hash = SHA256.hash(data: publicKey)
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    /// Short display fingerprint (first 16 hex chars).
    public var shortFingerprint: String {
        String(fingerprint.prefix(16))
    }
}

// MARK: - HankoCapabilityToken

/// A scoped, time-bounded authorization grant tied to a HankoSigil.
/// The nonce provides replay protection (per-token one-time-use, per spec §10 OQ-4).
///
/// Per spec §2.1: expiresAt is ALWAYS bounded — no immortal cap tokens.
///
/// Mirrors protocol/types.go `CapabilityToken`.
public struct HankoCapabilityToken: Sendable, Codable, Equatable {
    /// UUID.
    public let id: String
    /// UUID of the bound HankoSigil.
    public let sigilID: String
    /// Scope string (e.g. "ai-worker:obyw-one", "shi-secrets:read:ns/key").
    public let scope: String
    /// Issue time.
    public let issuedAt: Date
    /// Expiry — always set (no immortal tokens).
    public let expiresAt: Date
    /// 16 random bytes for replay protection.
    public let nonce: Data
    /// Audience identifier (e.g. "hanko-broker@obyw.one", NATS subject prefix).
    public let audience: String

    public init(
        id: String,
        sigilID: String,
        scope: String,
        issuedAt: Date,
        expiresAt: Date,
        nonce: Data,
        audience: String
    ) {
        self.id        = id
        self.sigilID   = sigilID
        self.scope     = scope
        self.issuedAt  = issuedAt
        self.expiresAt = expiresAt
        self.nonce     = nonce
        self.audience  = audience
    }

    enum CodingKeys: String, CodingKey {
        case id
        case sigilID   = "sigil_id"
        case scope
        case issuedAt  = "issued_at"
        case expiresAt = "expires_at"
        case nonce
        case audience
    }

    /// Wire interop with the Go reference (protocol/types.go), whose
    /// CapabilityToken has no `audience` field yet: an absent audience
    /// decodes as "", and an empty audience is omitted on encode so
    /// canonical bodies stay byte-compatible with Go-issued tokens.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id        = try c.decode(String.self, forKey: .id)
        sigilID   = try c.decode(String.self, forKey: .sigilID)
        scope     = try c.decode(String.self, forKey: .scope)
        issuedAt  = try c.decode(Date.self, forKey: .issuedAt)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        nonce     = try c.decode(Data.self, forKey: .nonce)
        audience  = try c.decodeIfPresent(String.self, forKey: .audience) ?? ""
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id,        forKey: .id)
        try c.encode(sigilID,   forKey: .sigilID)
        try c.encode(scope,     forKey: .scope)
        try c.encode(issuedAt,  forKey: .issuedAt)
        try c.encode(expiresAt, forKey: .expiresAt)
        try c.encode(nonce,     forKey: .nonce)
        if !audience.isEmpty {
            try c.encode(audience, forKey: .audience)
        }
    }

    /// True when this token has passed its expiry.
    public var isExpired: Bool {
        expiresAt < Date()
    }

    /// True when this token is currently valid (not expired).
    public var isValid: Bool {
        !isExpired
    }

    /// Human-readable expiry label.
    public var expiryLabel: String {
        if isExpired { return "Expired" }
        let remaining = expiresAt.timeIntervalSinceNow
        if remaining < 60 { return "< 1 min" }
        if remaining < 3600 { return "\(Int(remaining / 60))m" }
        return "\(Int(remaining / 3600))h"
    }
}

// MARK: - HankoRevocationEntry

/// Records a single revoked entity (sigil or cap token).
///
/// Mirrors protocol/types.go `RevocationEntry`.
public struct HankoRevocationEntry: Sendable, Codable, Equatable {
    /// UUID of the revoked entity.
    public let id: String
    /// "sigil" | "cap" | "attestation"
    public let targetType: String
    /// Human-readable reason.
    public let reason: String?
    /// When the entity was revoked.
    public let revokedAt: Date
    /// UUID of the issuer sigil that performed the revocation.
    public let revokedBy: String

    public init(
        id: String,
        targetType: String,
        reason: String?,
        revokedAt: Date,
        revokedBy: String
    ) {
        self.id         = id
        self.targetType = targetType
        self.reason     = reason
        self.revokedAt  = revokedAt
        self.revokedBy  = revokedBy
    }

    enum CodingKeys: String, CodingKey {
        case id
        case targetType = "target_type"
        case reason
        case revokedAt  = "revoked_at"
        case revokedBy  = "revoked_by"
    }
}

// MARK: - HankoVerifyError

/// Structured denial from the Hanko verifier.
///
/// Mirrors protocol/types.go `VerifyError` + sentinel values.
public enum HankoVerifyError: Error, Sendable, Equatable {
    case signatureInvalid
    case sigilRevoked
    case capExpired
    case nonceReplayed
    case scopeMismatch(requested: String, granted: String)
    case audienceMismatch(requested: String, issued: String)
    case unknown(String)

    public var code: String {
        switch self {
        case .signatureInvalid:             return "signature_invalid"
        case .sigilRevoked:                 return "sigil_revoked"
        case .capExpired:                   return "capability_expired"
        case .nonceReplayed:                return "nonce_replayed"
        case .scopeMismatch:                return "scope_mismatch"
        case .audienceMismatch:             return "audience_mismatch"
        case .unknown(let c):               return c
        }
    }
}
