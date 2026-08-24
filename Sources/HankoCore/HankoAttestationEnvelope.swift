// HankoAttestationEnvelope.swift
// HankoCore — Hanko v0.1 wrapper signed envelope.
//
// Mirrors protocol/types.go `AttestationEnvelope` from gh:FJ-Studios/hanko.
//
// Spec: hanko-v0.1-protocol §2.1 — the AttestationEnvelope wraps a Sigil with
// its bound CapabilityTokens, an issuer identity, expiry, and a detached
// Ed25519 signature over the canonical JSON body (signature field omitted).

import Foundation

// MARK: - HankoAttestationEnvelope

/// A signed wrapper binding a Sigil + capability tokens + issuer + expiry.
///
/// The verifier checks: (1) the signature over the canonical JSON body
/// (with the `signature` field removed), (2) `expires_at > now`, (3) the
/// signing Sigil and its caps are not on the RevocationList, (4) the
/// requested scope matches one of the granted caps, (5) the audience
/// matches.
///
/// Wire format: canonical JSON (RFC 8785 key ordering, RFC3339 timestamps,
/// base64-std for signature).
///
/// Mirrors protocol/types.go `AttestationEnvelope`.
public struct HankoAttestationEnvelope: Sendable, Codable, Equatable {
    /// Protocol version, e.g. "hanko/v0.1".
    public let version: String
    /// UUID of the signing Sigil (the principal asserting these caps).
    public let sigilID: String
    /// CapabilityTokens granted within this envelope.
    public let caps: [HankoCapabilityToken]
    /// Issuer identity (e.g. "hanko-broker@obyw.one").
    public let issuer: String
    /// Issue timestamp (RFC3339).
    public let issuedAt: Date
    /// Expiry timestamp (RFC3339) — always set.
    public let expiresAt: Date
    /// Ed25519 signature over the canonical JSON body (excluding `signature`
    /// field itself). Base64-std encoded. Empty during signing, populated
    /// post-sign.
    public let signature: Data

    public init(
        version: String = HankoProtocolVersion,
        sigilID: String,
        caps: [HankoCapabilityToken],
        issuer: String,
        issuedAt: Date,
        expiresAt: Date,
        signature: Data = Data()
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

    /// Wire interop with the Go reference: the signed canonical body omits
    /// the `signature` key entirely (spec §2.1 — deleted prior to signing),
    /// so an empty signature is not encoded. An absent signature decodes as
    /// empty, matching pre-sign envelopes.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        sigilID = try c.decode(String.self, forKey: .sigilID)
        caps = try c.decode([HankoCapabilityToken].self, forKey: .caps)
        issuer = try c.decode(String.self, forKey: .issuer)
        issuedAt = try c.decode(Date.self, forKey: .issuedAt)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        signature = try c.decodeIfPresent(Data.self, forKey: .signature) ?? Data()
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(version, forKey: .version)
        try c.encode(sigilID, forKey: .sigilID)
        try c.encode(caps, forKey: .caps)
        try c.encode(issuer, forKey: .issuer)
        try c.encode(issuedAt, forKey: .issuedAt)
        try c.encode(expiresAt, forKey: .expiresAt)
        if !signature.isEmpty {
            try c.encode(signature, forKey: .signature)
        }
    }

    /// True when this envelope has passed its expiry.
    public var isExpired: Bool {
        expiresAt < Date()
    }

    /// True when this envelope is currently valid (not expired).
    public var isValid: Bool {
        !isExpired
    }

    /// Returns a copy of this envelope with the signature field removed,
    /// for canonical-JSON signature computation.
    ///
    /// Per spec §2.1: the signed body is the canonical JSON of the envelope
    /// with the `signature` field deleted from the map prior to signing.
    public func unsignedBody() -> HankoAttestationEnvelope {
        HankoAttestationEnvelope(
            version: version,
            sigilID: sigilID,
            caps: caps,
            issuer: issuer,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signature: Data()
        )
    }
}
