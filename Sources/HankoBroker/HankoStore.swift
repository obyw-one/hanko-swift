// HankoStore.swift
// HankoBroker — Persistence abstraction for Sigils + revocation list.
//
// Mirrors store/mem.go (Go ref impl) for the in-memory variant.
// Postgres impl deferred to W4-Swift (matches Go's W4 milestone).

import Foundation
import HankoCore

// MARK: - HankoStore

/// Persistence abstraction for Hanko broker state.
///
/// Implementations must be Sendable and concurrency-safe (actor or internal
/// locking). The verifier calls these methods on every attestation check.
public protocol HankoStore: Sendable {
    // MARK: Sigil lookup

    /// Return the registered Sigil for a given ID, or nil if unknown.
    func sigil(byID id: String) async throws -> HankoSigil?

    // MARK: Revocation

    /// Returns true if the given Sigil or CapabilityToken ID is on the
    /// revocation list.
    ///
    /// - Parameter id: A Sigil ID, CapabilityToken ID, or AttestationEnvelope ID.
    func isRevoked(_ id: String) async throws -> Bool

    /// Append a revocation entry to the list.
    func revoke(_ entry: HankoRevocationEntry) async throws
}

// MARK: - InMemoryHankoStore

/// In-memory implementation of `HankoStore`. Suitable for tests and small
/// single-process deployments. NOT suitable for production multi-node setups.
public actor InMemoryHankoStore: HankoStore {
    private var sigils: [String: HankoSigil] = [:]
    private var revoked: Set<String> = []

    public init() {}

    public func register(_ sigil: HankoSigil) {
        sigils[sigil.id] = sigil
    }

    public func sigil(byID id: String) async throws -> HankoSigil? {
        sigils[id]
    }

    public func isRevoked(_ id: String) async throws -> Bool {
        revoked.contains(id)
    }

    public func revoke(_ entry: HankoRevocationEntry) async throws {
        // In-mem variant: the id set is sufficient. A real append-only
        // revocation log arrives with the persistent store (W4 milestone).
        revoked.insert(entry.id)
    }
}
