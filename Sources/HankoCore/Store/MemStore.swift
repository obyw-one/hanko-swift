// Store/MemStore.swift — Thread-safe in-memory Hanko store
//
// Mirrors Go's store.MemStore (gh:FJ-Studios/hanko).
// Used by tests and demos. The Postgres-backed implementation ships in W4.

import Foundation

/// Minimal persistence interface the broker requires.
/// Mirrors Go's `broker.Store` interface.
/// All methods are async to support actor-isolated implementations.
public protocol HankoStore: Sendable {
    func saveSigil(_ sigil: Sigil) async throws
    func getSigil(_ id: String) async throws -> Sigil
    func saveCap(_ cap: CapabilityToken) async throws
    func getCap(_ id: String) async throws -> CapabilityToken
    func nonceUsed(_ nonce: Data) async -> Bool
    func recordNonce(_ nonce: Data) async
    func revocationList() async -> RevocationList
    func revoke(_ entry: RevocationEntry) async throws
}

/// Thread-safe in-memory Hanko store.
/// Swift 6 concurrency: protected by an actor.
public actor MemStore: HankoStore {
    private var sigils: [String: Sigil] = [:]
    private var caps: [String: CapabilityToken] = [:]
    private var revList: RevocationList = RevocationList()
    /// Hex-encoded nonce strings that have been consumed.
    private var usedNonces: Set<String> = []

    public init() {}

    public func saveSigil(_ sigil: Sigil) async throws {
        sigils[sigil.id] = sigil
    }

    public func getSigil(_ id: String) async throws -> Sigil {
        guard let sigil = sigils[id] else {
            throw StoreError.notFound("sigil \(id) not found")
        }
        return sigil
    }

    public func saveCap(_ cap: CapabilityToken) async throws {
        caps[cap.id] = cap
    }

    public func getCap(_ id: String) async throws -> CapabilityToken {
        guard let cap = caps[id] else {
            throw StoreError.notFound("cap \(id) not found")
        }
        return cap
    }

    public func nonceUsed(_ nonce: Data) async -> Bool {
        usedNonces.contains(nonce.hexString)
    }

    public func recordNonce(_ nonce: Data) async {
        usedNonces.insert(nonce.hexString)
    }

    public func revocationList() async -> RevocationList {
        revList
    }

    public func revoke(_ entry: RevocationEntry) async throws {
        revList.entries.append(entry)
    }
}

/// Store errors.
public enum StoreError: Error {
    case notFound(String)
}

// MARK: - Data hex helper

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
