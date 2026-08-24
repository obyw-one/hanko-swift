// HankoNonceCache.swift
// HankoBroker — In-memory anti-replay cache for nonces.
//
// Mirrors broker/nonce_cache.go (Go ref impl).
//
// Per spec §10 OQ-4: each capability token nonce is one-time-use. The
// verifier maintains a cache of recently-seen nonces and rejects any that
// have already been observed (subject to a sliding TTL window).

import Foundation

// MARK: - HankoNonceCache

/// In-memory TTL-bounded cache for nonces.
///
/// - Insert nonces as they are observed.
/// - Reject nonces that have been previously inserted.
/// - Expire entries after the TTL window to bound memory growth.
public actor HankoNonceCache {

    private var seen: [Data: Date] = [:]
    public let ttl: TimeInterval

    public init(ttl: TimeInterval = 3600) {
        self.ttl = ttl
    }

    /// Insert a nonce. Returns true if it was new, false if it was already
    /// seen (replay detected).
    public func observe(_ nonce: Data) -> Bool {
        evictExpired()
        if seen[nonce] != nil { return false }
        seen[nonce] = Date()
        return true
    }

    /// Evict expired entries. Called lazily on each observe.
    private func evictExpired() {
        let cutoff = Date().addingTimeInterval(-ttl)
        seen = seen.filter { $0.value >= cutoff }
    }
}
