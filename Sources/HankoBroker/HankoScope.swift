// HankoScope.swift
// HankoBroker — Scope string parsing and matching.
//
// Mirrors broker/scope.go (Go ref impl).
//
// Scope format: colon-separated tokens, e.g.:
//   - "sigma:portfolio:read"
//   - "shi-secrets:read:ns/key"
//   - "sigma:*:read"        — wildcard at one level
//   - "sigma:**"            — wildcard for remainder (greedy)
//
// Match semantics: a requested scope matches a granted scope if every
// token in the granted scope either matches the corresponding requested
// token, equals "*" (wildcard one level), or is "**" (wildcard all
// remaining levels).

import Foundation

// MARK: - HankoScope

public struct HankoScope: Hashable, Sendable, CustomStringConvertible {
    public let raw: String
    public let tokens: [String]

    public init(_ raw: String) {
        self.raw = raw
        self.tokens = raw.split(separator: ":").map(String.init)
    }

    public var description: String { raw }

    /// True if this scope (treated as granted) matches the requested scope.
    ///
    /// Examples:
    ///   - `sigma:portfolio:*` matches `sigma:portfolio:read` → true
    ///   - `sigma:**` matches `sigma:portfolio:export:bulk` → true
    ///   - `sigma:portfolio:read` matches `sigma:portfolio:write` → false
    ///   - `sigma:*` matches `sigma:portfolio:read` → false (needs `**`)
    public func matches(_ requested: HankoScope) -> Bool {
        // TODO(W3.2): Implement.
        //   Walk granted tokens against requested tokens:
        //   - "**" at position i: consume rest of requested, return true
        //   - "*"  at position i: requested[i] must exist, advance both
        //   - literal: must equal requested[i], advance both
        //   - end of granted: all requested must also have been consumed
        fatalError("HankoScope.matches: not yet implemented (W3.2 sprint)")
    }
}
