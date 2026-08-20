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
        let granted = tokens
        let req = requested.tokens
        var gi = 0
        var ri = 0
        while gi < granted.count {
            let token = granted[gi]
            if token == "**" {
                // Greedy: consumes the rest of the requested scope.
                return true
            }
            guard ri < req.count else { return false }
            if token == "*" || token == req[ri] {
                gi += 1
                ri += 1
                continue
            }
            return false
        }
        // End of granted: every requested token must also be consumed.
        return ri == req.count
    }
}
