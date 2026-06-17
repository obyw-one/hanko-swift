// HankoCanonicalJSON.swift
// HankoCrypto — RFC 8785 canonical JSON serialization.
//
// Mirrors crypto/canonical.go (Go ref impl).
//
// Spec: RFC 8785 (JSON Canonicalization Scheme — JCS)
//   - Lexicographic UTF-16 key ordering at every object level
//   - No whitespace between tokens
//   - Number serialization per IEEE 754 (no leading zeros, no trailing zeros
//     in fractional, exponent notation when |x| ≥ 1e21 or |x| < 1e-6)
//   - String escape: minimal — only \" \\ control chars (\u00..\u1f) and
//     . Other Unicode passed through as UTF-8.
//   - Timestamps RFC3339 with 'T' separator and 'Z' for UTC.
//
// This is the most delicate piece of the HankoSwift impl. Byte parity with
// `crypto/canonical.go` Go is REQUIRED. Tests against `canonical-json.json`
// parity vectors MUST pass.

import Foundation
import HankoCore

// MARK: - HankoCanonicalJSON

public enum HankoCanonicalJSON {

    // MARK: Errors

    public enum Error: Swift.Error, Sendable, Equatable {
        case unsupportedType(String)
        case invalidNumber(Double)
        case invalidUTF8
    }

    // MARK: API

    /// Canonicalize a JSON-compatible value (dict / array / string / number /
    /// bool / null) into RFC 8785 canonical JSON bytes (UTF-8).
    ///
    /// - Parameter value: One of `[String: Any]`, `[Any]`, `String`, `Int`,
    ///   `Double`, `Bool`, `NSNull`, `Data` (will be base64-std encoded),
    ///   or a `Date` (will be formatted as RFC3339 'Z' UTC).
    /// - Returns: Canonical JSON encoded as UTF-8 bytes.
    public static func encode(_ value: Any) throws -> Data {
        // TODO(W3.1): Implement.
        //   - dispatch on type
        //   - recurse for arrays and objects (sort keys lexicographically)
        //   - number formatting per RFC 8785 §3.2.2 (delegate to a helper)
        //   - string escape per RFC 8785 §3.2.3
        //   - dates → ISO8601DateFormatter with .withInternetDateTime + .withFractionalSeconds disabled
        //   - Data → base64-std
        //
        // Critical: byte-identical output vs Go's hcrypto.CanonicalJSON.
        // Tests against `Tests/HankoCryptoTests/Fixtures/canonical-json.json`
        // MUST pass.
        fatalError("HankoCanonicalJSON.encode: not yet implemented (W3.1 sprint)")
    }

    /// Convenience: encode a Codable value via canonical JSON.
    ///
    /// Internally: encode via standard JSONEncoder → decode into a generic
    /// dictionary → re-encode via canonical form.
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        // TODO(W3.1): Implement.
        //   1. JSONEncoder with .iso8601 strategy + .base64 data
        //   2. JSONSerialization to Any
        //   3. encode(Any)
        fatalError("HankoCanonicalJSON.encode<T>: not yet implemented (W3.1 sprint)")
    }
}

// MARK: - Helpers (TODO)

internal enum CanonicalNumber {
    /// Format a number per RFC 8785 §3.2.2.
    static func format(_ value: Double) throws -> String {
        // TODO(W3.1): Implement.
        fatalError("CanonicalNumber.format: not yet implemented")
    }
}

internal enum CanonicalString {
    /// Escape a string per RFC 8785 §3.2.3.
    static func escape(_ s: String) -> String {
        // TODO(W3.1): Implement.
        //   - " → \"
        //   - \ → \\
        //   - control chars (0x00..0x1f, 0x7f) → \uXXXX (lowercase hex)
        //   - all other Unicode passed through unchanged
        fatalError("CanonicalString.escape: not yet implemented")
    }
}
