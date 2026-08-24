// HankoCanonicalJSON.swift
// HankoCrypto — deterministic (canonical) JSON serialization.
//
// Mirrors the Go ref impl (crypto/ed25519.go: CanonicalJSON/marshalCanonical):
//   1. Round-trip the value through standard JSON to normalize all types.
//   2. Recursively sort all object keys byte-wise (Go `sort.Strings`).
//   3. Re-serialize without whitespace, matching Go `encoding/json` string
//      escaping (HTML escaping ON): short escapes for quote, backslash,
//      \n \r \t; other control chars as \u00xx (lowercase hex); the
//      HTML-sensitive chars < > & as < > &; U+2028/U+2029
//      as    .
//
// This intentionally mirrors Go byte-for-byte rather than full RFC 8785 —
// the Go implementation is the wire authority. Byte parity is REQUIRED and
// enforced by `Tests/HankoCryptoTests/Fixtures/canonical-json.json`.
//
// Timestamps: RFC3339 with 'T' separator and 'Z' UTC, no fractional seconds.
// Data → base64-std (matches Go []byte marshalling).

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
    /// bool / null) into deterministic JSON bytes (UTF-8).
    ///
    /// - Parameter value: One of `[String: Any]`, `[Any]`, `String`, `Int`,
    ///   `Double`, `Bool`, `NSNull`, `Data` (base64-std encoded),
    ///   or a `Date` (RFC3339 'Z' UTC).
    /// - Returns: Canonical JSON encoded as UTF-8 bytes.
    public static func encode(_ value: Any) throws -> Data {
        var out = ""
        try write(value, into: &out)
        guard let data = out.data(using: .utf8) else { throw Error.invalidUTF8 }
        return data
    }

    /// Convenience: encode a Codable value via canonical JSON.
    ///
    /// Internally: encode via standard JSONEncoder (RFC3339 dates, base64
    /// data) → JSONSerialization to a generic value → canonical re-encode.
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, enc in
            var c = enc.singleValueContainer()
            try c.encode(rfc3339.string(from: date))
        }
        encoder.dataEncodingStrategy = .base64
        let raw = try encoder.encode(value)
        let obj = try JSONSerialization.jsonObject(with: raw, options: [.fragmentsAllowed])
        return try encode(obj)
    }

    // MARK: Internals

    /// RFC3339 'Z' UTC, second precision — matches Go time.Time marshalling
    /// for whole-second timestamps (the only shape Hanko types produce).
    /// ISO8601DateFormatter is documented thread-safe; the reference is
    /// immutable after init, hence nonisolated(unsafe).
    nonisolated(unsafe) static let rfc3339: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()

    private static func write(_ value: Any, into out: inout String) throws {
        switch value {
        case is NSNull:
            out += "null"
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                out += n.boolValue ? "true" : "false"
            } else {
                out += try CanonicalNumber.format(n.doubleValue)
            }
        case let s as String:
            out += "\""
            out += CanonicalString.escape(s)
            out += "\""
        case let d as Date:
            out += "\""
            out += rfc3339.string(from: d)
            out += "\""
        case let d as Data:
            out += "\""
            out += d.base64EncodedString()
            out += "\""
        case let dict as [String: Any]:
            // Byte-wise key sort — mirrors Go sort.Strings over UTF-8 bytes.
            let keys = dict.keys.sorted {
                Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8))
            }
            out += "{"
            var first = true
            for k in keys {
                if !first { out += "," }
                first = false
                out += "\""
                out += CanonicalString.escape(k)
                out += "\":"
                try write(dict[k]!, into: &out)
            }
            out += "}"
        case let arr as [Any]:
            out += "["
            var first = true
            for item in arr {
                if !first { out += "," }
                first = false
                try write(item, into: &out)
            }
            out += "]"
        default:
            throw Error.unsupportedType(String(describing: type(of: value)))
        }
    }
}

// MARK: - Helpers

internal enum CanonicalNumber {
    /// Format a number. Integral values render as plain integers — the only
    /// numeric shape Hanko protocol types produce. Other finite doubles use
    /// Swift's shortest round-trip representation (matches Go for common
    /// values; protocol types never emit floats). NaN/Inf are invalid JSON.
    static func format(_ value: Double) throws -> String {
        guard value.isFinite else { throw HankoCanonicalJSON.Error.invalidNumber(value) }
        if value == value.rounded(), abs(value) < 9_007_199_254_740_992.0 {
            return String(Int64(value))
        }
        return "\(value)"
    }
}

internal enum CanonicalString {
    /// Escape a string exactly like Go's `encoding/json` (HTML escaping ON):
    /// quote and backslash get short escapes, as do \n \r \t; other control
    /// chars (below 0x20) become \u00xx with lowercase hex; the HTML chars
    /// < > & become < > &; U+2028/U+2029 become  / ;
    /// all other Unicode passes through as UTF-8.
    static func escape(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count + 2)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"":       out += "\\\""
            case "\\":       out += "\\\\"
            case "\n":       out += "\\n"
            case "\r":       out += "\\r"
            case "\t":       out += "\\t"
            case "<":        out += "\\u003c"
            case ">":        out += "\\u003e"
            case "&":        out += "\\u0026"
            case "\u{2028}": out += "\\u2028"
            case "\u{2029}": out += "\\u2029"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }
}
