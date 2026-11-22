//! Strict RFC 7515 JWS / JWT Compact Serialization structural auditor.
//!
//! Enforces:
//! - Exact 3-part compact serialization (`header.payload.signature`)
//! - Strict canonical unpadded Base64URL (rejects `=`, whitespace, and non-zero trailing bits)
//! - Duplicate-key rejection in JSON Protected Header (prevents parser-differential attacks)
//! - `alg: none` rejection & missing `alg` rejection
//! - RFC 7515 §4.1.11 `crit` header enforcement against caller's supported extension allowlist
//! - Embedded key-injection warnings (`jwk`, `jku`, `x5u`)

use crate::{AuditReport, Finding, MAX_NESTING_DEPTH};
use std::collections::HashSet;

const STANDARD_JWS_HEADERS: &[&str] = &[
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
];

/// Audit an RFC 7515 JWS Compact Serialization string.
pub fn audit_jws(input: &str, supported_crit: &[&str]) -> AuditReport {
    let mut findings = Vec::new();
    let trimmed = input.trim_end_matches(&['\r', '\n'][..]);
    let parts: Vec<&str> = trimmed.split('.').collect();

    if parts.len() != 3 {
        findings.push(Finding::error(
            "JWS001",
            0,
            format!("JWS compact serialization must have exactly 3 dot-separated segments (found {})", parts.len()),
        ));
        return AuditReport {
            format: "jws",
            byte_len: input.len(),
            findings,
        };
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    let header_bytes = decode_strict_b64url(header_b64, 0, "JWS002", &mut findings);
    let _payload_bytes = decode_strict_b64url(payload_b64, header_b64.len() + 1, "JWS002", &mut findings);

    if sig_b64.is_empty() {
        findings.push(Finding::error(
            "JWS003",
            header_b64.len() + payload_b64.len() + 2,
            "empty JWS signature segment (unsecured JWS rejected)",
        ));
    } else {
        let _sig_bytes = decode_strict_b64url(
            sig_b64,
            header_b64.len() + payload_b64.len() + 2,
            "JWS002",
            &mut findings,
        );
    }

    if let Some(hb) = header_bytes {
        match std::str::from_utf8(&hb) {
            Err(_) => findings.push(Finding::error("JWS004", 0, "JWS protected header is not valid UTF-8")),
            Ok(json_str) => audit_jws_header_json(json_str, supported_crit, &mut findings),
        }
    }

    AuditReport {
        format: "jws",
        byte_len: input.len(),
        findings,
    }
}

/// Strict RFC 4648 §5 Base64URL decoder with no padding and canonical trailing-bit verification.
pub fn decode_strict_b64url(
    s: &str,
    offset: usize,
    rule_id: &'static str,
    findings: &mut Vec<Finding>,
) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        findings.push(Finding::error(
            rule_id,
            offset,
            "invalid Base64URL length (len % 4 == 1)",
        ));
        return None;
    }

    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut i = 0;
    while i < bytes.len() {
        let rem = bytes.len() - i;
        let v0 = b64_val(bytes[i]);
        let v1 = if rem >= 2 { b64_val(bytes[i + 1]) } else { None };
        let v2 = if rem >= 3 { b64_val(bytes[i + 2]) } else { None };
        let v3 = if rem >= 4 { b64_val(bytes[i + 3]) } else { None };

        match rem {
            2 => {
                let (Some(a), Some(b)) = (v0, v1) else {
                    findings.push(Finding::error(rule_id, offset + i, "illegal character or padding in Base64URL"));
                    return None;
                };
                if (b & 0x0F) != 0 {
                    findings.push(Finding::error(
                        "JWS005",
                        offset + i + 1,
                        "non-canonical Base64URL (non-zero trailing bits in 2-char quantum)",
                    ));
                }
                out.push((a << 2) | (b >> 4));
                i += 2;
            }
            3 => {
                let (Some(a), Some(b), Some(c)) = (v0, v1, v2) else {
                    findings.push(Finding::error(rule_id, offset + i, "illegal character or padding in Base64URL"));
                    return None;
                };
                if (c & 0x03) != 0 {
                    findings.push(Finding::error(
                        "JWS005",
                        offset + i + 2,
                        "non-canonical Base64URL (non-zero trailing bits in 3-char quantum)",
                    ));
                }
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                i += 3;
            }
            _ => {
                let (Some(a), Some(b), Some(c), Some(d)) = (v0, v1, v2, v3) else {
                    findings.push(Finding::error(rule_id, offset + i, "illegal character or padding in Base64URL"));
                    return None;
                };
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
                i += 4;
            }
        }
    }
    Some(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[derive(Debug)]
enum JsonVal {
    Object(Vec<(String, JsonVal)>),
    Array(Vec<JsonVal>),
    Str(String),
    Other,
}

fn audit_jws_header_json(json: &str, supported_crit: &[&str], findings: &mut Vec<Finding>) {
    let mut parser = StrictJsonParser::new(json);
    let val = match parser.parse_value(0, findings) {
        Some(v) => v,
        None => return,
    };
    parser.skip_ws();
    if parser.pos < parser.bytes.len() {
        findings.push(Finding::error(
            "JWS004",
            parser.pos,
            "trailing bytes after JWS protected header JSON",
        ));
    }

    let entries = match val {
        JsonVal::Object(entries) => entries,
        _ => {
            findings.push(Finding::error("JWS004", 0, "JWS protected header must be a JSON object"));
            return;
        }
    };

    let mut keys = HashSet::new();
    let mut alg_val: Option<&str> = None;
    let mut crit_val: Option<&JsonVal> = None;

    for (k, v) in &entries {
        keys.insert(k.as_str());
        match k.as_str() {
            "alg" => {
                if let JsonVal::Str(s) = v {
                    alg_val = Some(s.as_str());
                } else {
                    findings.push(Finding::error("JWS006", 0, "JWS 'alg' header must be a string"));
                }
            }
            "crit" => crit_val = Some(v),
            "jwk" | "jku" | "x5u" => {
                findings.push(Finding::warning(
                    "JWS009",
                    0,
                    format!("header contains embedded/remote key parameter '{}' (verify strict pinning)", k),
                ));
            }
            _ => {}
        }
    }

    match alg_val {
        None => findings.push(Finding::error("JWS006", 0, "missing mandatory 'alg' JWS header")),
        Some(a) if a.eq_ignore_ascii_case("none") || a.is_empty() => {
            findings.push(Finding::error(
                "JWS006",
                0,
                format!("insecure JWS algorithm '{}' rejected", a),
            ));
        }
        Some(_) => {}
    }

    // RFC 7515 §4.1.11 `crit` header enforcement
    if let Some(cv) = crit_val {
        match cv {
            JsonVal::Array(items) => {
                if items.is_empty() {
                    findings.push(Finding::error(
                        "JWS007",
                        0,
                        "RFC 7515 §4.1.11 violation: 'crit' header array must not be empty",
                    ));
                }
                let mut seen_crit = HashSet::new();
                for item in items {
                    match item {
                        JsonVal::Str(ext) => {
                            if ext.is_empty() || !seen_crit.insert(ext.as_str()) {
                                findings.push(Finding::error(
                                    "JWS007",
                                    0,
                                    format!("RFC 7515 §4.1.11 violation: invalid or duplicate 'crit' entry '{}'", ext),
                                ));
                            }
                            if STANDARD_JWS_HEADERS.contains(&ext.as_str()) {
                                findings.push(Finding::error(
                                    "JWS007",
                                    0,
                                    format!("RFC 7515 §4.1.11 violation: standard header '{}' must not appear in 'crit'", ext),
                                ));
                            }
                            if !keys.contains(ext.as_str()) {
                                findings.push(Finding::error(
                                    "JWS007",
                                    0,
                                    format!("RFC 7515 §4.1.11 violation: 'crit' extension '{}' missing from header", ext),
                                ));
                            }
                            if !supported_crit.contains(&ext.as_str()) {
                                findings.push(Finding::error(
                                    "JWS008",
                                    0,
                                    format!("RFC 7515 §4.1.11 violation: unsupported critical extension '{}'", ext),
                                ));
                            }
                        }
                        _ => findings.push(Finding::error(
                            "JWS007",
                            0,
                            "RFC 7515 §4.1.11 violation: 'crit' entries must be strings",
                        )),
                    }
                }
            }
            _ => findings.push(Finding::error(
                "JWS007",
                0,
                "RFC 7515 §4.1.11 violation: 'crit' header must be a JSON array",
            )),
        }
    }
}

struct StrictJsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> StrictJsonParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\r' | b'\n')
        {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: usize, findings: &mut Vec<Finding>) -> Option<JsonVal> {
        if depth > MAX_NESTING_DEPTH {
            findings.push(Finding::error("JWS004", self.pos, "JSON nesting depth exceeded"));
            return None;
        }
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            findings.push(Finding::error("JWS004", self.pos, "unexpected EOF in JSON"));
            return None;
        }
        match self.bytes[self.pos] {
            b'{' => self.parse_object(depth + 1, findings),
            b'[' => self.parse_array(depth + 1, findings),
            b'"' => self.parse_string(findings).map(JsonVal::Str),
            b't' => self.expect_lit(b"true", findings).then_some(JsonVal::Other),
            b'f' => self.expect_lit(b"false", findings).then_some(JsonVal::Other),
            b'n' => self.expect_lit(b"null", findings).then_some(JsonVal::Other),
            b'-' | b'0'..=b'9' => self.parse_number(findings).then_some(JsonVal::Other),
            _ => {
                findings.push(Finding::error("JWS004", self.pos, "unexpected token in JWS JSON"));
                None
            }
        }
    }

    fn parse_object(&mut self, depth: usize, findings: &mut Vec<Finding>) -> Option<JsonVal> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'}' {
            self.pos += 1;
            return Some(JsonVal::Object(entries));
        }
        loop {
            self.skip_ws();
            let key_pos = self.pos;
            let key = self.parse_string(findings)?;
            if !seen.insert(key.clone()) {
                findings.push(Finding::error(
                    "JWS010",
                    key_pos,
                    format!("duplicate JSON key '{}' in JWS header (parser-differential hazard)", key),
                ));
            }
            self.skip_ws();
            if self.pos >= self.bytes.len() || self.bytes[self.pos] != b':' {
                findings.push(Finding::error("JWS004", self.pos, "expected ':' in JSON object"));
                return None;
            }
            self.pos += 1;
            let val = self.parse_value(depth, findings)?;
            entries.push((key, val));
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                findings.push(Finding::error("JWS004", self.pos, "unterminated JSON object"));
                return None;
            }
            match self.bytes[self.pos] {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Some(JsonVal::Object(entries));
                }
                _ => {
                    findings.push(Finding::error("JWS004", self.pos, "expected ',' or '}' in JSON object"));
                    return None;
                }
            }
        }
    }

    fn parse_array(&mut self, depth: usize, findings: &mut Vec<Finding>) -> Option<JsonVal> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b']' {
            self.pos += 1;
            return Some(JsonVal::Array(items));
        }
        loop {
            let val = self.parse_value(depth, findings)?;
            items.push(val);
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                findings.push(Finding::error("JWS004", self.pos, "unterminated JSON array"));
                return None;
            }
            match self.bytes[self.pos] {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(JsonVal::Array(items));
                }
                _ => {
                    findings.push(Finding::error("JWS004", self.pos, "expected ',' or ']' in JSON array"));
                    return None;
                }
            }
        }
    }

    fn parse_string(&mut self, findings: &mut Vec<Finding>) -> Option<String> {
        if self.pos >= self.bytes.len() || self.bytes[self.pos] != b'"' {
            findings.push(Finding::error("JWS004", self.pos, "expected JSON string"));
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Some(out),
                b'\\' => {
                    if self.pos >= self.bytes.len() {
                        findings.push(Finding::error("JWS004", self.pos, "truncated JSON escape"));
                        return None;
                    }
                    let esc = self.bytes[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.bytes.len() {
                                findings.push(Finding::error("JWS004", self.pos, "truncated \\u escape"));
                                return None;
                            }
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]).ok()?;
                            let code = u32::from_str_radix(hex, 16).ok()?;
                            self.pos += 4;
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            } else {
                                findings.push(Finding::error("JWS004", self.pos, "invalid Unicode scalar in JSON escape"));
                                return None;
                            }
                        }
                        _ => {
                            findings.push(Finding::error("JWS004", self.pos - 1, "invalid JSON escape sequence"));
                            return None;
                        }
                    }
                }
                c if c < 0x20 => {
                    findings.push(Finding::error("JWS004", self.pos - 1, "unescaped control character in JSON string"));
                    return None;
                }
                c => out.push(c as char),
            }
        }
        findings.push(Finding::error("JWS004", self.pos, "unterminated JSON string"));
        None
    }

    fn expect_lit(&mut self, lit: &[u8], findings: &mut Vec<Finding>) -> bool {
        if self.pos + lit.len() <= self.bytes.len() && &self.bytes[self.pos..self.pos + lit.len()] == lit {
            self.pos += lit.len();
            true
        } else {
            findings.push(Finding::error("JWS004", self.pos, "invalid JSON literal"));
            false
        }
    }

    fn parse_number(&mut self, findings: &mut Vec<Finding>) -> bool {
        let start = self.pos;
        if self.bytes[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        {
            self.pos += 1;
        }
        if self.pos == start {
            findings.push(Finding::error("JWS004", start, "invalid JSON number"));
            false
        } else {
            true
        }
    }
}
