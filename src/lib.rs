//! `wirelint` — Zero-dependency, fail-closed structural auditor for cryptographic wire formats.
//!
//! Enforces strict canonicalization and RFC security invariants across:
//! - **ASN.1 DER** (ITU-T X.690 / RFC 5280)
//! - **JWS Compact Serialization** (RFC 7515)
//! - **Deterministic CBOR / COSE** (RFC 8949 §4.2 / RFC 8152)

pub mod cbor;
pub mod der;
pub mod jws;

/// Maximum permitted structural nesting depth across all parsers (stack-DoS guard).
pub const MAX_NESTING_DEPTH: usize = 32;

/// Severity level for an audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// A single structured audit finding with stable rule ID and byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub offset: usize,
    pub message: String,
}

impl Finding {
    pub fn error(rule_id: &'static str, offset: usize, message: impl Into<String>) -> Self {
        Self {
            rule_id,
            severity: Severity::Error,
            offset,
            message: message.into(),
        }
    }

    pub fn warning(rule_id: &'static str, offset: usize, message: impl Into<String>) -> Self {
        Self {
            rule_id,
            severity: Severity::Warning,
            offset,
            message: message.into(),
        }
    }
}

/// Aggregate result of auditing a wire artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub format: &'static str,
    pub byte_len: usize,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn is_clean(&self) -> bool {
        self.findings
            .iter()
            .all(|f| f.severity != Severity::Error)
    }

    /// Render the report as minimal valid SARIF 2.1.0 JSON (zero external crates).
    pub fn to_sarif(&self, artifact_uri: &str) -> String {
        let mut results = String::new();
        for (idx, f) in self.findings.iter().enumerate() {
            if idx > 0 {
                results.push(',');
            }
            let level = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            };
            results.push_str(&format!(
                "{{\"ruleId\":\"{}\",\"level\":\"{}\",\"message\":{{\"text\":\"{}\"}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":\"{}\"}},\"region\":{{\"byteOffset\":{}}}}}}}]}}",
                escape_json(f.rule_id),
                level,
                escape_json(&f.message),
                escape_json(artifact_uri),
                f.offset
            ));
        }
        format!(
            "{{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"wirelint\",\"version\":\"0.1.0\"}}}},\"results\":[{}]}}]}}",
            results
        )
    }

    /// Render the report as compact JSON.
    pub fn to_json(&self) -> String {
        let mut items = String::new();
        for (idx, f) in self.findings.iter().enumerate() {
            if idx > 0 {
                items.push(',');
            }
            items.push_str(&format!(
                "{{\"rule_id\":\"{}\",\"severity\":\"{}\",\"offset\":{},\"message\":\"{}\"}}",
                escape_json(f.rule_id),
                f.severity.as_str(),
                f.offset,
                escape_json(&f.message)
            ));
        }
        format!(
            "{{\"format\":\"{}\",\"byte_len\":{},\"verdict\":\"{}\",\"findings\":[{}]}}",
            self.format,
            self.byte_len,
            if self.is_clean() { "PASS" } else { "FAIL" },
            items
        )
    }
}

pub(crate) fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
