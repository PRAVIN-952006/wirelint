//! Strict RFC 8949 §4.2 Deterministic CBOR / RFC 8152 COSE structural auditor.
//!
//! Enforces:
//! - No indefinite-length items (`ai == 31`)
//! - Strictly minimal integer & length encodings (no overlong `ai == 24..27`)
//! - Strict UTF-8 validation for Major Type 3 text strings
//! - Duplicate map key rejection and canonical deterministic map key ordering (RFC 8949 §4.2.1)
//! - Bounded nesting depth and zero trailing garbage bytes

use crate::{AuditReport, Finding, MAX_NESTING_DEPTH};
use std::collections::HashSet;

/// Audit a raw byte slice as a single Core Deterministic CBOR (RFC 8949 §4.2) item.
pub fn audit_cbor(input: &[u8]) -> AuditReport {
    let mut findings = Vec::new();
    if input.is_empty() {
        findings.push(Finding::error("CBOR001", 0, "empty CBOR input"));
        return AuditReport {
            format: "cbor",
            byte_len: 0,
            findings,
        };
    }

    if let Some(end) = parse_item(input, 0, 0, &mut findings) {
        if end < input.len() {
            findings.push(Finding::error(
                "CBOR002",
                end,
                format!("{} trailing byte(s) after top-level CBOR item", input.len() - end),
            ));
        }
    }

    AuditReport {
        format: "cbor",
        byte_len: input.len(),
        findings,
    }
}

fn parse_item(buf: &[u8], offset: usize, depth: usize, findings: &mut Vec<Finding>) -> Option<usize> {
    if depth > MAX_NESTING_DEPTH {
        findings.push(Finding::error(
            "CBOR003",
            offset,
            format!("CBOR nesting depth exceeds maximum ({})", MAX_NESTING_DEPTH),
        ));
        return None;
    }
    if offset >= buf.len() {
        findings.push(Finding::error("CBOR004", offset, "unexpected EOF reading CBOR head"));
        return None;
    }

    let head = buf[offset];
    let major = head >> 5;
    let ai = head & 0x1F;

    if ai == 31 {
        findings.push(Finding::error(
            "CBOR005",
            offset,
            "indefinite-length CBOR item (ai=31) is forbidden in Core Deterministic Encoding",
        ));
        return None;
    }
    if (28..=30).contains(&ai) {
        findings.push(Finding::error(
            "CBOR004",
            offset,
            format!("reserved CBOR additional information value ({})", ai),
        ));
        return None;
    }

    let (val, mut pos) = decode_arg(buf, offset, ai, findings)?;

    match major {
        0 | 1 => Some(pos),
        2 => {
            let len = usize::try_from(val).ok()?;
            let end = pos.checked_add(len)?;
            if end > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated CBOR byte string"));
                return None;
            }
            Some(end)
        }
        3 => {
            let len = usize::try_from(val).ok()?;
            let end = pos.checked_add(len)?;
            if end > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated CBOR text string"));
                return None;
            }
            if std::str::from_utf8(&buf[pos..end]).is_err() {
                findings.push(Finding::error("CBOR007", pos, "invalid UTF-8 in CBOR text string"));
            }
            Some(end)
        }
        4 => {
            let count = usize::try_from(val).ok()?;
            if count > buf.len().saturating_sub(pos) {
                findings.push(Finding::error(
                    "CBOR004",
                    offset,
                    format!("CBOR array count {} exceeds remaining buffer", count),
                ));
                return None;
            }
            for _ in 0..count {
                pos = parse_item(buf, pos, depth + 1, findings)?;
            }
            Some(pos)
        }
        5 => {
            let pairs = usize::try_from(val).ok()?;
            if pairs.saturating_mul(2) > buf.len().saturating_sub(pos) {
                findings.push(Finding::error(
                    "CBOR004",
                    offset,
                    format!("CBOR map pair count {} exceeds remaining buffer", pairs),
                ));
                return None;
            }
            let mut seen_keys: HashSet<&[u8]> = HashSet::new();
            let mut prev_key: Option<&[u8]> = None;

            for _ in 0..pairs {
                let key_start = pos;
                let key_end = parse_item(buf, key_start, depth + 1, findings)?;
                let key_bytes = &buf[key_start..key_end];

                if !seen_keys.insert(key_bytes) {
                    findings.push(Finding::error(
                        "CBOR008",
                        key_start,
                        "duplicate CBOR map key (COSE/WebAuthn parser-differential hazard)",
                    ));
                } else if let Some(prev) = prev_key {
                    // RFC 8949 §4.2.1 bytewise lexicographic ordering
                    if key_bytes < prev {
                        findings.push(Finding::error(
                            "CBOR009",
                            key_start,
                            "CBOR map keys are not in RFC 8949 §4.2.1 bytewise canonical order",
                        ));
                    }
                }
                prev_key = Some(key_bytes);

                pos = parse_item(buf, key_end, depth + 1, findings)?;
            }
            Some(pos)
        }
        6 => parse_item(buf, pos, depth + 1, findings),
        7 => Some(pos),
        _ => None,
    }
}

fn decode_arg(buf: &[u8], offset: usize, ai: u8, findings: &mut Vec<Finding>) -> Option<(u64, usize)> {
    let pos = offset + 1;
    match ai {
        0..=23 => Some((u64::from(ai), pos)),
        24 => {
            if pos + 1 > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated 1-byte CBOR argument"));
                return None;
            }
            let v = u64::from(buf[pos]);
            if v < 24 {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    format!("non-minimal CBOR encoding (1-byte arg for value {} < 24)", v),
                ));
            }
            Some((v, pos + 1))
        }
        25 => {
            if pos + 2 > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated 2-byte CBOR argument"));
                return None;
            }
            let v = u64::from(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
            if v <= 0xFF {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    format!("non-minimal CBOR encoding (2-byte arg for value {} <= 255)", v),
                ));
            }
            Some((v, pos + 2))
        }
        26 => {
            if pos + 4 > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated 4-byte CBOR argument"));
                return None;
            }
            let v = u64::from(u32::from_be_bytes([
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            ]));
            if v <= 0xFFFF {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    format!("non-minimal CBOR encoding (4-byte arg for value {} <= 65535)", v),
                ));
            }
            Some((v, pos + 4))
        }
        27 => {
            if pos + 8 > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated 8-byte CBOR argument"));
                return None;
            }
            let v = u64::from_be_bytes([
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
                buf[pos + 4],
                buf[pos + 5],
                buf[pos + 6],
                buf[pos + 7],
            ]);
            if v <= 0xFFFF_FFFF {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    format!("non-minimal CBOR encoding (8-byte arg for value {} <= 2^32-1)", v),
                ));
            }
            Some((v, pos + 8))
        }
        _ => None,
    }
}
