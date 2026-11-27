//! Strict RFC 8949 §4.2 Deterministic CBOR / RFC 8152 COSE structural auditor.
//!
//! Enforces:
//! - No indefinite-length items (`ai == 31`)
//! - Strictly minimal integer & length encodings (no overlong `ai == 24..27`)
//! - RFC 8949 §4.2.1 deterministic IEEE-754 floating-point encoding (shortest form & canonical NaN)
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

    let (val, mut pos) = decode_arg(buf, offset, major, ai, findings)?;

    match major {
        0 | 1 => Some(pos),
        2 => {
            let Some(end) = usize::try_from(val).ok().and_then(|l| pos.checked_add(l)) else {
                findings.push(Finding::error(
                    "CBOR004",
                    offset,
                    "CBOR byte string length overflows platform usize",
                ));
                return None;
            };
            if end > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated CBOR byte string"));
                return None;
            }
            Some(end)
        }
        3 => {
            let Some(end) = usize::try_from(val).ok().and_then(|l| pos.checked_add(l)) else {
                findings.push(Finding::error(
                    "CBOR004",
                    offset,
                    "CBOR text string length overflows platform usize",
                ));
                return None;
            };
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
            let Some(count) = usize::try_from(val).ok() else {
                findings.push(Finding::error(
                    "CBOR004",
                    offset,
                    "CBOR array count overflows platform usize",
                ));
                return None;
            };
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
            let Some(pairs) = usize::try_from(val).ok() else {
                findings.push(Finding::error(
                    "CBOR004",
                    offset,
                    "CBOR map pair count overflows platform usize",
                ));
                return None;
            };
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
        7 => {
            validate_major7(offset, ai, val, findings);
            Some(pos)
        }
        _ => None,
    }
}

fn validate_major7(offset: usize, ai: u8, val: u64, findings: &mut Vec<Finding>) {
    match ai {
        0..=23 => {}
        24 => {
            // RFC 8949 §3.3: simple values 0..=23 must use 1-byte head; 24..=31 are reserved.
            if val < 32 {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    format!("invalid or non-minimal 1-byte CBOR simple value ({})", val),
                ));
            }
        }
        25 => {
            // IEEE 754 binary16: only canonical quiet NaN 0x7e00 is allowed (RFC 8949 §4.2.1).
            let bits = val as u16;
            let exp = (bits >> 10) & 0x1F;
            let frac = bits & 0x03FF;
            if exp == 0x1F && frac != 0 && bits != 0x7E00 {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    format!("non-canonical CBOR float16 NaN (0x{:04x}, expected 0x7e00)", bits),
                ));
            }
        }
        26 => {
            // IEEE 754 binary32: NaN and values representable as binary16 must use f16 (RFC 8949 §4.2.1).
            let bits = val as u32;
            let f = f32::from_bits(bits);
            if f.is_nan() {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    "non-canonical CBOR float32 NaN (must be encoded as float16 0xf97e00)",
                ));
            } else if f32_fits_in_f16(bits) {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    "non-minimal CBOR float32 (value is exactly representable as float16)",
                ));
            }
        }
        27 => {
            // IEEE 754 binary64: NaN and values representable as binary32/binary16 must use shorter form.
            let f = f64::from_bits(val);
            if f.is_nan() {
                findings.push(Finding::error(
                    "CBOR006",
                    offset,
                    "non-canonical CBOR float64 NaN (must be encoded as float16 0xf97e00)",
                ));
            } else {
                let narrowed = f as f32;
                if (narrowed as f64).to_bits() == val {
                    findings.push(Finding::error(
                        "CBOR006",
                        offset,
                        "non-minimal CBOR float64 (value is exactly representable as float32/float16)",
                    ));
                }
            }
        }
        _ => {}
    }
}

/// Returns true iff an IEEE-754 binary32 bit pattern (non-NaN) converts losslessly to binary16.
fn f32_fits_in_f16(bits: u32) -> bool {
    let sign = (bits >> 31) & 1;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let frac = bits & 0x007F_FFFF;

    if exp == 0xFF {
        // Infinity (NaN already handled by caller) fits exactly in f16.
        return frac == 0;
    }
    if exp == 0 && frac == 0 {
        // +0.0 and -0.0 fit exactly in f16.
        return true;
    }

    let unbiased = exp - 127;
    if (-14..=15).contains(&unbiased) {
        // Normal f16: only top 10 mantissa bits may be non-zero.
        (frac & 0x1FFF) == 0
    } else if (-24..=-15).contains(&unbiased) {
        // Subnormal f16: shift = -14 - unbiased (1..=10), implicit leading 1 bit + frac.
        let shift = (-14 - unbiased) as u32;
        let full_sig = 0x0080_0000u32 | frac;
        let mask = (1u32 << (13 + shift)) - 1;
        let _ = sign;
        (full_sig & mask) == 0
    } else {
        false
    }
}

fn decode_arg(
    buf: &[u8],
    offset: usize,
    major: u8,
    ai: u8,
    findings: &mut Vec<Finding>,
) -> Option<(u64, usize)> {
    let pos = offset + 1;
    let check_int_minimal = major != 7;
    match ai {
        0..=23 => Some((u64::from(ai), pos)),
        24 => {
            if pos + 1 > buf.len() {
                findings.push(Finding::error("CBOR004", pos, "truncated 1-byte CBOR argument"));
                return None;
            }
            let v = u64::from(buf[pos]);
            if check_int_minimal && v < 24 {
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
            if check_int_minimal && v <= 0xFF {
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
            if check_int_minimal && v <= 0xFFFF {
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
            if check_int_minimal && v <= 0xFFFF_FFFF {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_u64_max_length_overflow_fail_closed() {
        // 5B FF FF FF FF FF FF FF FF -> major 2 (bstr), ai=27, len=u64::MAX
        let report = audit_cbor(&[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(!report.findings.is_empty(), "must fail closed on u64::MAX length");
        assert!(report.findings.iter().any(|f| f.rule_id == "CBOR004"));
    }

    #[test]
    fn accepts_canonical_f16_zero_and_nan_rejects_noncanonical_floats() {
        // Valid canonical f16 0.0 (F9 00 00) and canonical f16 NaN (F9 7E 00)
        assert!(audit_cbor(&[0xF9, 0x00, 0x00]).findings.is_empty());
        assert!(audit_cbor(&[0xF9, 0x7E, 0x00]).findings.is_empty());
        // Non-canonical f16 NaN payload (F9 7E 01)
        assert!(audit_cbor(&[0xF9, 0x7E, 0x01]).findings.iter().any(|f| f.rule_id == "CBOR006"));
        // Non-canonical f64 1.0 (FB 3F F0 00 00 00 00 00 00) must be rejected
        assert!(
            audit_cbor(&[0xFB, 0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .findings
                .iter()
                .any(|f| f.rule_id == "CBOR006")
        );
        // Valid canonical f64 1.1 (not representable in f32) must pass
        let f64_1_1 = 1.1f64.to_be_bytes();
        let mut buf = vec![0xFB];
        buf.extend_from_slice(&f64_1_1);
        assert!(audit_cbor(&buf).findings.is_empty());
    }
}
