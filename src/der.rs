//! Strict ASN.1 DER structural auditor (ITU-T X.690 / RFC 5280).
//!
//! Catches canonicalization differentials, malleable encodings, truncation,
//! trailing garbage, and excessive nesting depth without heap-bomb allocations.

use crate::{AuditReport, Finding, MAX_NESTING_DEPTH};

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;

/// Audit a raw byte slice as a single canonical ASN.1 DER TLV element.
pub fn audit_der(input: &[u8]) -> AuditReport {
    let mut findings = Vec::new();
    if input.is_empty() {
        findings.push(Finding::error("DER001", 0, "empty ASN.1 DER input"));
        return AuditReport {
            format: "der",
            byte_len: 0,
            findings,
        };
    }

    let consumed = parse_tlv(input, 0, 0, &mut findings);
    if let Some(end) = consumed {
        if end < input.len() {
            findings.push(Finding::error(
                "DER002",
                end,
                format!("{} trailing byte(s) after top-level DER element", input.len() - end),
            ));
        }
    }

    AuditReport {
        format: "der",
        byte_len: input.len(),
        findings,
    }
}

fn parse_tlv(buf: &[u8], offset: usize, depth: usize, findings: &mut Vec<Finding>) -> Option<usize> {
    if depth > MAX_NESTING_DEPTH {
        findings.push(Finding::error(
            "DER003",
            offset,
            format!("ASN.1 nesting depth exceeds maximum ({})", MAX_NESTING_DEPTH),
        ));
        return None;
    }
    if offset >= buf.len() {
        findings.push(Finding::error("DER004", offset, "unexpected EOF reading DER tag"));
        return None;
    }

    let first_tag = buf[offset];
    let is_constructed = (first_tag & 0x20) != 0;
    let tag_num = first_tag & 0x1F;
    let mut pos = offset + 1;

    // High-tag-number form (X.690 §8.1.2.4)
    if tag_num == 0x1F {
        if pos >= buf.len() {
            findings.push(Finding::error("DER004", pos, "truncated high-tag-number encoding"));
            return None;
        }
        if buf[pos] == 0x80 {
            findings.push(Finding::error(
                "DER005",
                pos,
                "non-minimal high-tag-number encoding (leading 0x80 octet)",
            ));
        }
        let mut decoded_tag: u64 = 0;
        let mut tag_octets = 0usize;
        loop {
            if pos >= buf.len() {
                findings.push(Finding::error("DER004", pos, "unterminated high-tag-number"));
                return None;
            }
            let b = buf[pos];
            pos += 1;
            tag_octets += 1;
            if tag_octets > 5 {
                findings.push(Finding::error("DER005", offset, "high-tag-number exceeds 35 bits"));
                return None;
            }
            decoded_tag = (decoded_tag << 7) | u64::from(b & 0x7F);
            if (b & 0x80) == 0 {
                break;
            }
        }
        if decoded_tag < 31 {
            findings.push(Finding::error(
                "DER005",
                offset,
                format!("non-minimal high-tag-number for tag {} (< 31)", decoded_tag),
            ));
        }
    }

    // Length octets (X.690 §8.1.3 & §10.1)
    if pos >= buf.len() {
        findings.push(Finding::error("DER004", pos, "unexpected EOF reading DER length"));
        return None;
    }
    let len_byte = buf[pos];
    pos += 1;

    let length: usize = if len_byte == 0x80 {
        findings.push(Finding::error(
            "DER006",
            pos - 1,
            "indefinite-length encoding (0x80) is forbidden in DER",
        ));
        return None;
    } else if (len_byte & 0x80) == 0 {
        usize::from(len_byte)
    } else {
        let num_octets = usize::from(len_byte & 0x7F);
        if num_octets == 0 || num_octets > 4 {
            findings.push(Finding::error(
                "DER007",
                pos - 1,
                format!("invalid or excessive DER length octet count ({})", num_octets),
            ));
            return None;
        }
        if pos + num_octets > buf.len() {
            findings.push(Finding::error("DER004", pos, "truncated long-form DER length"));
            return None;
        }
        if buf[pos] == 0x00 {
            findings.push(Finding::error(
                "DER008",
                pos,
                "non-minimal DER length (leading zero octet in long form)",
            ));
        }
        let mut val: usize = 0;
        for &b in &buf[pos..pos + num_octets] {
            val = (val << 8) | usize::from(b);
        }
        if val < 128 {
            findings.push(Finding::error(
                "DER008",
                pos - 1,
                format!("non-minimal long-form DER length for value {} (< 128)", val),
            ));
        }
        pos += num_octets;
        val
    };

    let content_end = match pos.checked_add(length) {
        Some(end) if end <= buf.len() => end,
        _ => {
            findings.push(Finding::error(
                "DER004",
                pos,
                format!(
                    "DER content length {} exceeds remaining buffer ({} bytes)",
                    length,
                    buf.len().saturating_sub(pos)
                ),
            ));
            return None;
        }
    };

    let content = &buf[pos..content_end];

    if is_constructed {
        // Constructed primitive tags (e.g., constructed OCTET STRING / BIT STRING) are forbidden in DER.
        if (first_tag & 0xC0) == 0 && matches!(tag_num, 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x0C) {
            findings.push(Finding::error(
                "DER009",
                offset,
                format!("constructed encoding forbidden in DER for universal tag 0x{:02x}", tag_num),
            ));
        }
        let mut child_pos = pos;
        while child_pos < content_end {
            match parse_tlv(buf, child_pos, depth + 1, findings) {
                Some(next) if next > child_pos => child_pos = next,
                _ => return None,
            }
        }
    } else if (first_tag & 0xC0) == 0 {
        check_universal_primitive(first_tag, pos, content, findings);
    }

    Some(content_end)
}

fn check_universal_primitive(tag: u8, offset: usize, content: &[u8], findings: &mut Vec<Finding>) {
    match tag {
        TAG_BOOLEAN => {
            if content.len() != 1 || (content[0] != 0x00 && content[0] != 0xFF) {
                findings.push(Finding::error(
                    "DER010",
                    offset,
                    "non-canonical DER BOOLEAN (must be 1 byte: 0x00 or 0xFF)",
                ));
            }
        }
        TAG_INTEGER => {
            if content.is_empty() {
                findings.push(Finding::error("DER011", offset, "zero-length DER INTEGER"));
            } else if content.len() >= 2 {
                let redundant_pos = content[0] == 0x00 && (content[1] & 0x80) == 0;
                let redundant_neg = content[0] == 0xFF && (content[1] & 0x80) != 0;
                if redundant_pos || redundant_neg {
                    findings.push(Finding::error(
                        "DER011",
                        offset,
                        "non-minimal DER INTEGER (redundant leading sign octet)",
                    ));
                }
            }
        }
        TAG_BIT_STRING => {
            if content.is_empty() {
                findings.push(Finding::error("DER012", offset, "empty DER BIT STRING (missing unused-bits octet)"));
            } else {
                let unused = content[0];
                if unused > 7 {
                    findings.push(Finding::error(
                        "DER012",
                        offset,
                        format!("invalid DER BIT STRING unused-bits count ({} > 7)", unused),
                    ));
                } else if content.len() == 1 && unused != 0 {
                    findings.push(Finding::error(
                        "DER012",
                        offset,
                        "empty DER BIT STRING must have 0 unused bits",
                    ));
                } else if content.len() > 1 && unused > 0 {
                    let mask = (1u8 << unused) - 1;
                    if (content[content.len() - 1] & mask) != 0 {
                        findings.push(Finding::error(
                            "DER012",
                            offset + content.len() - 1,
                            "non-zero unused padding bits in DER BIT STRING",
                        ));
                    }
                }
            }
        }
        TAG_NULL => {
            if !content.is_empty() {
                findings.push(Finding::error("DER013", offset, "DER NULL must have length 0"));
            }
        }
        TAG_OID => {
            if content.is_empty() {
                findings.push(Finding::error("DER014", offset, "empty DER OBJECT IDENTIFIER"));
            } else {
                let mut i = 0;
                while i < content.len() {
                    if content[i] == 0x80 {
                        findings.push(Finding::error(
                            "DER014",
                            offset + i,
                            "non-minimal DER OID subidentifier (leading 0x80)",
                        ));
                        break;
                    }
                    while i < content.len() && (content[i] & 0x80) != 0 {
                        i += 1;
                    }
                    if i >= content.len() {
                        findings.push(Finding::error(
                            "DER014",
                            offset + content.len() - 1,
                            "unterminated DER OID subidentifier",
                        ));
                        break;
                    }
                    i += 1;
                }
            }
        }
        TAG_UTF8_STRING if std::str::from_utf8(content).is_err() => {
            findings.push(Finding::error("DER015", offset, "invalid UTF-8 inside DER UTF8String"));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_first_oid_subidentifier_vlq_canonically() {
        let unterminated = audit_der(&[0x06, 0x01, 0x81]);
        assert!(!unterminated.is_clean());
        assert!(unterminated.findings.iter().any(|f| f.rule_id == "DER014"));

        let non_minimal = audit_der(&[0x06, 0x02, 0x80, 0x01]);
        assert!(!non_minimal.is_clean());
        assert!(non_minimal.findings.iter().any(|f| f.rule_id == "DER014"));

        let valid_multibyte = audit_der(&[0x06, 0x03, 0x81, 0x80, 0x50]);
        assert!(valid_multibyte.is_clean(), "valid OID 2.16384 must not trigger DER014");
    }
}
