use wirelint::{cbor, der, jws, Severity};

// ============================ ASN.1 DER TESTS ============================

#[test]
fn der_accepts_canonical_sequence() {
    let bytes = [
        0x30, 0x0F, 0x02, 0x01, 0x2A, 0x01, 0x01, 0xFF, 0x05, 0x00, 0x03, 0x02, 0x00, 0xA0, 0x0C,
        0x02, b'o', b'k',
    ];
    let r = der::audit_der(&bytes);
    assert!(r.is_clean(), "unexpected findings: {:?}", r.findings);
}

#[test]
fn der_rejects_empty_and_trailing_bytes() {
    assert!(!der::audit_der(&[]).is_clean());
    let trailing = [0x05, 0x00, 0xFF];
    let r = der::audit_der(&trailing);
    assert!(r.findings.iter().any(|f| f.rule_id == "DER002"));
}

#[test]
fn der_rejects_indefinite_length_and_non_minimal_length() {
    let indef = [0x30, 0x80, 0x00, 0x00];
    assert!(der::audit_der(&indef)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER006"));

    let non_min = [0x02, 0x81, 0x01, 0x05];
    assert!(der::audit_der(&non_min)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER008"));

    let lead_zero = [0x04, 0x82, 0x00, 0x01, 0x41];
    assert!(der::audit_der(&lead_zero)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER008"));
}

#[test]
fn der_rejects_non_canonical_boolean_and_integer() {
    let bad_bool = [0x01, 0x01, 0x01];
    assert!(der::audit_der(&bad_bool)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER010"));

    let bad_pos_int = [0x02, 0x02, 0x00, 0x05];
    assert!(der::audit_der(&bad_pos_int)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER011"));

    let bad_neg_int = [0x02, 0x02, 0xFF, 0x80];
    assert!(der::audit_der(&bad_neg_int)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER011"));

    assert!(der::audit_der(&[0x02, 0x02, 0xFF, 0x7F]).is_clean());
    assert!(der::audit_der(&[0x02, 0x02, 0x00, 0x80]).is_clean());
}

#[test]
fn der_rejects_bad_bit_string_padding_and_constructed_primitive() {
    let bad_bs = [0x03, 0x02, 0x02, 0x01];
    assert!(der::audit_der(&bad_bs)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER012"));

    let cons_oct = [0x24, 0x03, 0x04, 0x01, 0x41];
    assert!(der::audit_der(&cons_oct)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER009"));
}

#[test]
fn der_rejects_excessive_nesting_depth() {
    let mut buf = Vec::new();
    for i in (0..40).rev() {
        buf.push(0x30);
        buf.push((i * 2) as u8);
    }
    let r = der::audit_der(&buf);
    assert!(r.findings.iter().any(|f| f.rule_id == "DER003"));
}

#[test]
fn der_rejects_truncated_oom_length() {
    let oom = [0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF];
    assert!(der::audit_der(&oom)
        .findings
        .iter()
        .any(|f| f.rule_id == "DER004"));
}

// ============================ RFC 7515 JWS TESTS ============================

fn b64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
    }
    out
}

fn make_jws(header_json: &str, payload_json: &str) -> String {
    format!(
        "{}.{}.{}",
        b64url_encode(header_json.as_bytes()),
        b64url_encode(payload_json.as_bytes()),
        b64url_encode(&[0x42u8; 64])
    )
}

#[test]
fn jws_accepts_canonical_eddsa_and_supported_crit() {
    let tok = make_jws(r#"{"alg":"EdDSA","typ":"JWT"}"#, r#"{"sub":"alice"}"#);
    assert!(jws::audit_jws(&tok, &[]).is_clean());

    let crit_tok = make_jws(
        r#"{"alg":"EdDSA","crit":["x-tenant"],"x-tenant":"acme"}"#,
        r#"{"sub":"alice"}"#,
    );
    assert!(jws::audit_jws(&crit_tok, &["x-tenant"]).is_clean());
}

#[test]
fn jws_rejects_alg_none_and_empty_signature() {
    let none_tok = make_jws(r#"{"alg":"none"}"#, r#"{"sub":"alice"}"#);
    assert!(jws::audit_jws(&none_tok, &[])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS006"));

    let empty_sig = format!(
        "{}.{}.",
        b64url_encode(br#"{"alg":"EdDSA"}"#),
        b64url_encode(br#"{"sub":"alice"}"#)
    );
    assert!(jws::audit_jws(&empty_sig, &[])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS003"));
}

#[test]
fn jws_rejects_duplicate_json_keys() {
    let dup_tok = make_jws(r#"{"alg":"EdDSA","alg":"none"}"#, r#"{"sub":"alice"}"#);
    assert!(jws::audit_jws(&dup_tok, &[])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS010"));
}

#[test]
fn jws_enforces_rfc7515_crit_rules() {
    let unknown = make_jws(
        r#"{"alg":"ES256","crit":["x-pin"],"x-pin":"v1"}"#,
        r#"{"sub":"alice"}"#,
    );
    assert!(jws::audit_jws(&unknown, &[])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS008"));

    let empty = make_jws(r#"{"alg":"ES256","crit":[]}"#, r#"{"sub":"alice"}"#);
    assert!(jws::audit_jws(&empty, &[])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS007"));

    let std_hdr = make_jws(r#"{"alg":"ES256","crit":["alg"]}"#, r#"{"sub":"alice"}"#);
    assert!(jws::audit_jws(&std_hdr, &["alg"])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS007"));

    let missing_ext = make_jws(r#"{"alg":"ES256","crit":["x-pin"]}"#, r#"{"sub":"alice"}"#);
    assert!(jws::audit_jws(&missing_ext, &["x-pin"])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS007"));
}

#[test]
fn jws_rejects_padded_and_non_canonical_base64url() {
    let padded = format!(
        "{}==.{}.AAAA",
        b64url_encode(br#"{"alg":"EdDSA"}"#),
        b64url_encode(br#"{}"#)
    );
    assert!(jws::audit_jws(&padded, &[])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS002"));

    let non_canon = format!(
        "{}.{}.AB",
        b64url_encode(br#"{"alg":"EdDSA"}"#),
        b64url_encode(br#"{}"#)
    );
    assert!(jws::audit_jws(&non_canon, &[])
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS005"));
}

#[test]
fn jws_warns_on_embedded_jwk_without_failing_clean_syntax() {
    let tok = make_jws(
        r#"{"alg":"ES256","jwk":{"kty":"EC"}}"#,
        r#"{"sub":"alice"}"#,
    );
    let r = jws::audit_jws(&tok, &[]);
    assert!(r.is_clean());
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule_id == "JWS009" && f.severity == Severity::Warning));
}

// ============================ RFC 8949 CBOR / COSE TESTS ============================

#[test]
fn cbor_accepts_canonical_cose_map() {
    let bytes = [0xA2, 0x01, 0x26, 0x03, 0x62, b'o', b'k'];
    let r = cbor::audit_cbor(&bytes);
    assert!(r.is_clean(), "unexpected findings: {:?}", r.findings);
}

#[test]
fn cbor_rejects_indefinite_length_and_non_minimal_int() {
    let indef_map = [0xBF, 0xFF];
    assert!(cbor::audit_cbor(&indef_map)
        .findings
        .iter()
        .any(|f| f.rule_id == "CBOR005"));

    let non_min = [0x18, 0x05];
    assert!(cbor::audit_cbor(&non_min)
        .findings
        .iter()
        .any(|f| f.rule_id == "CBOR006"));
}

#[test]
fn cbor_rejects_duplicate_and_unsorted_map_keys() {
    let dup = [0xA2, 0x01, 0x00, 0x01, 0x01];
    assert!(cbor::audit_cbor(&dup)
        .findings
        .iter()
        .any(|f| f.rule_id == "CBOR008"));

    let unsorted = [0xA2, 0x03, 0x00, 0x01, 0x01];
    assert!(cbor::audit_cbor(&unsorted)
        .findings
        .iter()
        .any(|f| f.rule_id == "CBOR009"));
}

#[test]
fn cbor_rejects_invalid_utf8_and_trailing_bytes() {
    let bad_utf8 = [0x62, 0xFF, 0xFE];
    assert!(cbor::audit_cbor(&bad_utf8)
        .findings
        .iter()
        .any(|f| f.rule_id == "CBOR007"));

    let trailing = [0x01, 0x00];
    assert!(cbor::audit_cbor(&trailing)
        .findings
        .iter()
        .any(|f| f.rule_id == "CBOR002"));
}

#[test]
fn sarif_and_json_output_are_well_formed() {
    let r = der::audit_der(&[0x01, 0x01, 0x01]);
    let sarif = r.to_sarif("bad.der");
    assert!(sarif.contains("\"version\":\"2.1.0\""));
    assert!(sarif.contains("\"ruleId\":\"DER010\""));
    let json = r.to_json();
    assert!(json.contains("\"verdict\":\"FAIL\""));
}
