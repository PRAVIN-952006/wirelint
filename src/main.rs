use std::env;
use std::fs;
use std::process;
use std::time::Instant;
use wirelint::{cbor, der, jws};

fn usage() -> ! {
    eprintln!(
        "wirelint 0.1.0 — Zero-dependency cryptographic wire-format auditor\n\n\
         USAGE:\n\
         \x20 wirelint audit --format <der|jws|cbor> [--crit <ext>] [--json|--sarif] <file>\n\
         \x20 wirelint self-test\n"
    );
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "self-test" => run_self_test(),
        "audit" => run_audit(&args[2..]),
        _ => usage(),
    }
}

fn run_audit(args: &[String]) {
    let mut format: Option<String> = None;
    let mut crit_exts: Vec<String> = Vec::new();
    let mut out_mode = "text";
    let mut file_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" | "-f" => {
                i += 1;
                format = args.get(i).cloned();
            }
            "--crit" => {
                i += 1;
                if let Some(ext) = args.get(i) {
                    for part in ext.split(',') {
                        let trimmed = part.trim();
                        if !trimmed.is_empty() {
                            crit_exts.push(trimmed.to_string());
                        }
                    }
                }
            }
            "--json" => out_mode = "json",
            "--sarif" => out_mode = "sarif",
            other if !other.starts_with('-') => file_path = Some(other.to_string()),
            _ => usage(),
        }
        i += 1;
    }

    let (Some(fmt), Some(path)) = (format, file_path) else {
        usage();
    };

    let raw = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("wirelint: failed to read '{}': {}", path, e);
            process::exit(2);
        }
    };

    let crit_refs: Vec<&str> = crit_exts.iter().map(String::as_str).collect();
    let report = match fmt.as_str() {
        "der" => der::audit_der(&raw),
        "cbor" => cbor::audit_cbor(&raw),
        "jws" => {
            let text = match std::str::from_utf8(&raw) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("wirelint: JWS input is not valid UTF-8");
                    process::exit(1);
                }
            };
            jws::audit_jws(text, &crit_refs)
        }
        _ => usage(),
    };

    match out_mode {
        "json" => println!("{}", report.to_json()),
        "sarif" => println!("{}", report.to_sarif(&path)),
        _ => {
            println!(
                "wirelint [{}] {} ({} bytes): {}",
                report.format,
                path,
                report.byte_len,
                if report.is_clean() { "PASS" } else { "FAIL" }
            );
            for f in &report.findings {
                println!("  [{}:{}] @{} {}", f.severity.as_str(), f.rule_id, f.offset, f.message);
            }
        }
    }

    if !report.is_clean() {
        process::exit(1);
    }
}

fn run_self_test() {
    let valid_der: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x2A, 0x01, 0x01, 0xFF];
    let valid_jws = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let valid_cbor: &[u8] = &[0xA2, 0x01, 0x26, 0x03, 0x62, b'o', b'k'];

    assert!(der::audit_der(valid_der).is_clean(), "valid DER baseline failed");
    assert!(jws::audit_jws(valid_jws, &[]).is_clean(), "valid JWS baseline failed");
    assert!(cbor::audit_cbor(valid_cbor).is_clean(), "valid CBOR baseline failed");

    let iters: u32 = 50_000;

    let t0 = Instant::now();
    for _ in 0..iters {
        let _ = der::audit_der(valid_der);
    }
    let der_ns = t0.elapsed().as_nanos() / u128::from(iters);

    let t1 = Instant::now();
    for _ in 0..iters {
        let _ = jws::audit_jws(valid_jws, &[]);
    }
    let jws_ns = t1.elapsed().as_nanos() / u128::from(iters);

    let t2 = Instant::now();
    for _ in 0..iters {
        let _ = cbor::audit_cbor(valid_cbor);
    }
    let cbor_ns = t2.elapsed().as_nanos() / u128::from(iters);

    println!("wirelint self-test: PASS (3/3 baselines clean)");
    println!("  DER  audit: {} ns/op ({} iters)", der_ns, iters);
    println!("  JWS  audit: {} ns/op ({} iters)", jws_ns, iters);
    println!("  CBOR audit: {} ns/op ({} iters)", cbor_ns, iters);
}
