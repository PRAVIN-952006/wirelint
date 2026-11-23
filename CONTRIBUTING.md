# Contributing to `wirelint`

Contributions—especially new RFC canonicalization rules, differential test vectors, and fuzzing corpora for ASN.1 DER, JWS/JWT, and COSE CBOR—are welcome.

## Development Rules
1. Keep `[dependencies]` strictly empty in `Cargo.toml` (Rust `std` only).
2. All parsers must be bounds-checked, recursion-capped, and panic-free on arbitrary untrusted byte slices.
3. Run `cargo clippy --all-targets -- -D warnings`, `cargo test`, and `cargo run --release -- self-test` before opening a PR.
