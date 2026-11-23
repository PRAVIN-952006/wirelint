# Changelog

All notable changes to `wirelint` are documented in this file.

## [0.1.0] - 2026-11-23
### Added
- Zero-dependency, panic-free Rust structural auditor (`[dependencies]` empty).
- **ASN.1 DER (`DER001`–`DER015`):** ITU-T X.690 / RFC 5280 strict canonicalization checks.
- **RFC 7515 JWS/JWT (`JWS001`–`JWS010`):** Unpadded Base64URL, duplicate JSON key rejection, `alg: none` guard, and RFC 7515 §4.1.11 `crit` allowlist enforcement.
- **RFC 8949/8152 COSE CBOR (`CBOR001`–`CBOR009`):** Core Deterministic CBOR canonical integer, UTF-8, duplicate map key, and bytewise key-order enforcement.
- Built-in `self-test` baseline & throughput benchmark, plus Text, JSON, and **SARIF 2.1.0** outputs.
- Reusable GitHub Marketplace Action (`action.yml`) and terminal demo SVG (`assets/demo.svg`).
