# Security Policy

## Reporting a Vulnerability

If you discover a parser bypass, panic/DoS, or false-negative canonicalization bug in `wirelint`:

1. Please open a private GitHub Security Advisory on this repository rather than a public issue.
2. Include the minimal hex/Base64URL reproducer, the `wirelint` subcommand/flags used, and the expected RFC rule violation.
3. All parser paths in `wirelint` are designed to be **bounds-checked, panic-free, and zero-dependency**; any input that triggers a Rust panic or unbounded allocation is treated as a security bug.
