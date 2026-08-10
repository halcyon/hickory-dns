# Hickory DNS Core

## Project Type
Rust workspace implementing a full DNS stack: resolver, server, protocol parsing, and transports.

## Workspace Structure
- `crates/proto` — DNS protocol parsing/serialization, DNSSEC crypto types; lowest-level dependency, supports `no_std`.
- `crates/net` — DNS transport layer (UDP/TCP/TLS/HTTPS/QUIC/H3); depends on `proto`.
- `crates/resolver` — stub resolver with CNAME chasing, caching, async runtime abstraction (Tokio default); depends on `proto`, `net`.
- `crates/server` — authoritative/forwarding DNS server with zone hosting; depends on `proto`, `net`.
- `bin/` — `hickory-dns` server binary.
- `util/` — CLI tools (`resolve`, DNSSEC utils).
- `tests/integration-tests` — cross-crate integration tests.
- `tests/test-support` — shared test utilities.
- `tests/test-data` — fixtures, test configs, certificates.
- `conformance/` — interoperability test suite vs BIND/Unbound.
- `fuzz/` — excluded workspace with fuzz targets.

Read `ARCHITECTURE.md` before changing crate boundaries.

## Key Invariants
- Fully async architecture (Tokio runtime).
- Crates are individually published to crates.io with exact version pinning in workspace.
- Feature gates control TLS backends (aws-lc-rs vs ring), DNSSEC, HTTP/3, QUIC.
- MSRV declared in root `Cargo.toml` (currently 1.88).
