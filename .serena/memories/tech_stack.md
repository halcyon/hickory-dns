# Tech Stack

## Language
- Rust 2021 edition, MSRV 1.88 (see root `Cargo.toml`).

## Async Runtime
- Tokio 1.36 (default runtime for resolver and server).

## Build & Tooling
- `cargo` workspace with `resolver = "2"`.
- `just` for workflow orchestration (`justfile` at repo root).
- `cargo-workspaces` (`cargo ws`) for workspace-wide commands.
- `cargo-llvm-cov` for coverage.
- `cargo-audit` for dependency auditing.

## TLS / Crypto
- `aws-lc-rs` (default) or `ring` as TLS/crypto backends (feature-gated).
- `rustls` 0.23.x for TLS; `quinn` for QUIC; `h3`/`h3-quinn` for HTTP/3 DNS.

## Logging / Metrics
- `tracing` + `tracing-subscriber` for structured logging.
- `metrics` crate with Prometheus exporter (`metrics-exporter-prometheus`).

## Package Manager
- Cargo + crates.io; workspace uses exact version pins for internal crates.
