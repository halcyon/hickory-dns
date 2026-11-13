# Review findings: `f990dd272` "bin: configurable multi-port listeners" (branch `multi-port-listeners`)

Reviewed 2026-11-13. Verdict: sound, ship-worthy; no blocking findings.

## Verification performed

| Check | Result |
|---|---|
| `cargo test -p hickory-dns` (default features) | pass |
| `cargo test -p hickory-dns --features tls-aws-lc-rs` (full suite) | pass |
| `multi_port` tests on `https-aws-lc-rs` / `quic-aws-lc-rs` | 5/5 pass each |
| `cargo clippy -p hickory-dns --all-targets -- -D warnings`, both feature extremes | clean |
| `cargo fmt -p hickory-dns -- --check` | clean |
| Live binary `--validate` on `tests/test-data/test_configs/multi_listeners_tls.toml` | validates |
| Live binary on conflicting listener config | rejected pre-bind |

## Findings

1. **`--validate` is blind to two listener failures** (`bin/src/lib.rs`) — **FIXED 2026-11-13**:
   the `if validate` early-return moved below the expansion block, so `--validate` now runs
   the CLI-port rejection and certificate loading (and the `udp_receive_buffer_size` check).
   Regression tests: `test_reject_cli_port_override_with_listeners` (both variants) and
   `test_validate_rejects_missing_certificate` in `bin/tests/integration/multi_port_tests.rs`.
   `validate_listeners()` runs before the `--validate` early-return, so listener semantic
   errors are caught, but the CLI-port rejection lives in expansion and certificate loading
   happens after the early-return. `--validate --port=0` with `[[listeners]]` exits 0 while
   real startup fails. Low severity: `--validate` historically also skips cert-path checks
   and the `udp_receive_buffer_size` check (also post-early-return), and it already binds
   the Prometheus TCP socket and parses zone files, so file reads during validation are
   in-contract.
   Fix: move the expansion block (CLI-port rejection, `load_tls_cert`) above the `--validate`
   early-return — the real-startup path is unchanged (expansion already ran there once) and
   no socket binds happen during expansion. Behavioral caveat: deployments that mount certs
   as runtime secrets (e.g. Kubernetes TLS secrets) would see build-time `--validate` newly
   fail where it previously passed — but only for out-of-cluster validation (CI, image
   builds), where zone files must already be staged, so staging throwaway certs is a
   symmetric workaround; in-cluster init-container validation is unaffected because kubelet
   mounts Secrets before containers run. Project CI does not use `--validate` (no upstream
   precedent). If build-time cert-free validation matters, keep the status quo and soften
   the commit message's "bad cert path still fails fast" claim instead.

2. **Wildcard-overlap binds are not caught statically.** — **FIXED 2026-11-13**:
   `validate_listeners` now tracks claims per port across wildcard (`0.0.0.0`, `::`) and
   specific addresses per socket family; a wildcard claim conflicts with any claim of the
   same scope, family and port, and errors name both listeners and both addresses.
   IPv6 sockets are `IPV6_V6ONLY`, so the two wildcard scopes stay independent. Covered by
   the wildcard cases in `test_reject_invalid_listeners`. (Legacy `listen_addrs_*` settings
   remain unvalidated, as before.)

3. **Cert override is all-or-nothing; the other overrides fall back per-setting.** — **DOCUMENTED 2026-11-13**:
   `bin/README.md` now states that a listener `tls_cert` replaces the top-level one
   entirely and its `endpoint_name` does not fall back.
   A listener `tls_cert` without `endpoint_name` yields `endpoint_name = None` even when the
   top-level cert has one, while `http_endpoint` / `ssl_keylog_enabled` fall back to the
   top-level setting per key. Defensible (a cert is a unit) and the README describes it that
   way, but it is an asymmetry users may trip on. Worth one README sentence if kept.

4. **Minor inefficiency: per-listener certificate reload.** — **FIXED 2026-11-13**:
   listener mode loads the top-level `tls_cert` once before the listener loop (guarded on
   some listener needing it) and listeners without their own `tls_cert` clone it, instead
   of reloading from disk per listener. Listener-owned certificates still load once each.
   Listener expansion calls `load_tls_cert` once per listener; N listeners falling back to
   the same top-level `tls_cert` reload it from disk N times. Could memoize per
   `TlsCertConfig`; harmless at startup.

5. **Harness listener detection is string-sniffing** (`bin/tests/integration/server_harness.rs`). — **FIXED 2026-11-13**:
   detection now parses the config as `toml::Value` and checks the `listeners` key, so a
   `[[listeners]]` inside a string or comment can no longer false-positive.

6. **Test gaps (all low).** — **FIXED 2026-11-13**:
   added `test_listeners_https_endpoint_override` (per-listener `http_endpoint` served on
   `/dns-test`, top-level `/dns-query` rejected; new fixture
   `multi_listeners_https_endpoint.toml`) and
   `test_listeners_disable_tls_filters_protocols` (`--disable-tls` leaves UDP bound and
   drops TLS from a `["udp", "tls"]` listener) in `bin/tests/integration/multi_port_tests.rs`.
   No end-to-end coverage of per-listener `http_endpoint` override (parse+validate covered
   by unit tests only), and no test that `--disable-<proto>` filters listener protocols.
   Both behaviors are simple and log-observable; not worth blocking.

## Non-issues checked and cleared

- Duplicate-port `put()` cannot double-push: `collect_and_print` clears `output` per line,
  so each log line is processed once.
- `get_v4` / `get_v6` semantics preserved after the `SocketPorts` refactor.
- Port-0 conflict skip in `validate_listeners` is correct: ephemeral ports cannot collide.
- Family conflict checks (UDP/QUIC vs TCP/TLS/HTTPS) match OS enforcement: `set_only_v6(true)`
  on IPv6 sockets, no `SO_REUSEADDR` on single UDP sockets.
- Lone `--features __https` compile coupling to `tls_cert` is pre-existing; Cargo's feature
  graph makes `https`/`quic` imply `tls`, so the combination is unreachable in practice.
