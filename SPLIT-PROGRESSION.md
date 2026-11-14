# Split progression: `0dc6622c1` "bin: configurable multi-port listeners"

Recorded 2026-11-13. The single squashed commit (rebased onto `main` f3579d0c6 as
`0dc6622c1` on branch `multi-port-listeners`) is rebuilt as a progression of five
buildable, GPG-signed commits on branch `multi-port-listeners-split`, ordered so each
step is easy to read and follow. The final tree is byte-identical to the single-commit
version: `git diff HEAD 0dc6622c1` is empty.

## Progression

| Commit | Content | Size |
|---|---|---|
| `5d54e709a` config: add `[[listeners]]` entries with validation | `ListenerProtocol`/`ListenConfig` model, `validate_listeners` (mutual exclusion, socket-claim conflicts incl. wildcard-vs-specific, duplicates, unsupported protocols, cert requirements, unused secure settings), legacy ports → `Option<u16>`, minimal `lib.rs` wiring, all config unit tests | +732 −35 |
| `e539be2cc` bin: expand configuration into planned socket bindings | `PlannedBinding`/`ResolvedTlsCert`/`load_tls_cert`, unified expansion (legacy unchanged, listener mode with per-listener overrides + one shared top-level cert load), CLI-port rejection, `--validate` moved below expansion, per-socket bind loop with port in errors | +414 −201 |
| `e64c61abf` bin: support multiple listeners in the test harness | `SocketPorts` → `Vec<SocketAddr>` + `get_all`, TOML-parse listener detection, alt-cert generation (`additional_leaf`); first e2e tests: two UDP/TCP listeners + CLI rejection at startup and under `--validate` | +179 −32 |
| `b81d73e67` bin: listener tests for TLS, HTTPS and QUIC | TLS/HTTPS/QUIC e2e, two-certs, per-listener `http_endpoint` override, `--disable-tls` filtering, `--validate` bad-cert rejection; 5 fixtures + `define_test_config!` registrations + `http_endpoint` skip guard | +577 |
| `e6e399de2` docs: document `[[listeners]]` configuration | bin/README.md Listeners section + example.toml comments | +53 |

## Verification

- Each intermediate commit: `cargo test -p hickory-dns` pass, plus a secure-feature
  (`quic`+`https`) `cargo check --all-targets` compile.
- Final tree byte-identical to the single-commit version (`git diff HEAD 0dc6622c1` empty).
- Final matrix: tls suite 26 unit + 78 integration; `multi_port` 8/8 under
  `https-aws-lc-rs`, 7/7 under `quic-aws-lc-rs`; clippy `-D warnings` clean at both
  feature extremes; `cargo fmt --check` clean.
- All five commits signed (`%G?` = `G`).

## Notes

- main's CNAME commits had touched `tests/test-support/src/lib.rs`, so the harness commit
  carries the auto-merged version (blob-identical to the rebased single commit).
- The split deliberately puts the `SocketPorts::get_all` harness change in the same commit
  as the first test that uses it, keeping every step lint-clean.
- Ordering constraints honored: `define_test_config!` lines land with their fixtures; the
  legacy-port `Option` change and the exhaustive `Config` destructure tie the minimal
  `lib.rs` wiring into the config commit.
- The FINDINGS.md items marked FIXED (`--validate` ordering, wildcard-overlap validation,
  shared top-level certificate load, harness TOML parsing, the two added tests) are part
  of the squashed commit being split and therefore present throughout the progression's
  final state.
