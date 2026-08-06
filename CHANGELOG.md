# The CHANGELOG has moved

Current release notes are maintained on [GitHub Releases](https://github.com/hickory-dns/hickory-dns/releases).

## Unreleased

### Added

- Added self-contained `[[listeners]]` configuration blocks so one
  `hickory-dns` process can serve multiple address-and-port combinations with
  endpoint-specific protocols (`dot`, `doh` over HTTP/2, and `doq`),
  certificates, DNS-over-HTTPS paths, and TLS key logging settings.

### Changed

- `hickory-dns` now requires listener blocks. Legacy listener fields and the
  `--port`, `--tls-port`, `--https-port`, `--quic-port`, `--zonedir`,
  `--prometheus-listen-address`, `--disable-*`, `--nsid`, and `--nsid-hostname`
  overrides were removed. Listener protocols, the zone directory, NSID, and
  Prometheus settings are now controlled by TOML. The global protocol `disable_*`
  settings were also removed because each listener's `protocols` list is
  authoritative.
- The zone data root is now configured with `zone_directory`. Relative TLS
  certificate and private key paths are resolved from the directory containing
  the TOML configuration file instead of the zone directory.
- NSID is configured through one optional `nsid` field, which accepts a literal
  payload or `{ source = "hostname" }`. Prometheus is enabled only when
  `prometheus_listen_addr` is configured; `disable_prometheus` and the implicit
  `127.0.0.1:9000` listener were removed.

The old CHANGELOG can be reviewed at [`OLD-CHANGELOG.md`](OLD-CHANGELOG.md).
