# Overview

This crate provides a `hickory-dns` application, a safe and secure DNS server with a variety of 
protocol features (DNSSEC, TSIG, SIG(0), DoT, DoQ, DoH). It can be operated as an authoritative
DNS server, forwarding resolver, stub resolver, or a recursive resolver (experimental).
Zone data can be managed in-memory, with flat files, or with an SQLite database.

If you are writing your own Rust application, refer to the [`hickory-server`], [`hickory-client`], 
[`hickory-resolver`] and [`hickory-recursor`] library crates instead.

[`hickory-server`]: ../crates/server
[`hickory-client`]: ../crates/client
[`hickory-resolver`]: ../crates/resolver
[`hickory-recursor`]: ../crates/recursor

## Features

- Dynamic Update with sqlite journaling backend (SIG0)
- DNSSEC online signing (with NSEC and NSEC3)
- Forwarding stub resolver
- ANAME resolution, for zone mapping aliases to A and AAAA records
- Additionals section generation for aliasing record types

## Cryptography provider

Features requiring cryptography require selecting a specific cryptography 
provider. See the [project README] for more information.

[project README]: ../README.md#Cryptography-provider

## Protocol support

The following DNS protocols are optionally supported:

* DNS over TLS (DoT)
* DNS over HTTP/2 (DoH)
* DNS over QUIC (DoQ)

In order to use these optional protocols you must enable a cargo feature
corresponding to your desired cryptography provider:

* DoT: `tls-aws-lc-rs` or `tls-ring`
* DoH: `https-aws-lc-rs` or `https-ring`
* DoQ: `quic-aws-lc-rs` or `quic-ring`

DNS over HTTP/3 (DoH3) is available in the `hickory-server` library but is not
currently exposed by the `hickory-dns` binary or its `[[listeners]]`
configuration.

## DNSSEC

In order to use DNSSEC you must enable a cargo feature corresponding to your 
desired cryptography provider:

* `dnssec-aws-lc-rs`
* `dnssec-ring`

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

When using dynamic DNS, zones will be automatically resigned on any record updates.

## Other crate features

* `sqlite` (enabled by default) - support maintaining zone data in a SQLite database.
  Required for dynamic DNS support.
* `blocklist` - support configuring allow/deny blocklists.
* `recursor` - enable experimental support for recursive resolution.
* `resolver` (enabled by default) - enable forwarding zones to another resolver.
* `rustls-platform-verifier` (enabled by default) - use the system verifier for TLS with
   [rustls-platform-verifier].
* `webpki-roots` - use the [webpki-roots] crate for TLS certificate verification.
* `prometheus-metrics` - enable exposing [Prometheus] metrics for scraping.
* `systemd` - enable [systemd] readiness (`READY=1`/`STOPPING=1`) and watchdog notifications.
* `ascii-art` (enabled by default) - print project logo at start.

[rustls-platform-verifier]: https://crates.io/crates/rustls-platform-verifier
[webpki-roots]: https://crates.io/crates/webpki-roots
[Prometheus]: https://prometheus.io/
[systemd]: https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html

## Running

Warning: Hickory DNS is still under development, running in production is not
recommended.

- Building

```shell
cargo build --release --bin hickory-dns
```

- Verify the version

```shell
./target/release/hickory-dns --version
```

- Get help

```shell
./target/release/hickory-dns --help
```

- Launch `hickory-dns` server with test config

Listener addresses, ports, and protocols are configured exclusively through
`[[listeners]]` blocks in the TOML configuration file.

```shell
./target/release/hickory-dns -c ./tests/test-data/test_configs/example.toml
```

To serve multiple address-and-port combinations from one process, use
self-contained `[[listeners]]` blocks. Use `dot` for DNS over TLS, `doh` for
DNS over HTTP/2, and `doq` for DNS over QUIC:

```toml
[[listeners]]
address = "0.0.0.0"
port = 53
protocols = ["udp", "tcp"]

[[listeners]]
address = "192.0.2.10"
port = 853
protocols = ["dot", "doq"]

[listeners.tls_cert]
path = "sec/example.cert.pem"
private_key = "sec/example.key.pem"
endpoint_name = "ns.example.com"
```

At least one `[[listeners]]` block is required. Listener addresses, ports,
certificates, HTTP endpoints, and key-log settings must be configured in those
blocks. The zone directory, NSID, and Prometheus settings are also controlled by
the TOML file rather than command-line overrides. See the documented
[`example.toml`](../tests/test-data/test_configs/example.toml) for the full
configuration interface.

The `zone_directory` setting is used only for zone files and related zone data.
Relative TLS certificate and private key paths are resolved from the directory
containing the TOML configuration file.

Omitting `nsid` disables NSID responses. Configure a literal value with
`nsid = "dns-server-01"`, or use `nsid = { source = "hostname" }`. Prometheus is
enabled only when `prometheus_listen_addr` is configured.

- Query the just launched server with `dig`

```shell
dig @127.0.0.1 -p 53 www.example.com
```
