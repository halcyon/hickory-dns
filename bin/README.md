# Overview

This crate provides a `hickory-dns` application, a safe and secure DNS server with a variety of 
protocol features (DNSSEC, TSIG, SIG(0), DoT, DoQ, DoH). It can be operated as an authoritative
DNS server, forwarding resolver, stub resolver, or a recursive resolver (experimental).
Zone data can be managed in-memory, with flat files, or with an SQLite database.

If you are writing your own Rust application, refer to the [`hickory-server`], [`hickory-net`],
and [`hickory-resolver`] library crates instead.

[`hickory-server`]: ../crates/server
[`hickory-net`]: ../crates/net
[`hickory-resolver`]: ../crates/resolver

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
* DNS over HTTP/3 (DoH3)

In order to use these optional protocols you must enable a cargo feature
corresponding to your desired cryptography provider:

* DoT: `tls-aws-lc-rs` or `tls-ring`
* DoH: `https-aws-lc-rs` or `https-ring`
* DoQ: `quic-aws-lc-rs` or `quic-ring`
* DoH3: `h3-aws-lc-rs` or `h3-ring`

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

Note that if the `-p` parameter is not passed, the server will run on default
DNS ports. There are separate port options for DoT and DoH servers, see
`hickory-dns --help`

```shell
./target/release/hickory-dns -c ./tests/test-data/test_configs/example.toml -z ./tests/test-data/test_configs/ -p 24141
```

- Query the just launched server with `dig`

```shell
dig @127.0.0.1 -p 24141 www.example.com
```

## Listeners

By default the server binds every address in `listen_addrs_ipv4`/`listen_addrs_ipv6`
(or all unspecified addresses) to a single port. To bind more than one port, or to
choose the protocols served per address and port, define one or more `[[listeners]]`
sections in the configuration file:

```toml
[[listeners]]
address = "10.0.1.1"
port = 53
protocols = ["udp", "tcp"]

[[listeners]]
address = "10.0.1.1"
port = 1053
protocols = ["udp", "tcp"]
```

When `[[listeners]]` sections are present they replace the `listen_addrs_ipv4`,
`listen_addrs_ipv6` and `*_listen_port` settings; combining both is an error, and
startup fails naming every conflicting setting that must be removed.
`protocols` defaults to `["udp", "tcp"]`; `tls`, `https` and `quic` are also
supported. A listener may override the process-wide `tls_cert`, `http_endpoint`
and `ssl_keylog_enabled` settings: a listener setting applies where present, and
the top-level setting otherwise. A listener `tls_cert` replaces the top-level
`tls_cert` entirely: the `endpoint_name` in it is used as-is, without falling
back to the top-level `endpoint_name`. Secure protocols require a certificate from the
listener or the top-level `tls_cert`. The `-p`, `--tls-port`,
`--https-port` and `--quic-port` command line options are rejected when
`[[listeners]]` is configured; set ports in the listener entries. `--disable-tcp`, `--disable-udp`,
`--disable-tls`, `--disable-https` and `--disable-quic` remove the matching
protocols from every listener. Startup fails if two entries claim the same
socket, if a listener lists `tls`, `https` or `quic` without a `tls_cert`, if a
listener specifies `tls_cert`, `http_endpoint` or `ssl_keylog_enabled` that no
protocol on it uses, or if the build lacks a listed protocol.
