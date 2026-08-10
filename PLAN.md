  # Configurable Multi-Endpoint DNS Listeners

  ## Summary

  Add self-contained [[listeners]] blocks so one Hickory DNS process can bind multiple IP-and-port combinations. Each block selects the protocols
  served on that endpoint and carries its own secure-listener settings.

  Legacy configurations remain fully supported. When [[listeners]] is present, it becomes the authoritative listener configuration.

  ## Configuration and Behavior

  - Add this TOML interface:

  [[listeners]]
  address = "0.0.0.0"
  port = 53
  protocols = ["udp", "tcp"]

  [[listeners]]
  address = "192.0.2.10"
  port = 853
  protocols = ["tls", "quic"]
  ssl_keylog_enabled = false

  [listeners.tls_cert]
  path = "sec/example.cert.pem"
  private_key = "sec/example.key.pem"
  endpoint_name = "ns.example.com"

  [[listeners]]
  address = "192.0.2.10"
  port = 443
  protocols = ["https"]
  http_endpoint = "/dns-query"

  [listeners.tls_cert]
  path = "sec/example.cert.pem"
  private_key = "sec/example.key.pem"
  endpoint_name = "ns.example.com"

  - Require address, port, and a non-empty protocols list. Supported values are udp, tcp, tls, https, and quic.
  - Require tls_cert for any block containing tls, https, or quic. Keep endpoint_name optional.
  - Default listener-local http_endpoint to /dns-query and ssl_keylog_enabled to false.
  - Keep access controls, request timeout, UDP/TCP socket tuning, and protocol-disable settings global.
  - Global and CLI --disable-* switches continue to suppress matching protocols across all listeners.

  ## Compatibility and Validation

  - If [[listeners]] is absent, preserve current address lists, global ports, certificates, secure settings, defaults, and CLI overrides exactly.
  - If [[listeners]] is present, ignore legacy listener addresses, ports, global certificate, HTTP endpoint, and key-log settings, emitting warnings
    for explicitly supplied legacy fields.

  - Reject --port, --tls-port, --https-port, or --quic-port when [[listeners]] is active; endpoint ports must remain unambiguous.
  - Allow at most one TCP-family protocol (tcp, tls, https) and one UDP-family protocol (udp, quic) for each socket address. Apply this across blocks
    as well as within one block.

  - Reject duplicate protocols, empty listener lists, secure settings on plaintext-only blocks, HTTPS settings without https, missing certificates, and
    protocols unavailable in the compiled feature set.

  - Surface semantic errors during --validate, before attempting socket binds.

  ## Implementation Changes

  - Add internal listener and protocol configuration types with strict Serde unknown-field handling and a normalization/validation step.
  - Normalize legacy configuration into the same runtime listener representation, keeping startup code independent of which syntax was used.
  - Refactor server setup to iterate normalized endpoints, load each secure listener’s certificate, build its TLS configuration, and register the
    appropriate UDP or TCP handler.

  - Update startup logging and the integration-test harness to retain multiple socket addresses per protocol rather than one address per IP family.
  - Document the new blocks and legacy precedence in tests/test-data/test_configs/example.toml.

  ## Test Plan

  - Parse IPv4, IPv6, multiple-port, plaintext, and secure listener blocks.
  - Verify validation failures for missing fields, unsupported protocols, incompatible socket-sharing, missing certificates, misplaced secure settings,
    duplicates, and CLI port overrides.

  - Run integration queries against two UDP/TCP ports on one interface.
  - Exercise listener-local DoT, DoH, and DoQ endpoints, including distinct certificates/settings where practical.
  - Confirm legacy example, IPv4-only, IPv6-only, TLS, HTTPS, and QUIC configurations behave unchanged.
  - Run just fmt, focused hickory-dns tests, just clippy, and just all-features.

  ## Assumptions

  - “Interface” means an IP address, not an OS interface name such as eth0.
  - One endpoint may combine protocols only when they occupy different socket families.
  - Certificate reuse is expressed by repeating the certificate block; named TLS profiles are outside this change.
  - DNS-over-HTTP/3 is outside scope because the server binary does not currently expose an H3 listener.
