# Detailed Plan: Self-Contained `[[listeners]]` Blocks for Hickory DNS

## Goal

Allow a single Hickory DNS process to bind multiple IP-and-port combinations, each with its own protocol selection and optional per-endpoint socket settings, via `[[listeners]]` TOML blocks. Supported protocols: `udp`, `tcp`, `dot`, `doh`, `doq`.

## Design Principles

- **Minimal changes**: No modifications to `crates/server` or protocol implementations. The existing `Server` API already supports registering individual listeners independently.
- **Backward compatible**: Existing config files work unchanged. `[[listeners]]` is an alternative model — legacy config and listeners cannot be mixed.
- **Global flags as upper bounds**: CLI overrides (`--disable-tcp`, etc.) and config-level `disable_*` flags still apply globally; a listener that enables a globally disabled protocol is a validation error.
- **Validation**: `--validate` catches semantic errors (duplicate bindings, TLS protocols without certs) before startup.

---

## File: `bin/src/config/mod.rs`

### Change 1: Import `IpAddr`

**Why**: `ListenerConfig` uses `IpAddr` (not just `Ipv4Addr`/`Ipv6Addr`) to represent the bind address.

**Before** (line 16):
```rust
use std::{
    fmt, fs, io,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
```

**After**:
```rust
use std::{
    fmt, fs, io,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
```

---

### Change 2: Add `ListenerProtocols` struct

**Location**: After `TcpSocketConfig` impl (around line 243).

**Why**: Each listener needs to declare which protocols it serves. Defaults to all disabled (opt-in) for safety — you must explicitly enable each protocol.

```rust
/// Protocols enabled on a single listener endpoint.
///
/// Defaults to all protocols disabled; you must explicitly enable each protocol you want.
/// The global `disable_*` flags still act as an upper bound.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerProtocols {
    /// Enable plain DNS over UDP on this endpoint.
    #[serde(default)]
    pub(crate) udp: bool,
    /// Enable plain DNS over TCP on this endpoint.
    #[serde(default)]
    pub(crate) tcp: bool,
    /// Enable DNS-over-TLS on this endpoint.
    #[serde(default)]
    pub(crate) dot: bool,
    /// Enable DNS-over-HTTPS on this endpoint.
    #[serde(default)]
    pub(crate) doh: bool,
    /// Enable DNS-over-QUIC on this endpoint.
    #[serde(default)]
    pub(crate) doq: bool,
}
```

---

### Change 3: Add `ListenerConfig` struct

**Location**: After `ListenerProtocols`.

**Why**: The core new config type. Each `[[listeners]]` block deserializes into one of these. Per-endpoint socket configs override globals when present.

```rust
/// A single listener endpoint configuration.
///
/// Each `[[listeners]]` block defines one IP-and-port combination with its own protocol selection
/// and optional per-endpoint socket settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerConfig {
    /// The IP address to bind this listener to.
    pub(crate) address: IpAddr,
    /// The port to bind this listener to.
    pub(crate) port: u16,
    /// Which protocols to serve on this endpoint.
    #[serde(default)]
    pub(crate) protocols: ListenerProtocols,
    /// UDP socket settings for this listener (overrides global when set).
    pub(crate) udp_socket: Option<UdpSocketConfig>,
    /// TCP socket settings for this listener (overrides global when set).
    pub(crate) tcp_socket: Option<TcpSocketConfig>,
    /// TLS certificate for this listener (overrides global when set).
    ///
    /// If not specified, the global `tls_cert` is used. If neither is set, TLS protocols
    /// (`dot`, `doh`, `doq`) cannot be enabled on this listener.
    #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
    pub(crate) tls_cert: Option<TlsCertConfig>,
}
```

---

### Change 5: Add `listeners` field to `Config`

**Location**: In the `Config` struct, after `allow_networks` and before `udp_socket` (around line 170).

**Why**: Wire `[[listeners]]` into the main config.

```rust
    /// Per-endpoint listener configurations.
    ///
    /// Each `[[listeners]]` block defines an IP-and-port combination with its own protocol
    /// selection. These are additive to the legacy `listen_addrs_*` / `listen_port` configuration.
    #[serde(default)]
    pub(crate) listeners: Vec<ListenerConfig>,
```

---

### Change 6: Add `ConfigError::Validation` variant

**Location**: At the end of `ConfigError` enum (around line 834).

**Why**: Semantic validation errors (duplicates, missing certs) are distinct from TOML parse errors.

```rust
/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum ConfigError {
    // ... existing variants ...

    /// A semantic validation error in the configuration
    #[error("validation error: {0}")]
    Validation(String),
}
```

---

### Change 7: Add `Config::validate()` method

**Location**: In the `impl Config` block, after `from_toml()`.

**Why**: Catch configuration errors before startup. Checks:
1. Legacy config and `[[listeners]]` are mutually exclusive — you can't use both
2. No duplicate bindings among listeners themselves
3. TLS protocols (`dot`, `doh`, `doq`) require `tls_cert` to be configured (listener-specific or global)
4. Listeners don't enable protocols that are globally disabled
5. Listeners don't enable protocols that aren't compiled in (e.g., `dot = true` without TLS support)

```rust
/// Validate the configuration semantically.
///
/// Checks for duplicate bindings, TLS protocol requirements, and port validity.
/// Call this after `read_config()` but before starting the server.
pub(crate) fn validate(
    &self,
    disable_udp: bool,
    disable_tcp: bool,
    #[cfg(feature = "__tls")] disable_tls: bool,
    #[cfg(feature = "__https")] disable_https: bool,
    #[cfg(feature = "__quic")] disable_quic: bool,
) -> Result<(), ConfigError> {
    // Legacy config and [[listeners]] are mutually exclusive
    let has_legacy = !self.listen_addrs_ipv4.is_empty() || !self.listen_addrs_ipv6.is_empty();
    let has_listeners = !self.listeners.is_empty();

    if has_legacy && has_listeners {
        return Err(ConfigError::Validation(
            "cannot use both legacy listen_addrs_ipv4/listen_addrs_ipv6 and [[listeners]] blocks; \
             remove listen_addrs_ipv4 and listen_addrs_ipv6 from your config to use [[listeners]]"
                .to_string(),
        ));
    }

    // Validate each [[listeners]] entry
    let mut seen = std::collections::HashSet::new();
    for listener in &self.listeners {
        let key = (listener.address, listener.port);

        if !seen.insert(key) {
            return Err(ConfigError::Validation(format!(
                "duplicate listener binding: {key:?}"
            )));
        }

        // Check for protocol conflicts with global disable flags
        if listener.protocols.udp && disable_udp {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables udp but it is globally disabled"
            )));
        }
        if listener.protocols.tcp && disable_tcp {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables tcp but it is globally disabled"
            )));
        }

        // Check for protocols that are enabled but not compiled in
        #[cfg(not(feature = "__tls"))]
        if listener.protocols.dot {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables dot but TLS support is not compiled in"
            )));
        }
        #[cfg(not(feature = "__https"))]
        if listener.protocols.doh {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables doh but HTTPS support is not compiled in"
            )));
        }
        #[cfg(not(feature = "__quic"))]
        if listener.protocols.doq {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables doq but QUIC support is not compiled in"
            )));
        }

        #[cfg(feature = "__tls")]
        if listener.protocols.dot && disable_tls {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables dot but it is globally disabled"
            )));
        }
        #[cfg(feature = "__https")]
        if listener.protocols.doh && disable_https {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables doh but it is globally disabled"
            )));
        }
        #[cfg(feature = "__quic")]
        if listener.protocols.doq && disable_quic {
            return Err(ConfigError::Validation(format!(
                "listener {key:?} enables doq but it is globally disabled"
            )));
        }

        // Check if any TLS-based protocol is enabled without a certificate
        #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
        {
            let has_tls_protos = listener.protocols.dot || listener.protocols.doh || listener.protocols.doq;
            let has_cert = listener.tls_cert.is_some() || self.tls_cert.is_some();

            if has_tls_protos && !has_cert {
                let tls_protos: Vec<&str> = [
                    (listener.protocols.dot, "dot"),
                    (listener.protocols.doh, "doh"),
                    (listener.protocols.doq, "doq"),
                ]
                .into_iter()
                .filter_map(|(enabled, name)| enabled.then_some(name))
                .collect();

                return Err(ConfigError::Validation(format!(
                    "listener {key:?} enables TLS protocols ({}) but no tls_cert is configured (neither on listener nor globally)",
                    tls_protos.join(", ")
                )));
            }
        }
    }

    Ok(())
}
```

---

## File: `bin/src/lib.rs`

### Change 1: Import `ListenerConfig`

**Before** (line 38):
```rust
use config::{Config, TcpSocketConfig, UdpSocketConfig};
```

**After**:
```rust
use config::{Config, ListenerConfig, TcpSocketConfig, UdpSocketConfig};
```

---

### Change 2: Call `Config::validate()` after reading config

**Location**: In `DnsServer::run()`, right after `Config::read_config()` (around line 202).

**Why**: Fail fast on semantic errors before zone loading or binding.

```rust
let config = Config::read_config(config_path)
    .map_err(|err| format!("failed to read config file from {config_path:?}: {err}"))?;

config.validate(
    disable_udp,
    disable_tcp,
    #[cfg(feature = "__tls")]
    disable_tls,
    #[cfg(feature = "__https")]
    disable_https,
    #[cfg(feature = "__quic")]
    disable_quic,
)
.map_err(|err| format!("invalid configuration: {err}"))?;
```

---

### Change 3: Destructure `listeners` from Config

**Location**: In the `let Config { ... } = config;` block (around line 302).

**Why**: Extract the new field for use in server setup.

```rust
let Config {
    // ... existing fields ...
    udp_socket: udp_socket_config,
    tcp_socket: tcp_socket_config,
    listeners,
} = config;
```

---

### Change 3b: Skip legacy protocol setup when `[[listeners]]` is present

**Location**: In `DnsServer::run()`, wrap the legacy protocol setup block (around line 376).

**Why**: When `[[listeners]]` is present, legacy config is disabled. Skip the legacy protocol setup entirely, including the auto-default addresses (`0.0.0.0` and `::`).

```rust
// Set up legacy protocol listeners (only if not using [[listeners]])
if listeners.is_empty() {
    let listen_port = port.unwrap_or(listen_port);
    match disable_udp {
        true => info!("UDP protocol is disabled"),
        false => setup.udp(listen_port)?,
    }

    match disable_tcp {
        true => info!("TCP protocol is disabled"),
        false => setup.tcp(listen_port)?,
    }

    #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
    if setup.cert_resolver.is_none() {
        info!("TLS certificates are not provided");
        info!("TLS related protocols (TLS, HTTPS and QUIC) are disabled")
    }

    #[cfg(feature = "__tls")]
    match disable_tls {
        true => info!("TLS protocol is disabled"),
        false => setup.tls(tls_port.unwrap_or(tls_listen_port))?,
    }

    #[cfg(feature = "__https")]
    match disable_https {
        true => info!("HTTPS protocol is disabled"),
        false => setup.https(
            https_port.unwrap_or(https_listen_port),
            &http_endpoint,
            tls_cert
                .as_ref()
                .and_then(|config| config.endpoint_name.as_deref()),
        )?,
    }

    #[cfg(feature = "__quic")]
    match disable_quic {
        true => info!("QUIC protocol is disabled"),
        false => setup.quic(quic_port.unwrap_or(quic_listen_port))?,
    }
}
```

---

### Change 5: Add helper methods and `bind_listener()` to `ServerSetup`

**Location**: Inside `impl ServerSetup<'_>`, after the existing `quic()` method.

**Why**: Three small helpers eliminate repeated socket/TLS boilerplate across protocol blocks:
- `build_and_log_tcp` — shared by TCP, DoT, DoH
- `build_and_log_udp` — shared by DoQ
- `build_tls_config` — shared by DoT, DoH, DoQ

`bind_listener` itself then uses these helpers instead of duplicating socket creation, address logging, and TLS config setup for each protocol.

```rust
/// Build a TCP listener, log the bind and listening addresses.
fn build_and_log_tcp(
    &self,
    protocol: &str,
    addr: IpAddr,
    port: u16,
    tcp_cfg: TcpSocketConfig,
) -> Result<TcpListener, String> {
    info!("binding {protocol} to {addr:?}:{port}");

    let listener = build_tcp_listener(addr, port, tcp_cfg)
        .map_err(|err| format!("failed to bind to {protocol} socket address {addr:?}: {err}"))?;

    info!(
        "listening for {protocol} on {:?}",
        listener
            .local_addr()
            .map_err(|err| format!("failed to lookup local address: {err}"))?
    );

    Ok(listener)
}

/// Build a UDP socket, log the bind and listening addresses.
fn build_and_log_udp(
    &self,
    protocol: &str,
    addr: IpAddr,
    port: u16,
    udp_cfg: UdpSocketConfig,
) -> Result<UdpSocket, String> {
    info!("binding {protocol} to {addr:?}:{port}");

    let socket = build_udp_socket(addr, port, udp_cfg)
        .map_err(|err| format!("failed to bind to {protocol} socket address {addr:?}: {err}"))?;

    info!(
        "listening for {protocol} on {:?}",
        socket
            .local_addr()
            .map_err(|err| format!("failed to lookup local address: {err}"))?
    );

    Ok(socket)
}

/// Build a TLS server config with optional SSL key logging.
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
fn build_tls_config(
    &self,
    protocol: &str,
    protocol_name: &[u8],
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, String> {
    let mut tls_config = default_tls_server_config(protocol_name, cert_resolver)
        .map_err(|err| format!("failed to build default TLS config: {err}"))?;
    if self.ssl_keylog_enabled {
        warn!("{protocol} SSL_KEYLOG_FILE support enabled");
        tls_config.key_log = Arc::new(KeyLogFile::new());
    }

    Ok(Arc::new(tls_config))
}

/// Bind a single [[listeners]] endpoint with its own protocols and socket settings.
///
/// Note: Protocol conflicts with global disable flags are caught during validation,
/// so we don't need to check them here.
fn bind_listener(
    &mut self,
    listener: &ListenerConfig,
    #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))] zone_dir: &Path,
    #[cfg(feature = "__https")] http_endpoint: &str,
    #[cfg(feature = "__tls")] dns_hostname: Option<&str>,
) -> Result<(), String> {
    let addr = listener.address;
    let port = listener.port;
    let udp_cfg = listener.udp_socket.unwrap_or(self.udp_socket_config);
    let tcp_cfg = listener.tcp_socket.unwrap_or(self.tcp_socket_config);

    // UDP
    if listener.protocols.udp {
        #[cfg(unix)]
        let num_sockets = udp_cfg.sockets.unwrap_or(1);
        #[cfg(not(unix))]
        let num_sockets = 1_usize;
        info!("binding {num_sockets} UDP socket(s) to {addr:?}:{port}");

        let first_socket = build_udp_socket(addr, port, udp_cfg)
            .map_err(|err| format!("failed to bind to UDP socket address {addr:?}: {err}"))?;
        let bound_addr = first_socket
            .local_addr()
            .map_err(|err| format!("failed to lookup local address: {err}"))?;
        self.server.register_socket(first_socket);

        for _ in 1..num_sockets {
            self.server.register_socket(
                build_udp_socket(addr, port, udp_cfg).map_err(|err| {
                    format!("failed to bind to UDP socket address {addr:?}: {err}")
                })?,
            );
        }

        info!("listening for UDP on {bound_addr:?}");
    }

    // TCP
    if listener.protocols.tcp {
        let tcp_listener = self.build_and_log_tcp("TCP", addr, port, tcp_cfg)?;

        self.server.register_listener(
            tcp_listener,
            self.tcp_request_timeout,
            tcp_cfg.response_buffer_size,
        );
    }

    // DoT
    #[cfg(feature = "__tls")]
    if listener.protocols.dot {
        let cert_resolver = self.resolve_listener_cert(listener, zone_dir)?;

        let tls_listener = self.build_and_log_tcp("TLS", addr, port, tcp_cfg)?;
        let tls_config = self.build_tls_config("DoT", b"dot", cert_resolver)?;

        self.server
            .register_tls_listener_with_tls_config(
                tls_listener,
                self.tcp_request_timeout,
                tls_config,
            )
            .map_err(|err| format!("failed to register TLS listener: {err}"))?;
    }

    // DoH
    #[cfg(feature = "__https")]
    if listener.protocols.doh {
        let cert_resolver = self.resolve_listener_cert(listener, zone_dir)?;

        let https_listener = self.build_and_log_tcp("HTTPS", addr, port, tcp_cfg)?;
        let tls_config = self.build_tls_config("DoH", b"h2", cert_resolver)?;

        self.server
            .register_https_listener_with_tls_config(
                https_listener,
                self.tcp_request_timeout,
                tls_config,
                dns_hostname.map(|s| s.to_owned()),
                http_endpoint.to_owned(),
            )
            .map_err(|err| format!("failed to register HTTPS listener: {err}"))?;
    }

    // DoQ
    #[cfg(feature = "__quic")]
    if listener.protocols.doq {
        let cert_resolver = self.resolve_listener_cert(listener, zone_dir)?;

        let quic_listener = self.build_and_log_udp("QUIC", addr, port, udp_cfg)?;
        let tls_config = self.build_tls_config("DoQ", b"doq", cert_resolver)?;

        self.server
            .register_quic_listener_and_tls_config(
                quic_listener,
                self.tcp_request_timeout,
                tls_config,
            )
            .map_err(|err| format!("failed to register QUIC listener: {err}"))?;
    }

    Ok(())
}

/// Resolve the certificate resolver for a listener, using the listener's tls_cert
/// if set, or falling back to the global cert_resolver.
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
fn resolve_listener_cert(
    &self,
    listener: &ListenerConfig,
    zone_dir: &Path,
) -> Result<Arc<dyn ResolvesServerCert>, String> {
    // Use listener-specific cert if set
    if let Some(cert_config) = &listener.tls_cert {
        return cert_config.load(zone_dir).map_err(|err| {
            format!(
                "failed to load TLS certificate for listener {:?}:{:?} from {:?}: {err}",
                listener.address, listener.port, cert_config.path
            )
        });
    }

    // Fall back to global cert
    self.cert_resolver.clone().ok_or_else(|| {
        format!(
            "listener {:?}:{:?} requires TLS but no tls_cert is configured (neither on listener nor globally)",
            listener.address, listener.port
        )
    })
}
```
---

### Change 6: Wire listeners into `DnsServer::run()`

**Location**: After the legacy protocol setup block (after `setup.quic()`), before privilege dropping (around line 410).

**Why**: After setting up the legacy addresses, iterate over `[[listeners]]` and bind each one.

```rust
// Set up explicit [[listeners]] endpoints
for listener in &listeners {
    info!(
        "setting up listener {}:{} (protocols: udp={}, tcp={}, dot={}, doh={}, doq={})",
        listener.address,
        listener.port,
        listener.protocols.udp,
        listener.protocols.tcp,
        listener.protocols.dot,
        listener.protocols.doh,
        listener.protocols.doq,
    );

    setup.bind_listener(
        listener,
        #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
        &zone_dir,
        #[cfg(feature = "__https")]
        &http_endpoint,
        #[cfg(feature = "__tls")]
        tls_cert
            .as_ref()
            .and_then(|config| config.endpoint_name.as_deref()),
    )?;
}
```

---

## Example Configurations

### Basic multi-endpoint

```toml
# Legacy config is automatically disabled when [[listeners]] is present

[[listeners]]
address = "127.0.0.1"
port = 5353
protocols = { udp = true, tcp = true }

[[listeners]]
address = "10.0.0.1"
port = 853
protocols = { dot = true }

[[listeners]]
address = "10.0.0.1"
port = 443
protocols = { doh = true, doq = true }
tcp_socket = { listen_backlog = 256 }

### Per-listener TLS certificate

```toml
[[listeners]]
address = "10.0.0.1"
port = 853
protocols = { dot = true }
tls_cert = { path = "certs/example.com.pem", private_key = "certs/example.com.key" }

[[listeners]]
address = "10.0.0.2"
port = 853
protocols = { dot = true }
tls_cert = { path = "certs/other.com.pem", private_key = "certs/other.com.key" }
```

### Listener with all protocols

```toml
[[listeners]]
address = "192.168.1.1"
port = 53
protocols = { udp = true, tcp = true, dot = true, doh = true, doq = true }
```

### Per-endpoint socket tuning

```toml
[[listeners]]
address = "10.0.0.1"
port = 53
protocols = { udp = true, tcp = true }
udp_socket = { recv_buffer_size = 4194304, send_buffer_size = 4194304 }
tcp_socket = { listen_backlog = 512, response_buffer_size = 64 }
```

---

## Validation Behavior

Running `--validate` now catches:

1. **Mixing legacy and listeners**: Using both `listen_addrs_*` and `[[listeners]]` in the same config. Note: if `[[listeners]]` is present, legacy config is automatically disabled (including auto-default addresses).
2. **Duplicate bindings**: Two listeners try to bind the same `(address, port)`.
3. **TLS protocols without certs**: A listener enables `dot`, `doh`, or `doq` but neither a listener-specific `tls_cert` nor a global `tls_cert` is configured.
4. **Protocol conflicts with global flags**: A listener enables a protocol that's globally disabled (e.g., `tcp = true` with `--disable-tcp`).
5. **Protocol not compiled in**: A listener enables a protocol whose feature isn't compiled in (e.g., `dot = true` without TLS support).

Example errors:
```
Error: invalid configuration: validation error: cannot use both legacy listen_addrs_ipv4/listen_addrs_ipv6 and [[listeners]] blocks; remove listen_addrs_ipv4 and listen_addrs_ipv6 from your config to use [[listeners]]
Error: invalid configuration: validation error: duplicate listener binding: (127.0.0.1, 53)
Error: invalid configuration: validation error: listener (10.0.0.1, 53) enables tcp but it is globally disabled
Error: invalid configuration: validation error: listener (10.0.0.1, 853) enables dot but TLS support is not compiled in
```

---

## What Did NOT Change

- `crates/server/src/server/mod.rs` — the `Server` API already supports per-listener registration
- Protocol implementations (`proto`, `net`, `resolver`) — no changes needed
- CLI flags — config-only for now (could add `--listener` later)
- TLS cert handling — supports both global `tls_cert` and per-listener `tls_cert` (listener-specific overrides global)
