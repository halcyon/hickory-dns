#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use std::sync::Arc;
use std::time::Duration;
use std::{
    io::Error,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Parser;
#[cfg(feature = "metrics")]
use metrics_process::Collector;
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use rustls::KeyLogFile;
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use rustls::server::ResolvesServerCert;
use socket2::{Domain, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(any(feature = "metrics", all(unix, feature = "systemd")))]
use tokio::time::sleep;
#[cfg(any(
    feature = "__tls",
    feature = "__https",
    feature = "__quic",
    all(unix, feature = "systemd"),
))]
use tracing::warn;
use tracing::{error, info};

use hickory_server::proto::ProtoError;
use hickory_server::proto::rr::rdata::opt::NSIDPayload;
#[cfg(feature = "__tls")]
use hickory_server::server::default_tls_server_config;
use hickory_server::{server::Server, zone_handler::Catalog};

mod config;
use config::{Config, ListenerProtocol, NsidConfig, NsidSource, TcpSocketConfig, UdpSocketConfig};

#[cfg(feature = "__dnssec")]
pub mod dnssec;

#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "metrics")]
use crate::metrics::ConfigMetrics;

#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;
#[cfg(feature = "prometheus-metrics")]
use prometheus_server::PrometheusServer;

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(name = "Hickory DNS named server", version, about)]
pub struct DnsServer {
    /// Test validation of configuration files
    #[clap(long = "validate")]
    validate: bool,

    /// Number of runtime workers, defaults to the number of CPU cores
    #[clap(long = "workers")]
    pub workers: Option<usize>,

    /// Disable INFO messages, WARN and ERROR will remain
    #[clap(short = 'q', long = "quiet", conflicts_with = "debug")]
    pub quiet: bool,

    /// Turn on `DEBUG` messages (default is only `INFO`)
    #[clap(short = 'd', long = "debug", conflicts_with = "quiet")]
    pub debug: bool,

    /// Path to configuration file of named server
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/named.toml",
        value_name = "NAME",
        value_hint=clap::ValueHint::FilePath,
    )]
    config: PathBuf,
}

impl DnsServer {
    pub async fn run(self) -> Result<(), String> {
        let Self {
            validate,
            workers: _, // Used in `main()`
            quiet: _,   // Used in `main()`
            debug: _,   // Used in `main()`
            config,
        } = self;

        let config_path = Path::new(&config);
        #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
        let config_directory = config_path.parent().unwrap_or_else(|| Path::new("."));
        info!("loading configuration from: {config_path:?}");
        let config = Config::read_config(config_path)
            .map_err(|err| format!("failed to read config file from {config_path:?}: {err}"))?;

        let listeners = config
            .normalized_listeners()
            .map_err(|err| format!("failed to validate {config_path:?}: {err}"))?;

        let nsid = configured_nsid(config.nsid.as_ref())?;

        #[cfg(feature = "prometheus-metrics")]
        let prometheus_server_opt = if let Some(socket_addr) = config.prometheus_listen_addr {
            let listener = build_tcp_listener(
                socket_addr.ip(),
                socket_addr.port(),
                TcpSocketConfig::default(),
            )
            .map_err(|err| {
                format!("failed to bind to Prometheus TCP socket address {socket_addr:?}: {err}")
            })?;
            let local_addr = listener
                .local_addr()
                .map_err(|err| format!("failed to look up local address: {err}"))?;

            // Set up Prometheus HTTP server.
            let server = PrometheusServer::new(listener)?;
            info!("listening for Prometheus metrics on {local_addr:?}");
            Some(server)
        } else {
            info!("Prometheus metrics are disabled");
            None
        };

        #[cfg(feature = "metrics")]
        let (process_metrics_collector, config_metrics) = {
            // setup process metrics (cpu, memory, ...) collection
            let collector = Collector::default();
            collector.describe(); // add metric descriptions

            let process_metrics_collector = tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(1)).await;
                    collector.collect();
                }
            });

            // metrics need to be created after the recorder is registered
            // calling increment() after registration is not sufficient
            let config_metrics = ConfigMetrics::new(&config);
            (process_metrics_collector, config_metrics)
        };

        let Config {
            listeners: _,
            #[cfg(feature = "prometheus-metrics")]
                prometheus_listen_addr: _,
            nsid: _,
            tcp_request_timeout,
            zone_directory,
            user,
            group,
            zones,
            drop_privileges,
            deny_networks,
            allow_networks,
            udp_socket: udp_socket_config,
            tcp_socket: tcp_socket_config,
        } = config;

        #[cfg(unix)]
        let mut signal = signal(SignalKind::terminate())
            .map_err(|e| format!("failed to register signal handler: {e}"))?;

        let mut catalog = Catalog::new();
        catalog.set_nsid(nsid);

        for zone in zones {
            let zone_name = zone
                .zone()
                .map_err(|err| format!("failed to read zone name from {config_path:?}: {err}"))?;

            #[cfg(feature = "metrics")]
            config_metrics.increment_zone_metrics(&zone);

            match zone.load(&zone_directory).await {
                Ok(handlers) => catalog.upsert(zone_name.into(), handlers),
                Err(err) => return Err(format!("could not load zone {zone_name}: {err}")),
            }
        }

        if validate {
            info!("configuration files are validated");
            return Ok(());
        }

        // now, run the server, based on the config
        #[cfg_attr(not(feature = "__tls"), allow(unused_mut))]
        let mut server = Server::with_access(catalog, deny_networks, allow_networks);

        let mut setup = ServerSetup {
            server: &mut server,
            tcp_request_timeout,
            udp_socket_config,
            tcp_socket_config,
        };

        for listener in listeners {
            #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
            let cert_resolver = listener
                .tls_cert
                .as_ref()
                .map(|config| {
                    config.load(config_directory).map_err(|err| {
                        format!(
                            "failed to load TLS certificate from {:?}: {err}",
                            config.path
                        )
                    })
                })
                .transpose()?;

            for protocol in listener.protocols {
                match protocol {
                    ListenerProtocol::Udp => setup.udp(listener.socket_addr)?,
                    ListenerProtocol::Tcp => setup.tcp(listener.socket_addr)?,
                    ListenerProtocol::Tls => {
                        #[cfg(feature = "__tls")]
                        setup.tls(
                            listener.socket_addr,
                            cert_resolver.as_ref(),
                            listener.ssl_keylog_enabled,
                        )?;
                    }
                    ListenerProtocol::Https => {
                        #[cfg(feature = "__https")]
                        setup.https(
                            listener.socket_addr,
                            cert_resolver.as_ref(),
                            listener.ssl_keylog_enabled,
                            &listener.http_endpoint,
                            listener
                                .tls_cert
                                .as_ref()
                                .and_then(|config| config.endpoint_name.as_deref()),
                        )?;
                    }
                    ListenerProtocol::Quic => {
                        #[cfg(feature = "__quic")]
                        setup.quic(
                            listener.socket_addr,
                            cert_resolver.as_ref(),
                            listener.ssl_keylog_enabled,
                        )?;
                    }
                }
            }
        }

        // Drop privileges on Unix systems if running as root.
        #[cfg(target_family = "unix")]
        if drop_privileges {
            check_drop_privs(
                user.as_deref().unwrap_or(DEFAULT_USER),
                group.as_deref().unwrap_or(DEFAULT_GROUP),
            )?;
        }
        #[cfg(not(target_family = "unix"))]
        if drop_privileges && (user.is_some() || group.is_some()) {
            return Err("dropping privileges is only supported on Unix systems".to_string());
        }

        #[cfg(unix)]
        {
            let token = server.shutdown_token().clone();
            tokio::spawn(async move {
                signal.recv().await;
                token.cancel();
            });
        }

        // config complete, starting!
        banner();

        // TODO: how to do threads? should we do a bunch of listener threads and then query threads?
        // Ideally the processing would be n-threads for receiving, which hand off to m-threads for
        //  request handling. It would generally be the case that n <= m.
        info!("server starting up, awaiting connections...");

        #[cfg(all(unix, feature = "systemd"))]
        sd_notify::notify(&[sd_notify::NotifyState::Ready])
            .map_err(|e| format!("sd_notify READY=1 failed: {e}"))?;

        #[cfg(all(unix, feature = "systemd"))]
        if let Some(timeout) = sd_notify::watchdog_enabled() {
            let interval = timeout / 2;
            let token = server.shutdown_token().clone();
            tokio::spawn(async move {
                loop {
                    sleep(interval).await;
                    if token.is_cancelled() {
                        break;
                    }
                    if let Err(error) = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]) {
                        warn!(%error, "systemd watchdog ping failed");
                    }
                }
            });
            info!(?interval, "systemd watchdog enabled");
        }

        match server.block_until_done().await {
            Ok(()) => {
                // we're exiting for some reason...
                #[cfg(all(unix, feature = "systemd"))]
                sd_notify::notify(&[sd_notify::NotifyState::Stopping]).ok();
                info!("Hickory DNS {} stopping", env!("CARGO_PKG_VERSION"));
            }
            Err(e) => {
                let error_msg = format!(
                    "Hickory DNS {} has encountered an error: {}",
                    env!("CARGO_PKG_VERSION"),
                    e
                );

                error!("{}", error_msg);
                panic!("{}", error_msg);
            }
        };

        // Shut down the Prometheus metrics server after the DNS server has gracefully shut down.
        #[cfg(feature = "prometheus-metrics")]
        if let Some(server) = prometheus_server_opt {
            server.stop().await;
        }

        #[cfg(feature = "metrics")]
        process_metrics_collector.abort();

        Ok(())
    }
}

struct ServerSetup<'a> {
    server: &'a mut Server<Catalog>,
    tcp_request_timeout: Duration,
    udp_socket_config: UdpSocketConfig,
    tcp_socket_config: TcpSocketConfig,
}

impl ServerSetup<'_> {
    fn udp(&mut self, socket_addr: SocketAddr) -> Result<(), String> {
        #[cfg(unix)]
        let num_sockets = self.udp_socket_config.sockets.unwrap_or(1);
        #[cfg(not(unix))]
        let num_sockets = 1_usize;
        info!("binding {num_sockets} UDP socket(s) to {socket_addr}");

        // Bind the first socket up-front so we can log the local address. This is helpful
        // when binding :0 and allowing the OS to choose the listen port.
        let first_socket =
            build_udp_socket(socket_addr.ip(), socket_addr.port(), self.udp_socket_config)
                .map_err(|err| {
                    format!("failed to bind to UDP socket address {socket_addr}: {err}")
                })?;
        let bound_addr = first_socket
            .local_addr()
            .map_err(|err| format!("failed to lookup local address: {err}"))?;
        self.server.register_socket(first_socket);

        // Afterward, bind any additional sockets.
        for _ in 1..num_sockets {
            self.server.register_socket(
                build_udp_socket(socket_addr.ip(), socket_addr.port(), self.udp_socket_config)
                    .map_err(|err| {
                        format!("failed to bind to UDP socket address {socket_addr}: {err}")
                    })?,
            );
        }

        info!("listening for UDP on {bound_addr:?}");

        Ok(())
    }

    fn tcp(&mut self, socket_addr: SocketAddr) -> Result<(), String> {
        info!("binding TCP to {socket_addr}");

        let tcp_listener =
            build_tcp_listener(socket_addr.ip(), socket_addr.port(), self.tcp_socket_config)
                .map_err(|err| {
                    format!("failed to bind to TCP socket address {socket_addr}: {err}")
                })?;

        info!(
            "listening for TCP on {:?}",
            tcp_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        self.server.register_listener(
            tcp_listener,
            self.tcp_request_timeout,
            self.tcp_socket_config.response_buffer_size,
        );

        Ok(())
    }

    #[cfg(feature = "__tls")]
    fn tls(
        &mut self,
        socket_addr: SocketAddr,
        cert_resolver: Option<&Arc<dyn ResolvesServerCert>>,
        ssl_keylog_enabled: bool,
    ) -> Result<(), String> {
        let Some(cert_resolver) = cert_resolver else {
            return Ok(());
        };

        info!("binding TLS to {socket_addr}");

        let tls_listener =
            build_tcp_listener(socket_addr.ip(), socket_addr.port(), self.tcp_socket_config)
                .map_err(|err| {
                    format!("failed to bind to TLS socket address {socket_addr}: {err}")
                })?;

        info!(
            "listening for TLS on {:?}",
            tls_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let mut tls_config = default_tls_server_config(b"dot", cert_resolver.clone())
            .map_err(|err| format!("failed to build default TLS config: {err}"))?;
        if ssl_keylog_enabled {
            warn!("DoT SSL_KEYLOG_FILE support enabled");
            tls_config.key_log = Arc::new(KeyLogFile::new());
        }

        self.server
            .register_tls_listener_with_tls_config(
                tls_listener,
                self.tcp_request_timeout,
                Arc::new(tls_config),
            )
            .map_err(|err| format!("failed to register TLS listener: {err}"))?;
        Ok(())
    }

    #[cfg(feature = "__https")]
    fn https(
        &mut self,
        socket_addr: SocketAddr,
        cert_resolver: Option<&Arc<dyn ResolvesServerCert>>,
        ssl_keylog_enabled: bool,
        http_endpoint: &str,
        dns_hostname: Option<&str>,
    ) -> Result<(), String> {
        let Some(cert_resolver) = cert_resolver else {
            return Ok(());
        };

        info!("binding HTTPS to {socket_addr}");

        let https_listener =
            build_tcp_listener(socket_addr.ip(), socket_addr.port(), self.tcp_socket_config)
                .map_err(|err| {
                    format!("failed to bind to HTTPS socket address {socket_addr}: {err}")
                })?;

        info!(
            "listening for HTTPS on {:?}",
            https_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let mut tls_config = default_tls_server_config(b"h2", cert_resolver.clone())
            .map_err(|err| format!("failed to build default TLS config: {err}"))?;
        if ssl_keylog_enabled {
            warn!("DoH SSL_KEYLOG_FILE support enabled");
            tls_config.key_log = Arc::new(KeyLogFile::new());
        }

        self.server
            .register_https_listener_with_tls_config(
                https_listener,
                self.tcp_request_timeout,
                Arc::new(tls_config),
                dns_hostname.map(|s| s.to_owned()),
                http_endpoint.to_owned(),
            )
            .map_err(|err| format!("failed to register HTTPS listener: {err}"))?;
        Ok(())
    }

    #[cfg(feature = "__quic")]
    fn quic(
        &mut self,
        socket_addr: SocketAddr,
        cert_resolver: Option<&Arc<dyn ResolvesServerCert>>,
        ssl_keylog_enabled: bool,
    ) -> Result<(), String> {
        let Some(cert_resolver) = cert_resolver else {
            return Ok(());
        };

        info!("Binding QUIC to {socket_addr}");

        let quic_listener =
            build_udp_socket(socket_addr.ip(), socket_addr.port(), self.udp_socket_config)
                .map_err(|err| {
                    format!("failed to bind to QUIC socket address {socket_addr}: {err}")
                })?;

        info!(
            "listening for QUIC on {:?}",
            quic_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let mut tls_config = default_tls_server_config(b"doq", cert_resolver.clone())
            .map_err(|err| format!("failed to build default TLS config: {err}"))?;
        if ssl_keylog_enabled {
            warn!("DoQ SSL_KEYLOG_FILE support enabled");
            tls_config.key_log = Arc::new(KeyLogFile::new());
        }

        self.server
            .register_quic_listener_and_tls_config(
                quic_listener,
                self.tcp_request_timeout,
                Arc::new(tls_config),
            )
            .map_err(|err| format!("failed to register QUIC listener: {err}"))?;
        Ok(())
    }
}

fn banner() {
    #[cfg(feature = "ascii-art")]
    const HICKORY_DNS_LOGO: &str = include_str!("hickory-dns.ascii");

    #[cfg(not(feature = "ascii-art"))]
    const HICKORY_DNS_LOGO: &str = "Hickory DNS";

    info!("");
    for line in HICKORY_DNS_LOGO.lines() {
        info!(" {line}");
    }
    info!("");
}

/// Build a TcpListener for a given IP, port pair; IPv6 listeners will not accept v4 connections
fn build_tcp_listener(
    ip: IpAddr,
    port: u16,
    socket_config: TcpSocketConfig,
) -> Result<TcpListener, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::STREAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    sock.listen(socket_config.listen_backlog)?;

    TcpListener::from_std(sock.into())
}

/// Build a UdpSocket for a given IP, port pair; IPv6 sockets will not accept v4 connections
fn build_udp_socket(
    ip: IpAddr,
    port: u16,
    socket_config: UdpSocketConfig,
) -> Result<UdpSocket, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    #[cfg(unix)]
    if socket_config.sockets.is_some_and(|count| count > 1) {
        sock.set_reuse_port(true)?;
    }

    if let Some(size) = socket_config.recv_buffer_size {
        sock.set_recv_buffer_size(size)?;
    }
    if let Some(size) = socket_config.send_buffer_size {
        sock.set_send_buffer_size(size)?;
    }
    if socket_config.recv_buffer_size.is_some() || socket_config.send_buffer_size.is_some() {
        info!(
            "UDP socket buffer sizes: recv={} send={} (requested recv={:?} send={:?})",
            sock.recv_buffer_size().unwrap_or(0),
            sock.send_buffer_size().unwrap_or(0),
            socket_config.recv_buffer_size,
            socket_config.send_buffer_size,
        );
    }

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Drop privileges on Unix systems if running as root. Errors that prevent dropping privileges will
/// halt the server.  This must be called after binding to low numbered sockets is complete.
#[cfg(target_family = "unix")]
fn check_drop_privs(user: &str, group: &str) -> Result<(), String> {
    use libc::{getegid, geteuid, getgid, getgrnam, getpwnam, getuid, setgid, setuid};
    use std::ffi::CString;

    // These calls are guaranteed to succeed in a POSIX-conforming environment. In non-conforming
    // environments, implementations may return -1 to indicate a process running without an
    // associated UID/EUID/GID/EGID. In that case, our main block below will not execute as
    // libc typedefs uid_t and gid_t to u32; -1 will be u32::MAX.
    //
    // POSIX reference: IEEE Std 1003.1-1024 getuid, geteuid, getgid, and getegid specifications
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/geteuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getegid.html
    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    if uid == 0 || euid == 0 {
        info!(
            "running as root (uid: {uid} gid: {gid} euid: {euid} egid: {egid})...dropping privileges.",
        );

        let Ok(user_cstring) = CString::new(user) else {
            return Err(format!("unable to create CString for user {user}"));
        };

        let Ok(group_cstring) = CString::new(group) else {
            return Err(format!(
                "unable to create CString for group {group}. Exiting."
            ));
        };

        // These functions must be supplied a NULL-terminated string, which is guaranteed by
        // std::ffi::CString.  Upon success, they will return a pointer to a struct passwd or
        // struct group, or NULL upon failure. Testing for a NULL return value is mandatory.
        //
        // POSIX reference: IEEE Std 1003.1-1024 getpwnam and getgrnam specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getpwnam.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgrnam.html
        let (user_info, group_info) = unsafe {
            (
                getpwnam(user_cstring.as_ptr()),
                getgrnam(group_cstring.as_ptr()),
            )
        };

        if user_info.is_null() {
            return Err(format!("unable to lookup user '{user}'. Exiting."));
        }

        if group_info.is_null() {
            return Err(format!("unable to lookup group '{group}'. Exiting."));
        }

        // These functions must be supplied a gid_t (setgid) and uid_t (setuid), which are
        // supplied by the passwd and group structs returned by getpwnam and getgrnam.
        // The structs are tested to be valid by the calls to is_null() above.
        //
        // The call to setgid must be completed before the call to setuid is made or the
        // process will almost certainly lack the privileges necessary to switch its real gid.
        //
        // POSIX reference: IEEE Std 1003.1-1024 setgid and setuid specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setgid.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setuid.html
        let (setgid_rc, setuid_rc) =
            unsafe { (setgid((*group_info).gr_gid), setuid((*user_info).pw_uid)) };

        if setgid_rc < 0 {
            return Err("unable to set gid. Exiting.".into());
        }

        if setuid_rc < 0 {
            return Err("unable to set uid. Exiting.".into());
        }
    }

    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    info!("now running as uid: {uid}, gid: {gid} (euid: {euid}, egid: {egid})",);
    Ok(())
}

fn parse_nsid_payload(raw_payload: &str) -> Result<NSIDPayload, ProtoError> {
    let bytes = if let Some(hex_str) = raw_payload.strip_prefix("0x") {
        hex::decode(hex_str)
            .map_err(|e| ProtoError::from(format!("invalid NSID hex encoding: {e}")))?
    } else {
        raw_payload.as_bytes().to_vec()
    };
    NSIDPayload::new(bytes)
}

fn configured_nsid(config: Option<&NsidConfig>) -> Result<Option<NSIDPayload>, String> {
    let Some(config) = config else {
        return Ok(None);
    };

    match config {
        NsidConfig::Value(value) => parse_nsid_payload(value)
            .map(Some)
            .map_err(|err| format!("invalid NSID payload: {err}")),
        NsidConfig::Source(source) => match source.source {
            NsidSource::Hostname => {
                let hostname = hostname::get()
                    .map_err(|err| format!("failed to get system hostname: {err}"))?;
                NSIDPayload::new(hostname.into_encoded_bytes())
                    .map(Some)
                    .map_err(|err| format!("invalid NSID payload: {err}"))
            }
        },
    }
}

#[cfg(target_family = "unix")]
const DEFAULT_USER: &str = "nobody";
#[cfg(target_family = "unix")]
const DEFAULT_GROUP: &str = "nobody";

#[cfg(test)]
mod tests {
    use hickory_proto::rr::rdata::opt::NSIDPayload;

    use super::{configured_nsid, parse_nsid_payload};
    use crate::config::{NsidConfig, NsidSource, NsidSourceConfig};

    #[test]
    fn test_hex_nsid_payload() {
        let expected = NSIDPayload::new(vec![0xC0, 0xFF, 0xEE]).unwrap();
        let value = parse_nsid_payload("0xC0FFEE").unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_string_nsid_payload() {
        let string_value = "HickoryDNS";
        let expected = NSIDPayload::new(string_value.as_bytes()).unwrap();
        let value = parse_nsid_payload(string_value).unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_nsid_payload_too_long() {
        let too_large = "x".repeat(u16::MAX as usize + 1);
        let err = parse_nsid_payload(&too_large).unwrap_err();
        assert_eq!(err.to_string(), "NSID EDNS payload too large");
    }

    #[test]
    fn test_nsid_configuration_disabled_by_default() {
        assert_eq!(configured_nsid(None).unwrap(), None);
    }

    #[test]
    fn test_hostname_nsid_source() {
        let config = NsidConfig::Source(NsidSourceConfig {
            source: NsidSource::Hostname,
        });
        let expected = NSIDPayload::new(hostname::get().unwrap().into_encoded_bytes()).unwrap();

        assert_eq!(configured_nsid(Some(&config)).unwrap(), Some(expected));
    }
}
