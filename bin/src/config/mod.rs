// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `hickory-dns`.

#[cfg(feature = "__tls")]
use std::ffi::OsStr;
use std::{
    collections::{HashMap, HashSet},
    fmt, fs, io,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "sqlite")]
use cfg_if::cfg_if;
use ipnet::IpNet;
#[cfg(feature = "__tls")]
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
// `IgnoredAny` is only used by the fallback store variants below, so it is
// unused when every store feature is enabled.
#[allow(unused_imports)]
use serde::de::IgnoredAny;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{self, Deserialize, Deserializer};
use thiserror::Error;
use tracing::{debug, info};

#[cfg(feature = "__dnssec")]
use crate::dnssec;
#[cfg(feature = "__tls")]
use hickory_net::tls::default_provider;
use hickory_proto::{ProtoError, rr::Name, serialize::txt::ParseError};
#[cfg(feature = "recursor")]
use hickory_resolver::recursor::RecursiveConfig;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
#[cfg(any(feature = "recursor", feature = "sqlite"))]
use hickory_server::net::runtime::TokioRuntimeProvider;
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::{BlocklistConfig, BlocklistZoneHandler};
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveZoneHandler;
#[cfg(feature = "sqlite")]
use hickory_server::store::sqlite::{SqliteConfig, SqliteZoneHandler};
use hickory_server::{
    store::file::{FileConfig, FileZoneHandler},
    zone_handler::{AxfrPolicy, ZoneHandler, ZoneType},
};

#[cfg(test)]
mod tests;

/// Server configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Self-contained DNS listener configurations.
    #[serde(default)]
    pub(crate) listeners: Vec<ListenerConfig>,
    /// Prometheus listen address
    #[cfg(feature = "prometheus-metrics")]
    pub(crate) prometheus_listen_addr: Option<SocketAddr>,
    /// Name server identifier (NSID) payload for EDNS responses.
    pub(crate) nsid: Option<NsidConfig>,
    /// Timeout associated to a request before it is closed.
    #[serde(
        deserialize_with = "parse_request_timeout",
        default = "default_request_timeout"
    )]
    pub(crate) tcp_request_timeout: Duration,
    /// Base directory for zone files and other zone-related data.
    #[serde(default = "default_zone_directory")]
    pub(crate) zone_directory: PathBuf,
    /// User to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this user (or to nobody if no user is specified here.)
    pub user: Option<String>,
    /// Group to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this group (or to nobody if no group is specified here.)
    pub group: Option<String>,
    /// Whether to drop privileges on startup. Defaults to true.
    /// Set to false in container/namespace environments where
    /// /etc/passwd is not available.
    #[serde(default = "default_drop_privileges")]
    pub(crate) drop_privileges: bool,
    /// List of configurations for zones
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_file")]
    pub(crate) zones: Vec<ZoneConfig>,
    /// Networks denied to access the server
    #[serde(default)]
    pub(crate) deny_networks: Vec<IpNet>,
    /// Networks allowed to access the server
    #[serde(default)]
    pub(crate) allow_networks: Vec<IpNet>,
    /// UDP socket configuration options.
    #[serde(default)]
    pub(crate) udp_socket: UdpSocketConfig,
    /// TCP socket configuration options.
    #[serde(default)]
    pub(crate) tcp_socket: TcpSocketConfig,
}

/// Name server identifier configuration.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum NsidConfig {
    /// A literal payload. Values prefixed with `0x` are decoded as hexadecimal.
    Value(String),
    /// A payload obtained from a runtime source.
    Source(NsidSourceConfig),
}

/// Runtime source for an NSID payload.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct NsidSourceConfig {
    pub(crate) source: NsidSource,
}

/// Supported runtime sources for an NSID payload.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NsidSource {
    /// Use the system hostname.
    Hostname,
}

/// DNS service protocol exposed by a configured listener.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ListenerProtocol {
    Udp,
    Tcp,
    #[serde(rename = "dot")]
    Tls,
    #[serde(rename = "doh")]
    Https,
    #[serde(rename = "doq")]
    Quic,
}

impl fmt::Display for ListenerProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "dot",
            Self::Https => "doh",
            Self::Quic => "doq",
        };
        formatter.write_str(value)
    }
}

impl ListenerProtocol {
    fn is_secure(self) -> bool {
        matches!(self, Self::Tls | Self::Https | Self::Quic)
    }

    fn is_tcp_family(self) -> bool {
        matches!(self, Self::Tcp | Self::Tls | Self::Https)
    }

    fn is_supported(self) -> bool {
        match self {
            Self::Udp | Self::Tcp => true,
            Self::Tls => cfg!(feature = "__tls"),
            Self::Https => cfg!(feature = "__https"),
            Self::Quic => cfg!(feature = "__quic"),
        }
    }
}

/// A self-contained listener block from the configuration file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerConfig {
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
    pub(crate) protocols: Vec<ListenerProtocol>,
    pub(crate) tls_cert: Option<TlsCertConfig>,
    pub(crate) http_endpoint: Option<String>,
    pub(crate) ssl_keylog_enabled: Option<bool>,
}

/// Validated listener configuration used by server startup.
#[derive(Clone, Debug)]
pub(crate) struct NormalizedListener {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) protocols: Vec<ListenerProtocol>,
    #[cfg_attr(
        not(any(feature = "__tls", feature = "__https", feature = "__quic")),
        allow(dead_code)
    )]
    pub(crate) tls_cert: Option<TlsCertConfig>,
    #[cfg_attr(not(feature = "__https"), allow(dead_code))]
    pub(crate) http_endpoint: String,
    #[cfg_attr(
        not(any(feature = "__tls", feature = "__https", feature = "__quic")),
        allow(dead_code)
    )]
    pub(crate) ssl_keylog_enabled: bool,
}

/// Configuration options for UDP sockets.
///
/// These settings control the kernel buffer sizes for UDP sockets used by the DNS server.
/// Under high query load, increasing buffer sizes can help prevent packet loss when the
/// application cannot process incoming packets fast enough.
///
/// Note: The kernel may cap the actual buffer size based on system limits
/// (e.g., `net.core.rmem_max` on Linux). Check logs at startup to see the actual
/// buffer size that was configured.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UdpSocketConfig {
    /// UDP socket receive buffer size in bytes.
    ///
    /// Controls the kernel buffer for incoming UDP packets. If not specified, the operating
    /// system default is used. Larger values help absorb traffic bursts without dropping
    /// packets.
    pub(crate) recv_buffer_size: Option<usize>,
    /// UDP socket send buffer size in bytes.
    ///
    /// Controls the kernel buffer for outgoing UDP packets. If not specified, the operating
    /// system default is used. Larger values help when the server is sending many responses.
    pub(crate) send_buffer_size: Option<usize>,
    /// Number of UDP sockets to create per listen address (Unix only).
    ///
    /// Using multiple sockets with SO_REUSEPORT allows the kernel to distribute incoming packets
    /// across sockets, which may improve performance under high load. Optimal values depend
    /// on workload and setting it too high will have the opposite effect and cause performance
    /// degradation.
    ///
    /// Defaults to 1.
    #[cfg(unix)]
    pub(crate) sockets: Option<usize>,
}

/// Configuration options for TCP sockets.
///
/// These settings control aspects of TCP listeners used by the DNS server.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TcpSocketConfig {
    /// TCP listen backlog size.
    ///
    /// Controls the maximum number of pending connections queued by the kernel before
    /// connections are refused. If not specified, defaults to 128.
    ///
    /// Higher values allow more connections to queue during traffic spikes.
    /// Consider increasing this for high-TCP load deployments.
    ///
    /// On Linux the kernel `net.core.somaxconn` and `net.ipv[4|6].tcp_max_syn_backlog`
    /// may also need adjustment to match.
    #[serde(default = "default_tcp_listen_backlog")]
    pub(crate) listen_backlog: i32,

    /// TCP response buffer size.
    ///
    /// Controls the maximum number of DNS responses that can be queued for
    /// sending on a single TCP connection. Under high query rates, a larger
    /// buffer prevents responses from being dropped due to backpressure.
    ///
    /// If not specified, defaults to 32.
    #[serde(default = "default_tcp_response_buffer_size")]
    pub(crate) response_buffer_size: usize,
}

impl Default for TcpSocketConfig {
    fn default() -> Self {
        Self {
            listen_backlog: default_tcp_listen_backlog(),
            response_buffer_size: default_tcp_response_buffer_size(),
        }
    }
}

fn default_drop_privileges() -> bool {
    true
}

fn default_tcp_listen_backlog() -> i32 {
    128
}

fn default_tcp_response_buffer_size() -> usize {
    32
}

impl Config {
    /// read a Config file from the file specified at path.
    pub(crate) fn read_config(path: &Path) -> Result<Self, ConfigError> {
        Self::from_toml(&fs::read_to_string(path)?)
    }

    /// Read a [`Config`] from the given TOML string.
    fn from_toml(toml: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(toml)?)
    }

    /// Validate and normalize self-contained listener blocks.
    pub(crate) fn normalized_listeners(&self) -> Result<Vec<NormalizedListener>, ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::InvalidListener(
                "`listeners` must contain at least one listener".to_owned(),
            ));
        }

        let mut normalized = Vec::with_capacity(self.listeners.len());
        let mut socket_families =
            HashMap::<SocketAddr, (Option<ListenerProtocol>, Option<ListenerProtocol>)>::new();

        for (index, listener) in self.listeners.iter().enumerate() {
            if listener.protocols.is_empty() {
                return Err(ConfigError::InvalidListener(format!(
                    "listener {} must contain at least one protocol",
                    index + 1
                )));
            }

            let mut protocols = HashSet::new();
            for protocol in &listener.protocols {
                if !protocols.insert(*protocol) {
                    return Err(ConfigError::InvalidListener(format!(
                        "listener {} contains duplicate protocol `{protocol}`",
                        index + 1
                    )));
                }
                if !protocol.is_supported() {
                    return Err(ConfigError::InvalidListener(format!(
                        "listener {} protocol `{protocol}` is unavailable in this build",
                        index + 1
                    )));
                }
            }

            let has_secure_protocol = listener
                .protocols
                .iter()
                .any(|protocol| protocol.is_secure());
            let has_https = protocols.contains(&ListenerProtocol::Https);
            if has_secure_protocol && listener.tls_cert.is_none() {
                return Err(ConfigError::InvalidListener(format!(
                    "listener {} requires `tls_cert` for secure protocols",
                    index + 1
                )));
            }
            if !has_secure_protocol
                && (listener.tls_cert.is_some() || listener.ssl_keylog_enabled.is_some())
            {
                return Err(ConfigError::InvalidListener(format!(
                    "listener {} has secure settings but only plaintext protocols",
                    index + 1
                )));
            }
            if listener.http_endpoint.is_some() && !has_https {
                return Err(ConfigError::InvalidListener(format!(
                    "listener {} has `http_endpoint` without the `doh` protocol",
                    index + 1
                )));
            }

            let mut local_families = (None, None);
            for protocol in &listener.protocols {
                let previous = if protocol.is_tcp_family() {
                    &mut local_families.1
                } else {
                    &mut local_families.0
                };
                if let Some(previous) = previous {
                    return Err(ConfigError::InvalidListener(format!(
                        "listener {} cannot serve both `{previous}` and `{protocol}` because they use the same socket family",
                        index + 1
                    )));
                }
                *previous = Some(*protocol);
            }

            let socket_addr = SocketAddr::new(listener.address, listener.port);
            let families = socket_families.entry(socket_addr).or_default();
            for protocol in &listener.protocols {
                let previous = if protocol.is_tcp_family() {
                    &mut families.1
                } else {
                    &mut families.0
                };
                if let Some(previous) = previous {
                    return Err(ConfigError::InvalidListener(format!(
                        "socket {socket_addr} cannot serve both `{previous}` and `{protocol}` because they use the same socket family"
                    )));
                }
                *previous = Some(*protocol);
            }

            normalized.push(NormalizedListener {
                socket_addr,
                protocols: listener.protocols.clone(),
                tls_cert: listener.tls_cert.clone(),
                http_endpoint: listener
                    .http_endpoint
                    .clone()
                    .unwrap_or_else(default_listener_http_endpoint),
                ssl_keylog_enabled: listener.ssl_keylog_enabled.unwrap_or(false),
            });
        }

        Ok(normalized)
    }
}

#[derive(Deserialize, Debug)]
struct ZoneConfigWithFile {
    file: Option<PathBuf>,
    #[serde(flatten)]
    config: ZoneConfig,
}

fn deserialize_with_file<'de, D>(deserializer: D) -> Result<Vec<ZoneConfig>, D::Error>
where
    D: Deserializer<'de>,
    D::Error: de::Error,
{
    Vec::<ZoneConfigWithFile>::deserialize(deserializer)?
        .into_iter()
        .map(|ZoneConfigWithFile { file, mut config }| match file {
            Some(file) => match &mut config.zone_type_config {
                ZoneTypeConfig::Primary(server_config)
                | ZoneTypeConfig::Secondary(server_config) => {
                    if server_config
                        .stores
                        .iter()
                        .any(|store| matches!(store, ServerStoreConfig::File(_)))
                    {
                        Err(<D::Error as de::Error>::custom(
                            "having `file` and `[zones.store]` item with type `file` is ambiguous",
                        ))
                    } else {
                        let store = ServerStoreConfig::File(FileConfig { zone_path: file });

                        if server_config.stores.len() == 1
                            && matches!(&server_config.stores[0], ServerStoreConfig::Default)
                        {
                            server_config.stores[0] = store;
                        } else {
                            server_config.stores.push(store);
                        }
                        Ok(config)
                    }
                }
                _ => Err(<D::Error as de::Error>::custom(
                    "cannot use `file` on a zone that is not primary or secondary",
                )),
            },

            _ => Ok(config),
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Configuration for a zone
#[derive(Deserialize, Debug)]
pub(crate) struct ZoneConfig {
    /// name of the zone
    pub zone: String, // TODO: make Domain::Name decodable
    /// type of the zone
    #[serde(flatten)]
    pub zone_type_config: ZoneTypeConfig,
}

impl ZoneConfig {
    pub(crate) async fn load(
        self,
        zone_dir: &Path,
    ) -> Result<Vec<Arc<dyn ZoneHandler>>, ProtoError> {
        debug!("loading zone with config: {self:#?}");

        let zone_name = self
            .zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;
        let zone_type = self.zone_type();

        // load the zone and insert any configured zone handlers in the catalog.

        let mut handlers: Vec<Arc<dyn ZoneHandler>> = vec![];
        match self.zone_type_config {
            ZoneTypeConfig::Primary(server_config) | ZoneTypeConfig::Secondary(server_config) => {
                debug!(
                    "loading zone handlers for {zone_name} with stores {:?}",
                    server_config.stores
                );

                let axfr_policy = server_config.axfr_policy();
                for store in &server_config.stores {
                    let handler: Arc<dyn ZoneHandler> = match store {
                        #[cfg(feature = "sqlite")]
                        ServerStoreConfig::Sqlite(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut handler =
                                SqliteZoneHandler::<TokioRuntimeProvider>::try_from_config(
                                    zone_name.clone(),
                                    zone_type,
                                    axfr_policy,
                                    server_config.is_dnssec_enabled(),
                                    Some(zone_dir),
                                    config,
                                    #[cfg(feature = "__dnssec")]
                                    server_config.nx_proof_kind.clone(),
                                )
                                .await?;

                            #[cfg(feature = "__dnssec")]
                            dnssec::load_keys(&mut handler, &zone_name, &server_config.keys)
                                .await?;
                            Arc::new(handler)
                        }

                        ServerStoreConfig::File(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut handler = FileZoneHandler::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                axfr_policy,
                                Some(zone_dir),
                                config,
                                #[cfg(feature = "__dnssec")]
                                server_config.nx_proof_kind.clone(),
                            )?;

                            #[cfg(feature = "__dnssec")]
                            dnssec::load_keys(&mut handler, &zone_name, &server_config.keys)
                                .await?;
                            Arc::new(handler)
                        }
                        #[cfg(not(feature = "sqlite"))]
                        ServerStoreConfig::Sqlite(_) => {
                            return Err(ProtoError::from(
                                "store type `sqlite` requires the `sqlite` Cargo feature, \
                                 which was not enabled when this binary was built",
                            ));
                        }
                        _ => return Err(ProtoError::from(EMPTY_STORES)),
                    };

                    handlers.push(handler);
                }
            }
            ZoneTypeConfig::External { stores } => {
                debug!(
                    "loading zone handlers for {zone_name} with stores {:?}",
                    stores
                );

                #[cfg_attr(
                    not(any(feature = "blocklist", feature = "resolver", feature = "recursor")),
                    allow(unreachable_code, unused_variables, clippy::never_loop)
                )]
                for store in stores {
                    let handler: Arc<dyn ZoneHandler> = match store {
                        #[cfg(feature = "blocklist")]
                        ExternalStoreConfig::Blocklist(config) => {
                            Arc::new(BlocklistZoneHandler::try_from_config(
                                zone_name.clone(),
                                config,
                                Some(zone_dir),
                            )?)
                        }
                        #[cfg(feature = "resolver")]
                        ExternalStoreConfig::Forward(config) => {
                            let forwarder = ForwardZoneHandler::builder_tokio(config)
                                .with_origin(zone_name.clone())
                                .build()?;

                            Arc::new(forwarder)
                        }
                        #[cfg(feature = "recursor")]
                        ExternalStoreConfig::Recursor(config) => {
                            let recursor = RecursiveZoneHandler::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                *config,
                                Some(zone_dir),
                                TokioRuntimeProvider::default(),
                            )
                            .await?;

                            Arc::new(recursor)
                        }
                        #[cfg(not(feature = "blocklist"))]
                        ExternalStoreConfig::Blocklist(_) => {
                            return Err(ProtoError::from(
                                "store type `blocklist` requires the `blocklist` Cargo feature, \
                                 which was not enabled when this binary was built",
                            ));
                        }
                        #[cfg(not(feature = "resolver"))]
                        ExternalStoreConfig::Forward(_) => {
                            return Err(ProtoError::from(
                                "store type `forward` requires the `resolver` Cargo feature, \
                                 which was not enabled when this binary was built",
                            ));
                        }
                        #[cfg(not(feature = "recursor"))]
                        ExternalStoreConfig::Recursor(_) => {
                            return Err(ProtoError::from(
                                "store type `recursor` requires the `recursor` Cargo feature, \
                                 which was not enabled when this binary was built",
                            ));
                        }
                        _ => return Err(ProtoError::from(EMPTY_STORES)),
                    };

                    handlers.push(handler);
                }
            }
        }

        info!("zone successfully loaded: {zone_name}");
        Ok(handlers)
    }

    // TODO this is a little ugly for the parse, b/c there is no terminal char
    /// returns the name of the Zone, i.e. the `example.com` of `www.example.com.`
    pub(crate) fn zone(&self) -> Result<Name, ProtoError> {
        Name::parse(&self.zone, Some(&Name::new()))
    }

    /// the type of the zone
    fn zone_type(&self) -> ZoneType {
        match &self.zone_type_config {
            ZoneTypeConfig::Primary { .. } => ZoneType::Primary,
            ZoneTypeConfig::Secondary { .. } => ZoneType::Secondary,
            ZoneTypeConfig::External { .. } => ZoneType::External,
        }
    }
}

const EMPTY_STORES: &str = "empty [[zones.stores]] in config";

#[derive(Deserialize, Debug)]
#[serde(tag = "zone_type")]
#[serde(deny_unknown_fields)]
/// Enumeration over each zone type's configuration.
pub(crate) enum ZoneTypeConfig {
    Primary(ServerZoneConfig),
    Secondary(ServerZoneConfig),
    External {
        /// Store configurations.  Note: we specify a default handler to get a Vec containing a
        /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
        /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
        /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
        /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
        #[serde(default = "store_config_default")]
        #[serde(deserialize_with = "store_config_visitor")]
        stores: Vec<ExternalStoreConfig>,
    },
}

impl ZoneTypeConfig {
    #[cfg(test)]
    fn as_server(&self) -> Option<&ServerZoneConfig> {
        match self {
            Self::Primary(c) | Self::Secondary(c) => Some(c),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerZoneConfig {
    /// A policy used to determine whether AXFR requests are allowed
    ///
    /// By default, all AXFR requests are rejected
    #[serde(default)]
    pub axfr_policy: AxfrPolicy,
    /// Keys for use by the zone
    #[cfg(feature = "__dnssec")]
    #[serde(default)]
    pub keys: Vec<dnssec::KeyConfig>,
    /// The kind of non-existence proof provided by the nameserver
    #[cfg(feature = "__dnssec")]
    pub nx_proof_kind: Option<NxProofKind>,
    /// Store configurations.  Note: we specify a default handler to get a Vec containing a
    /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
    /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
    /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
    /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
    #[serde(default = "store_config_default")]
    #[serde(deserialize_with = "store_config_visitor")]
    pub stores: Vec<ServerStoreConfig>,
}

impl ServerZoneConfig {
    /// path to the zone file, i.e. the base set of original records in the zone
    ///
    /// this is only used on first load, if dynamic update is enabled for the zone, then the journal
    /// file is the actual source of truth for the zone.
    #[cfg(test)]
    fn file(&self) -> Option<&Path> {
        self.stores.iter().find_map(|store| match store {
            ServerStoreConfig::File(file_config) => Some(&*file_config.zone_path),
            #[cfg(feature = "sqlite")]
            ServerStoreConfig::Sqlite(sqlite_config) => Some(&*sqlite_config.zone_path),
            ServerStoreConfig::Default => None,
            #[cfg(not(feature = "sqlite"))]
            ServerStoreConfig::Sqlite(_) => None,
        })
    }

    /// Return a policy that can be used to determine how AXFR requests should be handled.
    fn axfr_policy(&self) -> AxfrPolicy {
        self.axfr_policy
    }

    /// declare that this zone should be signed, see keys for configuration of the keys for signing
    #[cfg(feature = "sqlite")]
    fn is_dnssec_enabled(&self) -> bool {
        cfg_if! {
            if #[cfg(feature = "__dnssec")] {
                !self.keys.is_empty()
            } else {
                false
            }
        }
    }
}

/// Enumeration over store types for secondary nameservers.
#[derive(Deserialize, Debug, Default)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub(crate) enum ServerStoreConfig {
    /// File based configuration
    File(FileConfig),
    /// Sqlite based configuration file
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteConfig),
    /// Fallback variant for when the `sqlite` feature is not enabled.
    ///
    /// Serde will parse the config, and the error is returned when the store is used, so that
    /// the user learns the feature is missing rather than that the store type is unknown.
    #[cfg(not(feature = "sqlite"))]
    Sqlite(IgnoredAny),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Enumeration over store types for external nameservers.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
#[non_exhaustive]
pub(crate) enum ExternalStoreConfig {
    /// Blocklist configuration
    #[cfg(feature = "blocklist")]
    Blocklist(BlocklistConfig),
    /// Fallback variant for when the `blocklist` feature is not enabled.
    #[cfg(not(feature = "blocklist"))]
    Blocklist(IgnoredAny),
    /// Forwarding Resolver
    #[cfg(feature = "resolver")]
    Forward(ForwardConfig),
    /// Fallback variant for when the `resolver` feature is not enabled.
    #[cfg(not(feature = "resolver"))]
    Forward(IgnoredAny),
    /// Recursive Resolver
    #[cfg(feature = "recursor")]
    Recursor(Box<RecursiveConfig>),
    /// Fallback variant for when the `recursor` feature is not enabled.
    #[cfg(not(feature = "recursor"))]
    Recursor(IgnoredAny),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Create a default value for serde for store config enums.
fn store_config_default<S: Default>() -> Vec<S> {
    vec![Default::default()]
}

/// Custom serde visitor that can deserialize a map (single configuration store, expressed as a TOML
/// table) or sequence (chained configuration stores, expressed as a TOML array of tables.)
/// This is used instead of an untagged enum because serde cannot provide variant-specific error
/// messages when using an untagged enum.
fn store_config_visitor<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapOrSequence<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOrSequence<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("map or sequence")
        }

        fn visit_seq<S>(self, seq: S) -> Result<Vec<T>, S::Error>
        where
            S: SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
        }

        fn visit_map<M>(self, map: M) -> Result<Vec<T>, M::Error>
        where
            M: MapAccess<'de>,
        {
            match Deserialize::deserialize(de::value::MapAccessDeserializer::new(map)) {
                Ok(seq) => Ok(vec![seq]),
                Err(e) => Err(e),
            }
        }
    }

    deserializer.deserialize_any(MapOrSequence::<T>(PhantomData))
}

/// Configuration for a TLS certificate
#[derive(Clone, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub(crate) struct TlsCertConfig {
    pub(crate) path: PathBuf,
    pub(crate) endpoint_name: Option<String>,
    pub(crate) private_key: PathBuf,
}

#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
impl TlsCertConfig {
    /// Load a Certificate from the path (with rustls)
    pub(crate) fn load(&self, config_dir: &Path) -> Result<Arc<dyn ResolvesServerCert>, String> {
        if let Some(endpoint_name) = &self.endpoint_name {
            info!("loading TLS cert for {endpoint_name} from {:?}", self.path);
        } else {
            info!("loading TLS cert from {:?}", self.path);
        }

        if self.path.extension().and_then(OsStr::to_str) != Some("pem") {
            return Err(format!(
                "unsupported certificate file format (expected `.pem` extension): {}",
                self.path.display()
            ));
        }

        let cert_path = config_dir.join(&self.path);
        info!(
            "loading TLS PEM certificate chain from: {}",
            cert_path.display()
        );

        let cert_chain = CertificateDer::pem_file_iter(&cert_path)
            .map_err(|e| {
                format!(
                    "failed to read cert chain from {}: {e}",
                    cert_path.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                format!(
                    "failed to parse cert chain from {}: {e}",
                    cert_path.display()
                )
            })?;

        let key_extension = self.private_key.extension();
        let key = if key_extension.is_some_and(|ext| ext == "pem") {
            let key_path = config_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from PEM: {}", key_path.display());
            PrivateKeyDer::from_pem_file(&key_path)
                .map_err(|e| format!("failed to read key from {}: {e}", key_path.display()))?
        } else if key_extension.is_some_and(|ext| ext == "der" || ext == "key") {
            let key_path = config_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from DER: {}", key_path.display());

            let buf =
                fs::read(&key_path).map_err(|e| format!("error reading key from file: {e}"))?;
            PrivateKeyDer::try_from(buf).map_err(|e| format!("error parsing key DER: {e}"))?
        } else {
            return Err(format!(
                "unsupported private key file format (expected `.pem` or `.der` extension): {}",
                self.private_key.display()
            ));
        };

        let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())
            .map_err(|err| format!("failed to read certificate and keys: {err:?}"))?;

        Ok(Arc::new(SingleCertAndKey::from(certified_key)))
    }
}

/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum ConfigError {
    // foreign
    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// An error occurred while decoding toml data
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),

    /// Listener configuration is semantically invalid.
    #[error("invalid listener configuration: {0}")]
    InvalidListener(String),

    /// An error occurred while parsing a zone file
    #[error("failed to parse the zone file: {0}")]
    ZoneParse(#[from] ParseError),
}

fn parse_request_timeout<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(Duration::from_secs(u64::deserialize(deserializer)?))
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_listener_http_endpoint() -> String {
    "/dns-query".to_owned()
}

fn default_zone_directory() -> PathBuf {
    PathBuf::from("/var/named") // TODO what about windows (do I care? ;)
}
