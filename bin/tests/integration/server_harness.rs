#![allow(unreachable_pub)]

use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader},
    net::SocketAddr,
    process::{Child, ChildStdout, Command, Stdio},
    str::FromStr,
    time::*,
};

use regex::Regex;
use tracing::{info, warn};

use hickory_net::{NetError, client::ClientHandle, xfer::Protocol};
#[cfg(feature = "__dnssec")]
use hickory_net::{client::Client, runtime::TokioRuntimeProvider, xfer::DnsHandle};
#[cfg(feature = "__dnssec")]
use hickory_proto::{
    dnssec::Algorithm,
    op::{DnsRequest, Edns},
};
use hickory_proto::{
    op::{DnsResponse, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType, rdata::A},
};
#[cfg(feature = "__dnssec")]
use hickory_server::zone_handler::LookupOptions;

use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct SocketPorts(HashMap<ServerProtocol, Vec<SocketAddr>>);

impl SocketPorts {
    fn put(&mut self, protocol: impl Into<ServerProtocol>, addr: SocketAddr) {
        self.0.entry(protocol.into()).or_default().push(addr);
    }

    /// Returns the first recorded IPv4 port for compatibility with single-listener tests.
    pub fn get_v4(&self, protocol: impl Into<ServerProtocol>) -> Option<u16> {
        self.0
            .get(&protocol.into())
            .and_then(|addrs| addrs.iter().find(|addr| addr.is_ipv4()))
            .map(SocketAddr::port)
    }

    /// Returns the first recorded IPv6 port for compatibility with single-listener tests.
    pub fn get_v6(&self, protocol: impl Into<ServerProtocol>) -> Option<u16> {
        self.0
            .get(&protocol.into())
            .and_then(|addrs| addrs.iter().find(|addr| addr.is_ipv6()))
            .map(SocketAddr::port)
    }

    /// Returns every socket address recorded for a protocol.
    pub fn get_all(&self, protocol: impl Into<ServerProtocol>) -> &[SocketAddr] {
        self.0
            .get(&protocol.into())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ServerProtocol {
    Dns(Protocol),
    #[cfg(feature = "metrics")]
    PrometheusMetrics,
}

impl From<Protocol> for ServerProtocol {
    fn from(proto: Protocol) -> Self {
        Self::Dns(proto)
    }
}

fn collect_and_print<R: BufRead>(read: &mut R, output: &mut String) {
    output.clear();
    read.read_line(output).expect("could not read stdio");

    if !output.is_empty() {
        // uncomment for debugging
        // println!("SRV: {}", output.trim_end());
    }
}

fn unused_dns_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("failed to reserve an ephemeral TCP port");
        let port = tcp.local_addr().unwrap().port();
        if let Ok(udp) = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
            drop(udp);
            drop(tcp);
            return port;
        }
    }
}

fn temporary_server_config(
    original_config_path: &std::path::Path,
    zone_directory: &std::path::Path,
    enable_prometheus: bool,
) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_CONFIG_ID: AtomicU64 = AtomicU64::new(0);

    let contents =
        std::fs::read_to_string(original_config_path).expect("failed to read server configuration");
    let mut config =
        toml::from_str::<toml::Value>(&contents).expect("failed to parse server configuration");
    let config_table = config
        .as_table_mut()
        .expect("server configuration must be a table");
    config_table.insert(
        "zone_directory".to_owned(),
        toml::Value::String(zone_directory.to_string_lossy().into_owned()),
    );
    #[cfg(feature = "prometheus-metrics")]
    if enable_prometheus {
        config_table.insert(
            "prometheus_listen_addr".to_owned(),
            toml::Value::String("127.0.0.1:0".to_owned()),
        );
    }
    #[cfg(not(feature = "prometheus-metrics"))]
    let _ = enable_prometheus;
    let listeners = config
        .get_mut("listeners")
        .and_then(toml::Value::as_array_mut)
        .filter(|listeners| !listeners.is_empty())
        .expect("server test configuration must contain at least one listener");

    if listeners.len() == 1 {
        listeners[0]
            .as_table_mut()
            .expect("listener must be a table")
            .insert("port".to_owned(), toml::Value::Integer(0));
    } else {
        let mut assigned_ports = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let mut port = unused_dns_port();
            while assigned_ports.contains(&port) {
                port = unused_dns_port();
            }
            assigned_ports.push(port);
            listener
                .as_table_mut()
                .expect("listener must be a table")
                .insert("port".to_owned(), toml::Value::Integer(i64::from(port)));
        }
    }

    let config_id = NEXT_CONFIG_ID.fetch_add(1, Ordering::Relaxed);
    // Keep the generated configuration beside the source configuration so relative TLS paths
    // continue to exercise config-directory-relative resolution.
    let path = original_config_path
        .parent()
        .expect("server configuration must have a parent directory")
        .join(format!(
            ".hickory-dns-test-{}-{config_id}.tmp",
            std::process::id()
        ));
    std::fs::write(
        &path,
        toml::to_string(&config).expect("failed to serialize server configuration"),
    )
    .expect("failed to write temporary server configuration");
    path
}

struct TemporaryConfig(PathBuf);

impl Drop for TemporaryConfig {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0) {
            warn!(path = %self.0.display(), %error, "failed to remove temporary server config");
        }
    }
}

pub struct TestServer {
    pub ports: SocketPorts,
    child: Child,
    stdout: BufReader<ChildStdout>,
    _temporary_config: TemporaryConfig,
}

impl TestServer {
    /// Spins up a Server and handles shutting it down after running the test
    #[allow(dead_code)]
    pub fn start(toml: &str) -> Self {
        Self::start_with_prometheus(toml, true)
    }

    /// Spins up a server without configuring a Prometheus listen address.
    #[cfg(feature = "prometheus-metrics")]
    pub fn start_without_prometheus(toml: &str) -> Self {
        Self::start_with_prometheus(toml, false)
    }

    fn start_with_prometheus(toml: &str, enable_prometheus: bool) -> Self {
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
        println!("using server src path: {server_path}");

        let zone_directory = PathBuf::from(&server_path).join("tests/test-data/test_configs");
        let original_config_path = zone_directory.join(toml);
        let config_path =
            temporary_server_config(&original_config_path, &zone_directory, enable_prometheus);
        let temporary_config = TemporaryConfig(config_path.clone());

        let mut command = Command::new(env!("CARGO_BIN_EXE_hickory-dns"));
        command
        .stdout(Stdio::piped())
        .env(
            "RUST_LOG",
            "hickory_dns=debug,hickory_client=debug,hickory_proto=debug,hickory_resolver=debug,hickory_server=debug",
        )
        .arg("-d")
        .arg(format!("--config={}", config_path.display()));

        println!("named cli options: {command:#?}");

        let mut named = command.spawn().expect("failed to start named");

        println!("server starting");

        let mut stdout = BufReader::new(named.stdout.take().expect("no stdout"));

        // These will be collected from the server startup output
        let mut ports = SocketPorts::default();

        let mut output = String::new();
        let mut found = false;
        let wait_for_start_until = Instant::now() + Duration::from_secs(60);

        // Search strings for the ports used during testing
        let addr_regex = Regex::new(
            r"listening for (UDP|TCP|TLS|HTTPS|QUIC|Prometheus metrics) on ((?:(?:0\.0\.0\.0)|(?:127\.0\.0\.1)|(?:\[::\])):\d+)",
        )
        .unwrap();

        while Instant::now() < wait_for_start_until {
            if let Some(ret_code) = named.try_wait().expect("failed to check status of named") {
                panic!("named has already exited with code: {ret_code}");
            }

            collect_and_print(&mut stdout, &mut output);

            if let Some(addr) = addr_regex.captures(&output) {
                let proto = addr.get(1).expect("missing protocol").as_str();
                let socket_addr = addr.get(2).expect("missing socket addr").as_str();

                let socket_addr =
                    SocketAddr::from_str(socket_addr).expect("could not parse socket_addr");

                match proto {
                    "UDP" => ports.put(Protocol::Udp, socket_addr),
                    "TCP" => ports.put(Protocol::Tcp, socket_addr),
                    #[cfg(feature = "__tls")]
                    "TLS" => ports.put(Protocol::Tls, socket_addr),
                    #[cfg(feature = "__https")]
                    "HTTPS" => ports.put(Protocol::Https, socket_addr),
                    #[cfg(feature = "__quic")]
                    "QUIC" => ports.put(Protocol::Quic, socket_addr),
                    #[cfg(feature = "metrics")]
                    "Prometheus metrics" => {
                        ports.put(ServerProtocol::PrometheusMetrics, socket_addr)
                    }
                    _ => panic!("unsupported protocol: {proto}"),
                }
            } else if output.contains("awaiting connections...") {
                found = true;
                break;
            }
        }

        assert!(found);
        println!("Test server started. ports: {ports:?}");

        Self {
            ports,
            child: named,
            stdout,
            _temporary_config: temporary_config,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        match self.child.kill() {
            Ok(()) => info!("killed test server"),
            Err(err) => warn!("could not kill test server: {err}"),
        }

        let mut line = String::new();
        loop {
            match self.stdout.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    print!("SRV: {line}");
                    line.clear();
                }
                Err(err) => {
                    warn!("could not read remaining stdout: {err}");
                    break;
                }
            }
        }
    }
}

pub async fn query_message<C: ClientHandle>(
    client: &mut C,
    name: Name,
    record_type: RecordType,
) -> Result<DnsResponse, NetError> {
    println!("sending request: {name} for: {record_type}");
    client.query(name, DNSClass::IN, record_type).await
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
pub async fn query_a<C: ClientHandle>(client: &mut C) {
    let name = Name::from_str("www.example.com.").unwrap();
    let response = query_message(client, name, RecordType::A).await.unwrap();
    let record = &response.answers[0];

    if let RData::A(address) = record.data {
        assert_eq!(address, A::new(127, 0, 0, 1))
    } else {
        panic!("wrong RDATA")
    }
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
pub async fn query_a_refused<C: ClientHandle>(client: &mut C) {
    let name = Name::from_str("www.example.com.").unwrap();
    let response = query_message(client, name, RecordType::A).await.unwrap();

    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
#[cfg(feature = "__dnssec")]
pub async fn query_all_dnssec(client: Client<TokioRuntimeProvider>, algorithm: Algorithm) {
    use hickory_proto::{
        dnssec::{
            PublicKey,
            rdata::{DNSKEY, RRSIG},
        },
        rr::RecordData,
    };

    let name = Name::from_str("example.com.").unwrap();
    let mut client = MutMessageHandle::new(client);
    client.lookup_options.dnssec_ok = true;

    let response = query_message(&mut client, name.clone(), RecordType::DNSKEY)
        .await
        .unwrap();

    let dnskey = response
        .answers
        .iter()
        .map(|r| &r.data)
        .filter_map(DNSKEY::try_borrow)
        .find(|d| d.public_key().algorithm() == algorithm);
    assert!(dnskey.is_some(), "DNSKEY not found");

    let response = query_message(&mut client, name, RecordType::DNSKEY)
        .await
        .unwrap();

    let rrsig = response
        .answers
        .iter()
        .map(|r| &r.data)
        .filter_map(RRSIG::try_borrow)
        .filter(|rrsig| rrsig.input().algorithm == algorithm)
        .find(|rrsig| rrsig.input().type_covered == RecordType::DNSKEY);
    assert!(rrsig.is_some(), "Associated RRSIG not found");
}

#[cfg(feature = "__dnssec")]
#[derive(Clone)]
pub struct MutMessageHandle<C: ClientHandle + Unpin> {
    client: C,
    pub lookup_options: LookupOptions,
}

#[cfg(feature = "__dnssec")]
impl<C: ClientHandle + Unpin> MutMessageHandle<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            #[cfg(feature = "__dnssec")]
            lookup_options: LookupOptions::default(),
        }
    }
}

#[cfg(feature = "__dnssec")]
impl<C: ClientHandle + Unpin> DnsHandle for MutMessageHandle<C> {
    type Response = <C as DnsHandle>::Response;
    type Runtime = C::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        // mutable block
        let edns = request.edns.get_or_insert_with(Edns::new);
        edns.set_dnssec_ok(true);

        println!("sending message");
        self.client.send(request)
    }
}
