// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;

use crate::server_harness::{TestServer, query_a};
use hickory_net::client::Client;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::Protocol;
use test_support::subscribe;

/// Tests that multiple `[[listeners]]` entries each bind their own port, and that each serves
/// queries (https://github.com/hickory-dns/hickory-dns/issues/3820).
#[tokio::test]
async fn test_multiple_listeners() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("multi_listeners.toml");

    let tcp_addrs: Vec<SocketAddr> = server.ports.get_all(Protocol::Tcp).to_vec();
    let udp_addrs: Vec<SocketAddr> = server.ports.get_all(Protocol::Udp).to_vec();

    assert_eq!(
        tcp_addrs.len(),
        2,
        "expected two TCP listeners, got {tcp_addrs:?}"
    );
    assert_eq!(
        udp_addrs.len(),
        2,
        "expected two UDP listeners, got {udp_addrs:?}"
    );
    assert_ne!(
        tcp_addrs[0].port(),
        tcp_addrs[1].port(),
        "listeners must bind distinct ports"
    );
    assert_ne!(
        udp_addrs[0].port(),
        udp_addrs[1].port(),
        "listeners must bind distinct ports"
    );

    for addr in tcp_addrs {
        let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
        let stream = future.await.expect("failed to create tcp stream");
        let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
        tokio::spawn(bg);

        query_a(&mut client).await;
    }

    for addr in udp_addrs {
        let stream = UdpClientStream::builder(addr, provider.clone()).build();
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);

        query_a(&mut client).await;
    }
}

/// CLI port flags are rejected when `[[listeners]]` is configured
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #2).
/// `--validate` must reach the same rejection: it runs every expansion-time check.
#[test]
fn test_reject_cli_port_override_with_listeners() {
    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    for validate in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_hickory-dns"));
        command
            .arg(format!(
                "--config={server_path}/tests/test-data/test_configs/multi_listeners.toml"
            ))
            .arg(format!(
                "--zonedir={server_path}/tests/test-data/test_configs"
            ))
            .arg("--logging=stdout")
            .arg("--port=0");
        if validate {
            command.arg("--validate");
        }
        let output = command.output().expect("failed to run hickory-dns");
        assert!(!output.status.success(), "--validate={validate}");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            text.contains("cannot be used when `[[listeners]]` is configured"),
            "unexpected output: {text}"
        );
    }
}

/// `--validate` surfaces certificate load failures before reporting success
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #1).
#[cfg(feature = "__tls")]
#[test]
fn test_validate_rejects_missing_certificate() {
    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let config_path = std::env::temp_dir().join("hickory-test-listener-badcert.toml");
    std::fs::write(
        &config_path,
        r#"
[tls_cert]
path = "tls/no-such-certificate.pem"
private_key = "tls/no-such-certificate.key"

[[listeners]]
address = "127.0.0.1"
port = 0
protocols = ["tls"]

[[zones]]
zone = "example.com"
file = "example.com.zone"
"#,
    )
    .expect("failed to write test config");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hickory-dns"))
        .arg(format!("--config={}", config_path.display()))
        .arg(format!(
            "--zonedir={server_path}/tests/test-data/test_configs"
        ))
        .arg("--logging=stdout")
        .arg("--validate")
        .output()
        .expect("failed to run hickory-dns");

    let _ = std::fs::remove_file(&config_path);
    assert!(
        !output.status.success(),
        "`--validate` must reject a certificate that cannot be loaded"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("failed to load TLS certificate"),
        "unexpected output: {text}"
    );
}

/// An HTTPS listener serves its own `http_endpoint`, overriding the top-level one
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #6).
#[cfg(all(not(windows), feature = "__https"))]
#[tokio::test]
async fn test_listeners_https_endpoint_override() {
    subscribe();

    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let ca_cert = crate::server_harness::tls::prepare_certificates(&server_path);

    let server = TestServer::start("multi_listeners_https_endpoint.toml");
    let https_port = server.ports.get_v4(Protocol::Https);
    let addr = SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        https_port.expect("no https_port"),
    ));
    std::thread::sleep(std::time::Duration::from_secs(1));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store.add(ca_cert.clone()).unwrap();

    let mut client_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        hickory_net::tls::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();
    client_config.alpn_protocols.push(b"h2".to_vec());

    // The listener's own endpoint serves DNS.
    let sender = hickory_net::h2::HttpsClientStream::builder(
        std::sync::Arc::new(client_config.clone()),
        TokioRuntimeProvider::new(),
    )
    .build(
        addr,
        std::sync::Arc::from("ns.example.com"),
        std::sync::Arc::from("/dns-test"),
    )
    .await
    .unwrap();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);
    tokio::spawn(bg);
    query_a(&mut client).await;

    // The top-level endpoint is not served by this listener.
    let sender = hickory_net::h2::HttpsClientStream::builder(
        std::sync::Arc::new(client_config),
        TokioRuntimeProvider::new(),
    )
    .build(
        addr,
        std::sync::Arc::from("ns.example.com"),
        std::sync::Arc::from("/dns-query"),
    )
    .await
    .unwrap();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);
    tokio::spawn(bg);
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    let name = Name::from_str("www.example.com.").unwrap();
    assert!(
        crate::server_harness::query_message(&mut client, name, RecordType::A)
            .await
            .is_err(),
        "the listener must not serve the top-level endpoint"
    );
}

/// Runs the server with `extra_args` and collects its startup log lines until it reports
/// `awaiting connections...`, the process exits, or 30 seconds pass.
#[cfg(all(not(windows), feature = "__tls"))]
fn collect_startup_lines(
    server_path: &str,
    config_path: &std::path::Path,
    extra_args: &[&str],
) -> Vec<String> {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_hickory-dns"))
        .arg(format!("--config={}", config_path.display()))
        .arg(format!(
            "--zonedir={server_path}/tests/test-data/test_configs"
        ))
        .arg("--logging=stdout")
        .args(extra_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to run hickory-dns");

    let stdout = child.stdout.take().expect("no stdout");
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = sender.send(line);
        }
    });

    let mut lines = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(line) => {
                let ready = line.contains("awaiting connections...");
                lines.push(line);
                if ready {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(Some(status)) = child.try_wait() {
                    let _ = child.kill();
                    panic!("server exited early: {status}");
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    panic!("server did not report readiness in 30s");
                }
            }
            Err(_) => {
                let _ = child.kill();
                panic!("server stdout closed before startup completed");
            }
        }
    }

    child.kill().expect("failed to kill server");
    lines
}

/// `--disable-tls` removes TLS from listener protocols while leaving the rest
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #6).
#[cfg(all(not(windows), feature = "__tls"))]
#[test]
fn test_listeners_disable_tls_filters_protocols() {
    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    crate::server_harness::tls::prepare_certificates(&server_path);

    let config_path = std::env::temp_dir().join("hickory-test-listener-disable-tls.toml");
    std::fs::write(
        &config_path,
        r#"
[tls_cert]
path = "tls/example.pem"
private_key = "tls/example.key"

[[listeners]]
address = "127.0.0.1"
port = 0
protocols = ["udp", "tls"]

[[zones]]
zone = "example.com"
file = "example.com.zone"
"#,
    )
    .expect("failed to write test config");

    // Without the flag, both protocols bind.
    let lines = collect_startup_lines(&server_path, &config_path, &[]);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("listening for UDP on")),
        "no UDP binding logged: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("listening for TLS on")),
        "no TLS binding logged: {lines:?}"
    );

    // With the flag, only UDP binds.
    let lines = collect_startup_lines(&server_path, &config_path, &["--disable-tls"]);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("listening for UDP on")),
        "no UDP binding logged: {lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("listening for TLS on")),
        "TLS binding leaked through --disable-tls: {lines:?}"
    );

    let _ = std::fs::remove_file(&config_path);
}

/// Connects to a DoT listener and sends one query, returning whether the TLS handshake
/// succeeded.
#[cfg(all(not(windows), feature = "__tls"))]
async fn try_query_dot(
    ca_cert: &rustls::pki_types::CertificateDer<'static>,
    addr: SocketAddr,
    server_name: &str,
) -> bool {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_cert.clone()).expect("bad certificate");

    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            hickory_net::tls::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth(),
    );

    let (future, sender) = hickory_net::tls::tls_client_connect(
        addr,
        rustls::pki_types::ServerName::try_from(server_name.to_owned()).unwrap(),
        config,
        TokioRuntimeProvider::new(),
    );
    let Ok(stream) = future.await else {
        return false;
    };
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;
    true
}

/// Two TLS listeners serve different certificates: the first from the top-level `tls_cert`,
/// the second from its own
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #4).
#[cfg(all(not(windows), feature = "__tls"))]
#[tokio::test]
async fn test_listeners_distinct_certs() {
    subscribe();

    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let ca_cert = crate::server_harness::tls::prepare_certificates(&server_path);

    let server = TestServer::start("multi_listeners_two_certs.toml");
    let tls_addrs: Vec<SocketAddr> = server.ports.get_all(Protocol::Tls).to_vec();
    assert_eq!(
        tls_addrs.len(),
        2,
        "expected two TLS listeners, got {tls_addrs:?}"
    );

    // The first listener falls back to the top-level certificate.
    assert!(
        try_query_dot(ca_cert, tls_addrs[0], "ns.example.com").await,
        "first listener must serve the top-level certificate"
    );
    // The second listener uses its own certificate and endpoint name.
    assert!(
        try_query_dot(ca_cert, tls_addrs[1], "alt.example.com").await,
        "second listener must serve its own certificate"
    );
    // ...and not the top-level certificate, whose name it does not carry.
    assert!(
        !try_query_dot(ca_cert, tls_addrs[1], "ns.example.com").await,
        "second listener must not serve the top-level certificate"
    );
}

/// Exercises a TLS listener end-to-end in `[[listeners]]` mode
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #6).
#[cfg(all(not(windows), feature = "__tls"))]
#[tokio::test]
async fn test_listeners_tls() {
    subscribe();

    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let ca_cert = crate::server_harness::tls::prepare_certificates(&server_path);

    let server = TestServer::start("multi_listeners_tls.toml");
    let tls_port = server.ports.get_v4(Protocol::Tls);
    let addr = SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        tls_port.expect("no tls_port"),
    ));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_cert.clone()).expect("bad certificate");

    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            hickory_net::tls::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth(),
    );

    let (future, sender) = hickory_net::tls::tls_client_connect(
        addr,
        rustls::pki_types::ServerName::try_from("ns.example.com").unwrap(),
        config,
        TokioRuntimeProvider::new(),
    );
    let stream = future.await.expect("client failed to connect");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;
}

/// Exercises an HTTPS listener end-to-end in `[[listeners]]` mode
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #6).
#[cfg(all(not(windows), feature = "__https"))]
#[tokio::test]
async fn test_listeners_https() {
    subscribe();

    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let ca_cert = crate::server_harness::tls::prepare_certificates(&server_path);

    let server = TestServer::start("multi_listeners_https.toml");
    let https_port = server.ports.get_v4(Protocol::Https);
    let addr = SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        https_port.expect("no https_port"),
    ));
    std::thread::sleep(std::time::Duration::from_secs(1));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store.add(ca_cert.clone()).unwrap();

    let mut client_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        hickory_net::tls::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();
    client_config.alpn_protocols.push(b"h2".to_vec());

    let sender = hickory_net::h2::HttpsClientStream::builder(
        std::sync::Arc::new(client_config),
        TokioRuntimeProvider::new(),
    )
    .build(
        addr,
        std::sync::Arc::from("ns.example.com"),
        std::sync::Arc::from("/dns-query"),
    )
    .await
    .unwrap();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);
    tokio::spawn(bg);

    query_a(&mut client).await;
    query_a(&mut client).await;
}

/// Exercises a QUIC listener end-to-end in `[[listeners]]` mode
/// (https://github.com/hickory-dns/hickory-dns/issues/3820 review finding #6).
#[cfg(all(not(windows), feature = "__quic"))]
#[tokio::test]
async fn test_listeners_quic() {
    subscribe();

    let server_path = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    let ca_cert = crate::server_harness::tls::prepare_certificates(&server_path);

    let server = TestServer::start("multi_listeners_quic.toml");
    let quic_port = server.ports.get_v4(Protocol::Quic);
    let addr = SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        quic_port.expect("no quic_port"),
    ));
    std::thread::sleep(std::time::Duration::from_secs(1));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store.add(ca_cert.clone()).unwrap();

    let client_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        hickory_net::tls::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(
        hickory_net::quic::QuicClientStream::builder()
            .crypto_config(client_config)
            .build(addr, std::sync::Arc::from("ns.example.com"))
            .await
            .expect("client failed to connect"),
    );
    tokio::spawn(bg);

    query_a(&mut client).await;
    query_a(&mut client).await;
}
