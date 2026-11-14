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
