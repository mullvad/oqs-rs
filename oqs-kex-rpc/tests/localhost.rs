extern crate hyper;
extern crate jsonrpc_core;
extern crate oqs;
extern crate oqs_kex_rpc;

use oqs::kex::OqsKexAlg;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

#[test]
fn full_kex_localhost() {
    let local_addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let algorithms = &[
        OqsKexAlg::MlweKyber,
        OqsKexAlg::CodeMcbits,
        OqsKexAlg::RlweNewhope,
    ];

    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let on_kex = move |meta: Metadata, keys| {
        tx.lock().unwrap().send((meta, keys)).unwrap();
    };

    let server = oqs_kex_rpc::server::start(local_addr, meta_extractor, on_kex).unwrap();

    let http_addr = format!("http://{}", server.address());
    println!("kex server listening on {}", http_addr);

    let mut client = oqs_kex_rpc::client::OqsKexClient::new(&http_addr).unwrap();

    let client_keys = client
        .kex(algorithms)
        .expect("Error in client during exchange");
    let (_meta, server_keys) = rx.recv_timeout(Duration::from_secs(1))
        .expect("Server did not output keys");

    assert_eq!(client_keys.len(), 3);
    assert_eq!(client_keys, server_keys);
    for key in client_keys {
        assert!(!key.data().is_empty());
    }
}

fn meta_extractor(request: &hyper::Request) -> Metadata {
    Metadata {
        remote_addr: request.remote_addr().unwrap(),
    }
}

#[derive(Debug, Copy, Clone)]
struct Metadata {
    remote_addr: SocketAddr,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        }
    }
}

impl jsonrpc_core::Metadata for Metadata {}
