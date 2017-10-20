// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate jsonrpc_core;
extern crate jsonrpc_http_server;
extern crate oqs;
extern crate oqs_kex_rpc;

use oqs::kex::{OqsKexAlg, SharedKey};
use oqs_kex_rpc::{server, client};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

macro_rules! test_client_server {
    ($name:ident, $algos:expr, $constraints:expr, $verification:expr) => (
        #[test]
        fn $name() {
            let local_addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
            let algorithms = $algos();

            let (tx, rx) = mpsc::channel();
            let tx = Mutex::new(tx);
            let on_kex = move |meta: Metadata, keys| {
                tx.lock().unwrap().send((meta, keys)).unwrap();
                Ok(()) as Result<(), ::std::io::Error>
            };

            let server = server::start(local_addr, meta_extractor, on_kex,
                $constraints()).unwrap();

            let http_addr = format!("http://{}", server.address());
            println!("kex server listening on {}", http_addr);

            let mut client = client::OqsKexClient::new(&http_addr).unwrap();

            $verification(&mut client, &algorithms, &rx);
        }
    )
}

test_client_server!(test_regular_request, algos_default, constraints_none, verify_kex_succeeds);
test_client_server!(test_exotic_request, algos_exotic, constraints_none, verify_kex_succeeds);
test_client_server!(test_null_request, algos_none, constraints_none, verify_kex_succeeds);
test_client_server!(test_regular_request_constrained, algos_default, constraints_default, verify_kex_succeeds);

test_client_server!(test_only_enabled_algo_allowed, algos_exotic, constraints_default, verify_kex_fails);
test_client_server!(test_max_algorithm_constraint, algos_three_newhope, constraints_max_two_algos, verify_kex_fails);
test_client_server!(test_max_occurrences_constraint, algos_two_newhope, constraints_single_newhope_only, verify_kex_fails);

fn constraints_none() -> server::ServerConstraints {
    server::ServerConstraints::new()
}

fn constraints_default() -> server::ServerConstraints {
    server::ServerConstraints::new_init(&algos_default(), 3, 1)
}

fn constraints_single_newhope_only() -> server::ServerConstraints {
    server::ServerConstraints::new_init(&algos_default(), 1, 1)
}

fn constraints_max_two_algos() -> server::ServerConstraints {
    server::ServerConstraints::new_init(&Vec::new(), 2, 0)
}

fn algos_none() -> Vec<OqsKexAlg> {
    Vec::new()
}

fn algos_default() -> Vec<OqsKexAlg> {
    vec!(OqsKexAlg::RlweNewhope, OqsKexAlg::CodeMcbits, OqsKexAlg::SidhCln16)
}

fn algos_exotic() -> Vec<OqsKexAlg> {
    vec!(OqsKexAlg::MlweKyber, OqsKexAlg::Ntru)
}

fn algos_two_newhope() -> Vec<OqsKexAlg> {
    vec!(OqsKexAlg::RlweNewhope, OqsKexAlg::RlweNewhope)
}

fn algos_three_newhope() -> Vec<OqsKexAlg> {
    vec!(OqsKexAlg::RlweNewhope, OqsKexAlg::RlweNewhope, OqsKexAlg::RlweNewhope)
}

fn verify_kex_succeeds(client: &mut client::OqsKexClient, algorithms: &[OqsKexAlg],
    server_channel: &mpsc::Receiver<(Metadata, Vec<SharedKey>)>) {
    let client_keys = client
        .kex(algorithms)
        .expect("Error in client during exchange");
    let (_meta, server_keys) = server_channel.recv_timeout(Duration::from_secs(1))
        .expect("Server did not output keys");

    assert_eq!(client_keys.len(), algorithms.len());
    assert_eq!(client_keys, server_keys);
    for key in client_keys {
        assert!(!key.data().is_empty());
    }
}

fn verify_kex_fails(client: &mut client::OqsKexClient, algorithms: &[OqsKexAlg],
    _server_channel: &mpsc::Receiver<(Metadata, Vec<SharedKey>)>) {
    assert!(client.kex(algorithms).is_err(), "An expected failure in kex did NOT occur");
}

fn meta_extractor(request: &jsonrpc_http_server::hyper::Request) -> Metadata {
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
