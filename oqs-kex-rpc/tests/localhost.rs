// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate oqs_kex_rpc;

#[macro_use]
extern crate lazy_static;

use oqs_kex_rpc::{client, server, OqsKexAlg, SharedKey};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

fn test_helper(
    algorithms: &[OqsKexAlg],
    constraints: &server::ServerConstraints,
    verifier: fn(&mut client::OqsKexClient,
                 &[OqsKexAlg],
                 &mpsc::Receiver<(Metadata, Vec<SharedKey>)>),
) {
    let local_addr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let on_kex = move |meta: Metadata, keys| {
        tx.lock().unwrap().send((meta, keys)).unwrap();
        Ok(()) as Result<(), ::std::io::Error>
    };

    let server = server::start(local_addr, meta_extractor, on_kex, constraints.clone()).unwrap();

    let http_addr = format!("http://{}", server.address());
    println!("kex server listening on {}", http_addr);

    let mut client = client::OqsKexClient::new(&http_addr).unwrap();

    verifier(&mut client, algorithms, &rx);
}

lazy_static! {
    static ref CONSTRAINTS_NONE: server::ServerConstraints =
        server::ServerConstraints::default();
    static ref CONSTRAINTS_DEFAULT: server::ServerConstraints =
        server::ServerConstraints::new(
            None,
            Some(ALGOS_DEFAULT.to_vec()),
            Some(ALGOS_DEFAULT.len()),
            Some(1),
        );
    static ref CONSTRAINTS_SINGLE_NEWHOPE: server::ServerConstraints =
        server::ServerConstraints::new(None, Some(vec![OqsKexAlg::RlweNewhope]), Some(1), Some(1));
    static ref CONSTRAINTS_MAX_TWO_ALGOS: server::ServerConstraints =
        server::ServerConstraints::new(None, None, Some(2), None);
    static ref CONSTRAINTS_REQUEST_MAX_10KB: server::ServerConstraints =
        server::ServerConstraints::new(Some(1024 * 10), None, None, None);
    static ref CONSTRAINTS_REQUEST_MAX_1KB: server::ServerConstraints =
        server::ServerConstraints::new(Some(1024), None, None, None);
}

static ALGOS_NONE: &[OqsKexAlg] = &[];
static ALGOS_DEFAULT: &[OqsKexAlg] = &[
    OqsKexAlg::RlweNewhope,
    OqsKexAlg::CodeMcbits,
    OqsKexAlg::SidhCln16,
];
static ALGOS_EXOTIC: &[OqsKexAlg] = &[OqsKexAlg::MlweKyber, OqsKexAlg::Ntru];
static ALGOS_SINGLE_NEWHOPE: &[OqsKexAlg] = &[OqsKexAlg::RlweNewhope];
static ALGOS_TWO_NEWHOPE: &[OqsKexAlg] = &[OqsKexAlg::RlweNewhope, OqsKexAlg::RlweNewhope];
static ALGOS_THREE_NEWHOPE: &[OqsKexAlg] = &[
    OqsKexAlg::RlweNewhope,
    OqsKexAlg::RlweNewhope,
    OqsKexAlg::RlweNewhope,
];

#[test]
fn test_regular_request() {
    test_helper(ALGOS_DEFAULT, &CONSTRAINTS_NONE, verify_kex_succeeds)
}

#[test]
fn test_exotic_request() {
    test_helper(ALGOS_EXOTIC, &CONSTRAINTS_NONE, verify_kex_succeeds)
}

#[test]
fn test_null_request() {
    test_helper(ALGOS_NONE, &CONSTRAINTS_NONE, verify_kex_succeeds)
}

#[test]
fn test_regular_request_constrained() {
    test_helper(ALGOS_DEFAULT, &CONSTRAINTS_DEFAULT, verify_kex_succeeds)
}

#[test]
fn test_only_enabled_algos_allowed() {
    test_helper(ALGOS_EXOTIC, &CONSTRAINTS_DEFAULT, verify_kex_fails)
}

#[test]
fn test_max_algorithm_constraint() {
    test_helper(
        ALGOS_THREE_NEWHOPE,
        &CONSTRAINTS_MAX_TWO_ALGOS,
        verify_kex_fails,
    )
}

#[test]
fn test_max_occurrences_constraint() {
    test_helper(
        ALGOS_TWO_NEWHOPE,
        &CONSTRAINTS_SINGLE_NEWHOPE,
        verify_kex_fails,
    )
}

#[test]
fn test_large_request_max_size_permits_request() {
    test_helper(
        ALGOS_SINGLE_NEWHOPE,
        &CONSTRAINTS_REQUEST_MAX_10KB,
        verify_kex_succeeds,
    )
}

#[test]
fn test_small_request_max_size_rejects_request() {
    test_helper(
        ALGOS_THREE_NEWHOPE,
        &CONSTRAINTS_REQUEST_MAX_1KB,
        verify_kex_fails,
    )
}


fn verify_kex_succeeds(
    client: &mut client::OqsKexClient,
    algorithms: &[OqsKexAlg],
    server_channel: &mpsc::Receiver<(Metadata, Vec<SharedKey>)>,
) {
    let client_keys = client.kex(algorithms).expect(
        "Error in client during exchange",
    );
    let (_meta, server_keys) = server_channel.recv_timeout(Duration::from_secs(1)).expect(
        "Server did not output keys",
    );

    assert_eq!(client_keys.len(), algorithms.len());
    assert_eq!(client_keys, server_keys);
    for key in client_keys {
        assert!(!key.data().is_empty());
    }
}

fn verify_kex_fails(
    client: &mut client::OqsKexClient,
    algorithms: &[OqsKexAlg],
    _server_channel: &mpsc::Receiver<(Metadata, Vec<SharedKey>)>,
) {
    assert!(
        client.kex(algorithms).is_err(),
        "An expected failure in kex did NOT occur"
    );
}

fn meta_extractor(request: &oqs_kex_rpc::server::Request) -> Metadata {
    Metadata { remote_addr: request.remote_addr().unwrap() }
}

#[derive(Debug, Copy, Clone)]
struct Metadata {
    remote_addr: SocketAddr,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata { remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0) }
    }
}

impl oqs_kex_rpc::server::Metadata for Metadata {}
