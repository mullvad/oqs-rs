// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A client and server able to perform post-quantum safe key exchanges over HTTP based
//! JSON-RPC 2.0. The client and server uses [oqs] for the cryptography.
//!
//! # Example
//!
//! This example code shows how to set up a key exchange server listening on localhost
//! and then perform a key exchange with it from a client instance.
//!
//! ```rust
//! extern crate oqs_kex_rpc;
//!
//! use oqs_kex_rpc::server::ServerConstraints;
//! use oqs_kex_rpc::client::OqsKexClient;
//! use oqs_kex_rpc::{OqsKexAlg, SharedKey};
//! # use std::net::SocketAddr;
//! # use std::str::FromStr;
//!
//! static ALGORITHMS: &[oqs_kex_rpc::OqsKexAlg] = &[
//!     OqsKexAlg::RlweNewhope,
//! ];
//!
//! # fn main() {
//! // This is the callback that will be called on the server after the shared key
//! // has been computed on the server, but before Bob's messages are returned
//! // to the client.
//! let on_kex = move |_metadata: (), keys: Vec<SharedKey>| {
//!     println!("Done exchanging {} keys", keys.len());
//!     // If this callback return an `Err`, Bob's messages will not be returned
//!     // to the client, instead a JSON-RPC error will be returned.
//!     Ok(()) as Result<(), ::std::io::Error>
//! };
//!
//! // See the `start` function's documentation for an explanation of the
//! // `meta_extractor` and how it can be used. Here it does the least possible to
//! // keep the example simple.
//! let meta_extractor = |_: &oqs_kex_rpc::server::Request| ();
//!
//! // Start the server on localhost. Port zero means that the OS will pick a
//! // random port that we can later get with `server.address()`.
//! let server: oqs_kex_rpc::server::Server = oqs_kex_rpc::server::start(
//!     SocketAddr::from_str("127.0.0.1:0").unwrap(),
//!     meta_extractor,
//!     on_kex,
//!     ServerConstraints::default(),
//! ).expect("Unable to start RPC server");
//!
//! let http_addr = format!("http://{}", server.address());
//! println!("kex server listening on {}", http_addr);
//!
//! // Connect a client to our localhost server and exchange keys with it
//! let mut client = OqsKexClient::new(&http_addr).unwrap();
//! let client_keys = client.kex(ALGORITHMS).expect("Error in client during exchange");
//!
//! // Check that the result is sane (same algorithms as requested)
//! assert_eq!(client_keys.len(), ALGORITHMS.len());
//! for (key, algorithm) in client_keys.iter().zip(ALGORITHMS) {
//!     assert_eq!(key.algorithm(), *algorithm);
//! }
//! # }
//! ```
//!
//! [oqs]: https://crates.io/crates/oqs

#![deny(missing_docs)]

#[macro_use]
extern crate error_chain;
extern crate futures;
#[macro_use]
extern crate log;
extern crate oqs;

#[macro_use]
extern crate jsonrpc_client_core;
extern crate jsonrpc_client_http;

extern crate jsonrpc_core;
extern crate jsonrpc_http_server;
#[macro_use]
extern crate jsonrpc_macros;


pub use oqs::kex::{OqsKexAlg, SharedKey};
pub use oqs::rand::OqsRandAlg;

/// Module containing a JSON-RPC 2.0 client for key exchange.
pub mod client;

/// Module containing a JSON-RPC 2.0 server for key exchange.
pub mod server;
