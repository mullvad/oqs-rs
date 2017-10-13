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
