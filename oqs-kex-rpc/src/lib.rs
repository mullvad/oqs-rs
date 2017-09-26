#[macro_use]
extern crate error_chain;

extern crate oqs;
extern crate uuid;

#[macro_use]
extern crate jsonrpc_client_core;
extern crate jsonrpc_client_http;

extern crate jsonrpc_core;
extern crate jsonrpc_http_server;
#[macro_use]
extern crate jsonrpc_macros;

pub mod client;
pub mod server;
