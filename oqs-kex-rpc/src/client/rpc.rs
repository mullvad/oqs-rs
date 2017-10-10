// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use jsonrpc_client_http::{HttpHandle, HttpTransport};
use oqs::kex::{AliceMsg, BobMsg};

error_chain! {
    errors {
        RpcInitError { description("RPC client could not be initialized") }
    }
}

jsonrpc_client!(pub struct OqsKexRpcClient {
    pub fn kex(&mut self, alice_msgs: &[&AliceMsg]) -> RpcRequest<Vec<BobMsg>>;
});

impl OqsKexRpcClient<HttpHandle> {
    pub fn connect(server_uri: &str) -> Result<Self> {
        let transport = HttpTransport::new().chain_err(|| ErrorKind::RpcInitError)?;
        let transport_handle = transport
            .handle(server_uri)
            .chain_err(|| ErrorKind::RpcInitError)?;
        Ok(OqsKexRpcClient::new(transport_handle))
    }
}
