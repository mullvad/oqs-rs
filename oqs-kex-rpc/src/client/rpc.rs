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
    pub fn connect(addr: &str) -> Result<Self> {
        let transport = HttpTransport::new().chain_err(|| ErrorKind::RpcInitError)?;
        let transport_handle = transport.handle(addr).chain_err(|| ErrorKind::RpcInitError)?;
        Ok(OqsKexRpcClient::new(transport_handle))
    }
}
