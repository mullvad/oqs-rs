use jsonrpc_client_http::{HttpTransport, HttpHandle};
use oqs::kex::{AliceMsg, BobMsg};

error_chain! {
    errors {
        CreateHttpTransport { description("failed to create HTTP transport") }
        RegisterServerEndpoint { description("failed to register server endpoint in transport context") }
    }
}

jsonrpc_client!(pub struct OqsKexRpcClient {
    pub fn kex(&mut self, alice_msgs: &[&AliceMsg]) -> RpcRequest<Vec<BobMsg>>;
});

impl OqsKexRpcClient<HttpHandle> {
    pub fn connect(addr: &str) -> Result<Self> {
        let transport = HttpTransport::new().chain_err(|| ErrorKind::CreateHttpTransport)?;
        let transport_handle = transport.handle(addr).chain_err(|| ErrorKind::RegisterServerEndpoint)?;
        Ok(OqsKexRpcClient::new(transport_handle))
    }
}
