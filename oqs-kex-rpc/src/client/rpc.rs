use uuid::Uuid;

use jsonrpc_client_http::{HttpTransport, HttpHandle};
use oqs::kex::{AliceMsg, BobMsg};

jsonrpc_client!(pub struct OqsKexRpcClient {
    pub fn kex(&mut self, alice_msgs: &[&AliceMsg]) -> RpcRequest<(Uuid, Vec<BobMsg>)>;
});

impl OqsKexRpcClient<HttpHandle> {
    pub fn connect(addr: &str) -> Self {
        let transport = HttpTransport::new().unwrap();
        let transport_handle = transport.handle(addr).unwrap();
        OqsKexRpcClient::new(transport_handle)
    }
}
