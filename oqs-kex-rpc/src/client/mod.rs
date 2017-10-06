pub mod rpc;

use oqs::kex::{OqsKexAlg, OqsRandAlg, SharedKey, OqsKex, AliceMsg, BobMsg, OqsKexAlice};
use jsonrpc_client_http::HttpHandle;

error_chain! {
    errors {
        RpcError { description("RPC client returned an error") }
        InvalidResponse { description("RPC response is syntactically valid but unexpected") }
        OqsError { description("Oqs returned an error") }
    }
}

pub struct OqsKexClient {
    rpc_client: rpc::OqsKexRpcClient<HttpHandle>,
    rand: OqsRandAlg,
}

impl OqsKexClient {
    pub fn new(addr: &str) -> Result<Self> {
        let rpc_client = rpc::OqsKexRpcClient::connect(addr).chain_err(|| ErrorKind::RpcError)?;

        let client = OqsKexClient {
            rpc_client,
            rand: OqsRandAlg::default(),
        };

        Ok(client)
    }

    pub fn set_rand(&mut self, rand: OqsRandAlg) {
        self.rand = rand;
    }

    pub fn kex(&mut self, algs: &[OqsKexAlg]) -> Result<Vec<SharedKey>> {
        let alices: Vec<OqsKexAlice> = self.initialize_kex(algs)?;

        let bob_msgs: Vec<BobMsg> = {
            let alice_msgs: Vec<&AliceMsg> = alices.iter().map(|alice| alice.get_alice_msg()).collect();
            self.rpc_client.kex(&alice_msgs).call().chain_err(|| ErrorKind::RpcError)?
        };

        ensure!(alices.len() == bob_msgs.len(), ErrorKind::InvalidResponse);

        self.finalize_kex(alices, &bob_msgs)
    }

    fn initialize_kex(&mut self, algs: &[OqsKexAlg]) -> Result<Vec<OqsKexAlice>> {
        let mut alices: Vec<OqsKexAlice> = Vec::new();

        for alg in algs {
           let oqskex = OqsKex::new(self.rand, *alg).chain_err(|| ErrorKind::OqsError)?;
           let alice = oqskex.alice_0().chain_err(|| ErrorKind::OqsError)?;
           alices.push(alice);
        }

        Ok(alices)
    }

    fn finalize_kex(&mut self, alices: Vec<OqsKexAlice>, bob_msgs: &Vec<BobMsg>) -> Result<Vec<SharedKey>> {
        let mut keys: Vec<SharedKey> = Vec::new();

        for (alice, bob_msg) in alices.into_iter().zip(bob_msgs) {
            let key = alice.alice_1(&bob_msg).chain_err(|| ErrorKind::OqsError)?;
            keys.push(key);
        }

        Ok(keys)
    }
}
