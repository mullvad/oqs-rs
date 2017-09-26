pub mod rpc;

use uuid::Uuid;
use oqs::kex::{OqsKexAlg, OqsRandAlg, SharedKey, OqsKex, AliceMsg, OqsKexAlice};
use jsonrpc_client_http::HttpHandle;

pub struct OqsKexClient {
    rpc_client: rpc::OqsKexRpcClient<HttpHandle>,
    rand: OqsRandAlg,
}

impl OqsKexClient {
    pub fn new(addr: &str) -> Self {
        let rpc_client = rpc::OqsKexRpcClient::connect(addr);
        OqsKexClient {
            rpc_client,
            rand: OqsRandAlg::default(),
        }
    }

    pub fn set_rand(&mut self, rand: OqsRandAlg) {
        self.rand = rand;
    }

    pub fn kex(&mut self, algs: &[OqsKexAlg]) -> (Uuid, Vec<SharedKey>) {
        let alices: Vec<OqsKexAlice> = algs.iter()
            .map(|alg| {
                OqsKex::new(self.rand, *alg).unwrap().alice_0().unwrap()
            })
            .collect();

        let (uuid, bob_msgs) = {
            let alice_msgs: Vec<&AliceMsg> = alices.iter().map(|alice| alice.get_alice_msg()).collect();
            self.rpc_client.kex(&alice_msgs).call().unwrap()
        };

        let shared_keys = alices
            .into_iter()
            .zip(bob_msgs)
            .map(|(alice, bob_msg)| alice.alice_1(&bob_msg).unwrap())
            .collect();

        (uuid, shared_keys)
    }
}
