#[macro_use]
extern crate error_chain;
extern crate oqs;
extern crate oqs_kex_rpc;
extern crate sha2;
extern crate base64;

use oqs::kex::OqsKexAlg;
use oqs_kex_rpc::client::OqsKexClient;
use sha2::{Sha512Trunc256, Digest};

error_chain! {
    links {
        KeyExchangeFailed(::oqs_kex_rpc::client::Error, ::oqs_kex_rpc::client::ErrorKind);
    }
}

quick_main!(run);

fn run() -> Result<()> {
    let server = "10.99.0.1:1984";
    let algs = [OqsKexAlg::RlweNewhope, OqsKexAlg::CodeMcbits, OqsKexAlg::SidhCln16];

    full_key_exchange(&server, &algs)
        .and_then(|psk| {
            println!("{}", psk);
            Ok(())
        })
}

fn full_key_exchange(server: &str, algorithms: &[OqsKexAlg]) -> Result<String> {
    let mut client = OqsKexClient::new(server)?;
    let keys = client.kex(algorithms)?;

    let mut hasher = Sha512Trunc256::default();
    for key in &keys {
        hasher.input(key.data());
    }

    let digest = hasher.result().to_vec();
    Ok(base64::encode(&digest))
}