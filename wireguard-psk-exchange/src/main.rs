// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate error_chain;
extern crate oqs;
extern crate oqs_kex_rpc;
extern crate sha2;
extern crate base64;

use oqs::kex::{OqsKexAlg, SharedKey};
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

    let keys = establish_quantum_safe_keys(&server, &algs)?;
    let psk = generate_psk(&keys);

    println!("{}", psk);
    Ok(())
}

fn establish_quantum_safe_keys(server: &str, algorithms: &[OqsKexAlg]) -> Result<Vec<SharedKey>> {
    let mut client = OqsKexClient::new(server)?;
    Ok(client.kex(algorithms)?)
}

fn generate_psk(keys: &[SharedKey]) -> String {
    let mut hasher = Sha512Trunc256::default();
    for key in keys {
        hasher.input(key.data());
    }

    let digest = hasher.result().to_vec();
    base64::encode(&digest)
}
