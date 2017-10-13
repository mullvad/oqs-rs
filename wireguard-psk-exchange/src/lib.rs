extern crate base64;
extern crate oqs_kex_rpc;
extern crate sha2;

use oqs_kex_rpc::SharedKey;
use sha2::{Digest, Sha512Trunc256};

pub fn generate_psk(keys: &[SharedKey]) -> String {
    let mut hasher = Sha512Trunc256::default();
    for key in keys {
        hasher.input(key.data());
    }

    let digest = hasher.result().to_vec();
    base64::encode(&digest)
}
