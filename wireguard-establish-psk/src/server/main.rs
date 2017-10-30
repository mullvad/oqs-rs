// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate oqs_kex_rpc;
extern crate wireguard_establish_psk;

use error_chain::ChainedError;

use oqs_kex_rpc::{OqsKexAlg, SharedKey};

use std::result::Result as StdResult;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use wireguard_establish_psk::generate_psk;

mod cli;
mod wg;

static WG_IFACE: &str = "wg0";

static ALLOWED_KEX_ALGORITHMS: &[OqsKexAlg] = &[
    OqsKexAlg::RlweNewhope,
    OqsKexAlg::CodeMcbits,
    OqsKexAlg::SidhCln16,
];

error_chain! {
    errors {
        InvalidPeer(msg: String) {
            description("Invalid wg peer")
            display("Invalid wg peer: {}", msg)
        }
        ScriptError(path: PathBuf) {
            description("Unable to run script")
            display("Unable to run script {}", path.to_string_lossy())
        }
        ScriptExitError(status: ExitStatus) {
            description("Script exited with an error")
            display("Script exited with an error: {}", status)
        }
    }
}

fn main() {
    env_logger::init().unwrap();
    let settings = cli::parse_arguments();
    let on_kex_script = settings.on_kex_script;
    let on_kex = move |meta: KexMetadata, keys: Vec<SharedKey>| on_kex(meta, &keys, &on_kex_script);

    let constraints = oqs_kex_rpc::server::ServerConstraints::new(
        Some(5000),
        Some(ALLOWED_KEX_ALGORITHMS.to_vec()),
        Some(ALLOWED_KEX_ALGORITHMS.len()),
        Some(1),
    );

    let server =
        oqs_kex_rpc::server::start(settings.listen_addr, meta_extractor, on_kex, constraints)
            .expect("Unable to start server");
    server.wait();
}

fn on_kex(metadata: KexMetadata, keys: &[SharedKey], script: &Path) -> Result<()> {
    let peer = metadata.peer.map_err(
        |msg| Error::from(ErrorKind::InvalidPeer(msg)),
    )?;
    let psk = generate_psk(keys);

    let script_result = Command::new(script).arg(&peer.public_key).arg(psk).status();
    match script_result {
        Ok(status) if status.success() => {
            println!("Negotiated new psk for {}", peer.public_key);
            Ok(())
        }
        Ok(status) => Err(Error::from(ErrorKind::ScriptExitError(status))),
        Err(e) => Err(e).chain_err(|| ErrorKind::ScriptError(script.to_owned())),
    }
}


/// Finds the `Peer` for a given request to the kex server.
/// On error a `KexMetadata` without a peer will be returned, then that will make the psk script
/// not run.
fn meta_extractor(request: &oqs_kex_rpc::server::Request) -> KexMetadata {
    KexMetadata { peer: request_to_peer(request) }
}

fn request_to_peer(request: &oqs_kex_rpc::server::Request) -> StdResult<wg::Peer, String> {
    let tunnel_addr = request.remote_addr().ok_or(String::from(
        "No remote addr for the requesting peer",
    ))?;
    let peers = wg::get_peers(WG_IFACE)
        .chain_err(|| "Unable to query wg for peers")
        .map_err(|e| e.display_chain().to_string())?;
    peers
        .into_iter()
        .find(|p| p.tunnel_ips.contains(&tunnel_addr.ip()))
        .ok_or(format!(
            "Could not find peer with tunnel IP {}",
            tunnel_addr.ip()
        ))
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct KexMetadata {
    peer: StdResult<wg::Peer, String>,
}

impl Default for KexMetadata {
    fn default() -> Self {
        KexMetadata { peer: Err(String::from("meta_extractor never executed")) }
    }
}

impl oqs_kex_rpc::server::Metadata for KexMetadata {}
