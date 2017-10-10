// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate oqs;
extern crate oqs_kex_rpc;
extern crate wireguard_psk_exchange;

use error_chain::ChainedError;
use oqs::kex::SharedKey;

use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Command};

use wireguard_psk_exchange::generate_psk;

mod cli;
mod wg;

static WG_IFACE: &str = "wg0";

error_chain! {
    errors {
        InvalidPeer { description("No information about this wireguard peer") }
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
    let settings = cli::parse_arguments();
    let on_kex_script = settings.on_kex_script;
    let on_kex = move |meta: KexMetadata, keys: Vec<SharedKey>| {
        on_kex(meta, &keys, &on_kex_script)
    };

    let server = oqs_kex_rpc::server::start(settings.listen_addr, meta_extractor, on_kex)
        .expect("Unable to start server");
    server.wait();
}

fn on_kex(metadata: KexMetadata, keys: &[SharedKey], script: &Path) -> Result<()> {
    let peer = metadata.peer.ok_or(Error::from(ErrorKind::InvalidPeer))?;
    let psk = generate_psk(keys);

    let script_result = Command::new(script).arg(&peer.public_key).arg(psk).status();
    match script_result {
        Ok(status) if status.success() => {
            println!("Negotiated new psk for {}", peer.public_key);
            Ok(())
        },
        Ok(status) => Err(Error::from(ErrorKind::ScriptExitError(status))),
        Err(e) => Err(e).chain_err(|| ErrorKind::ScriptError(script.to_owned())),
    }
}


/// Finds the `Peer` for a given request to the kex server.
/// On error a `KexMetadata` without a peer will be returned, then that will make the psk script
/// not run.
fn meta_extractor(request: &oqs_kex_rpc::server::Request) -> KexMetadata {
    let tunnel_ip = match request.remote_addr() {
        Some(tunnel_addr) => tunnel_addr.ip(),
        None => {
            eprintln!("No remote addr for the requesting peer");
            return KexMetadata::default();
        }
    };
    let peers = match wg::get_peers(WG_IFACE) {
        Ok(peers) => peers,
        Err(e) => {
            eprintln!(
                "{}",
                e.chain_err(|| "Unable to query wg for peers")
                    .display_chain()
            );
            return KexMetadata::default();
        }
    };
    let peer = match peers
        .into_iter()
        .find(|p| p.tunnel_ips.contains(&tunnel_ip))
    {
        Some(peer) => peer,
        None => {
            eprintln!("Could not find peer with tunnel IP {}", tunnel_ip);
            return KexMetadata::default();
        }
    };
    KexMetadata { peer: Some(peer) }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
struct KexMetadata {
    peer: Option<wg::Peer>,
}

impl oqs_kex_rpc::server::Metadata for KexMetadata {}
