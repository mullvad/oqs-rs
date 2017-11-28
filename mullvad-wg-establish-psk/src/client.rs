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
extern crate mullvad_wg_establish_psk;

use clap::Arg;
use oqs_kex_rpc::{OqsKexAlg, SharedKey};
use oqs_kex_rpc::client::OqsKexClient;

use mullvad_wg_establish_psk::generate_psk;

error_chain! {
    links {
        KeyExchangeFailed(::oqs_kex_rpc::client::Error, ::oqs_kex_rpc::client::ErrorKind);
    }
}

quick_main!(run);

fn run() -> Result<()> {
    env_logger::init().unwrap();
    let server_uri = parse_command_line();
    let algs = [OqsKexAlg::RlweNewhope];

    let keys = establish_quantum_safe_keys(&server_uri, &algs)?;
    let psk = generate_psk(&keys);

    println!("{}", psk);
    Ok(())
}

fn parse_command_line() -> String {
    let app = clap::App::new("mullvad-wg-establish-psk")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("server")
                .value_name("SERVER")
                .help("Specifies the Wireguard server to connect to")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("port")
                .value_name("PORT")
                .help("Specifies the port to connect to")
                .index(2)
                .required(true),
        );

    let matches = app.get_matches();

    let server = matches.value_of("server").unwrap();
    let port = value_t!(matches.value_of("port"), u16).unwrap_or_else(|e| e.exit());

    format!("http://{}:{}", server, port)
}

fn establish_quantum_safe_keys(
    server_uri: &str,
    algorithms: &[OqsKexAlg],
) -> Result<Vec<SharedKey>> {
    let mut client = OqsKexClient::new(server_uri)?;
    Ok(client.kex(algorithms)?)
}
