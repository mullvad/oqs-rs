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
extern crate oqs;
extern crate oqs_kex_rpc;
extern crate wireguard_psk_exchange;

use clap::Arg;
use oqs::kex::{OqsKexAlg, SharedKey};
use oqs_kex_rpc::client::OqsKexClient;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use wireguard_psk_exchange::generate_psk;

error_chain! {
    links {
        KeyExchangeFailed(::oqs_kex_rpc::client::Error, ::oqs_kex_rpc::client::ErrorKind);
    }
}

quick_main!(run);

fn run() -> Result<()> {
    env_logger::init().unwrap();
    let server_uri = parse_command_line();
    let algs = [
        OqsKexAlg::RlweNewhope,
        OqsKexAlg::CodeMcbits,
        OqsKexAlg::SidhCln16,
    ];

    let keys = establish_quantum_safe_keys(&server_uri, &algs)?;
    let psk = generate_psk(&keys);

    println!("{}", psk);
    Ok(())
}

fn parse_command_line() -> String {
    let app = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("SERVER")
                .help("Specifies the Wireguard server to connect to")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("Specifies the port to connect to")
                .takes_value(true)
                .required(true),
        );

    let app_matches = app.get_matches();

    let server = app_matches.value_of("server").unwrap();
    let port = value_t!(app_matches.value_of("port"), u16).unwrap_or_else(|e| e.exit());

    format_server_uri(server, port)
}

fn format_server_uri(server: &str, port: u16) -> String {
    let addr_port = match IpAddr::from_str(server) {
        Ok(ip) => format!("{}", SocketAddr::new(ip, port)),
        Err(_) => format!("{}:{}", server, port),
    };
    format!("http://{}", addr_port)
}

fn establish_quantum_safe_keys(
    server_uri: &str,
    algorithms: &[OqsKexAlg],
) -> Result<Vec<SharedKey>> {
    let mut client = OqsKexClient::new(server_uri)?;
    Ok(client.kex(algorithms)?)
}
