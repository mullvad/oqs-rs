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
extern crate sha2;
extern crate base64;

use clap::Arg;
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
    let (server, port) = parse_command_line();

    let server = format_server_addr(&server, &port);
    let algs = [OqsKexAlg::RlweNewhope, OqsKexAlg::CodeMcbits, OqsKexAlg::SidhCln16];

    let keys = establish_quantum_safe_keys(&server, &algs)?;
    let psk = generate_psk(&keys);

    println!("{}", psk);
    Ok(())
}

fn parse_command_line() -> (String, String)
{
    let app = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("server")
            .short("s")
            .long("server")
            .value_name("SERVER")
            .help("Specifies the Wireguard server to connect to")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .value_name("PORT")
            .help("Specifies the port to connect to")
            .takes_value(true)
            .required(true)
            .validator(validate_port));

    let app_matches = app.get_matches();

    // Unwrap is safe because these are required arguments.
    let server = app_matches.value_of("server").unwrap();
    let port = app_matches.value_of("port").unwrap();

    (String::from(server), String::from(port))
}

/// Validate that the argument value for 'port' can be parsed as a valid `int16`
fn validate_port(candidate: String) -> ::std::result::Result<(), String> {
    match candidate.parse::<i16>() {
        Ok(_n) => Ok(()),
        Err(_e) => Err(String::from("Cannot parse 'port' as an integer.")),
    }
}

/// Format server and port into SocketAddr-digestable string.
fn format_server_addr(server: &str, port: &str) -> String {
    if server.contains(":") {
        return format!("[{}]:{}", server, port);
    }
    format!("{}:{}", server, port)
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
