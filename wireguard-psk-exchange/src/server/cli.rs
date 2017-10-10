use clap::{App, Arg};

use std::path::PathBuf;
use std::net::SocketAddr;

pub struct Settings {
    pub listen_addr: SocketAddr,
    pub on_kex_script: PathBuf,
}

pub fn parse_arguments() -> Settings {
    let app = App::new("wg-psk-exchange-server")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("address")
                .value_name("LISTEN ADDR")
                .help("Specifies the IP and port to listen on (eg. 0.0.0.0:9876)")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("script")
                .value_name("SCRIPT")
                .help("Path to the script to run on each successful key exchange")
                .index(2)
                .required(true),
        );

    let matches = app.get_matches();
    let address = value_t!(matches.value_of("address"), SocketAddr).unwrap_or_else(|e| e.exit());
    let script = matches.value_of("script").unwrap();

    Settings {
        listen_addr: address,
        on_kex_script: PathBuf::from(script),
    }
}
