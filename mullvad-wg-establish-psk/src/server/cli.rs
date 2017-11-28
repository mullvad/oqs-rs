use clap::{App, Arg, ArgMatches};

use std::collections::HashMap;
use std::path::PathBuf;
use std::net::{IpAddr, SocketAddr};

use oqs_kex_rpc::OqsKexAlg;
use oqs_kex_rpc::server::ServerConstraints;

pub struct Settings {
    pub listen_addr: SocketAddr,
    pub on_kex_script: PathBuf,
    pub constraints: ServerConstraints,
}

lazy_static! {
    static ref ALGORITHMS: HashMap<&'static str, OqsKexAlg> = {
        let mut m = HashMap::new();
        m.insert("bcns15", OqsKexAlg::RlweBcns15);
        m.insert("newhope", OqsKexAlg::RlweNewhope);
        m.insert("msrln16", OqsKexAlg::RlweMsrln16);
        m.insert("sidhcln16", OqsKexAlg::SidhCln16);
        m.insert("sidhcln16_compressed", OqsKexAlg::SidhCln16Compressed);
        m.insert("mcbits", OqsKexAlg::CodeMcbits);
        m.insert("ntru", OqsKexAlg::Ntru);
        m.insert("kyber", OqsKexAlg::MlweKyber);
        m
    };
}

pub fn parse_arguments() -> Settings {
    let app = App::new("mullvad-wg-establish-psk-server")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("address")
                .value_name("LISTEN ADDR")
                .help("Specifies the IP to listen on")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("port")
                .value_name("PORT")
                .help("Specifies the port to listen on")
                .index(2)
                .required(true),
        )
        .arg(
            Arg::with_name("script")
                .value_name("SCRIPT")
                .help("Path to the script to run on each successful key exchange")
                .index(3)
                .required(true),
        )
        .arg(
            Arg::with_name("request_max_size")
                .value_name("SIZE")
                .help("Max size in bytes of incoming request")
                .long("request-max-size")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("request_max_algorithms")
                .value_name("COUNT")
                .help("Max number of key exchanges per request")
                .long("request-max-algorithms")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("request_max_algorithm_occurrences")
                .value_name("COUNT")
                .help("Max number of times a single algorithm may occur per request")
                .long("request-max-alg-occurrences")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("algorithms")
                .value_name("ALGORITHM")
                .help("Specifies one or more algorithms to enable")
                .long("algorithms")
                .takes_value(true)
                .possible_values(&ALGORITHMS.keys().map(|algo| *algo).collect::<Vec<&str>>())
                .multiple(true),
        );

    let matches = app.get_matches();
    let address = value_t!(matches.value_of("address"), IpAddr).unwrap_or_else(|e| e.exit());
    let port = value_t!(matches.value_of("port"), u16).unwrap_or_else(|e| e.exit());
    let script = matches.value_of("script").unwrap();

    let algorithms: Option<Vec<OqsKexAlg>> = matches.values_of("algorithms").map(|algs| {
        algs.map(|alg| *ALGORITHMS.get(alg).unwrap()).collect()
    });

    let max_size = optional_usize(&matches, "request_max_size");
    let max_algos = optional_usize(&matches, "request_max_algorithms");
    let max_algo_occurrences = optional_usize(&matches, "request_max_algorithm_occurrences");

    let constraints = ServerConstraints::new(max_size, algorithms, max_algos, max_algo_occurrences);

    Settings {
        listen_addr: SocketAddr::new(address, port),
        on_kex_script: PathBuf::from(script),
        constraints,
    }
}

fn optional_usize(matches: &ArgMatches, name: &str) -> Option<usize> {
    if matches.is_present(name) {
        Some(value_t!(matches.value_of(name), usize).unwrap_or_else(|e| e.exit()))
    } else {
        None
    }
}
