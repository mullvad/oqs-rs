use std::process::Command;
use std::net::IpAddr;
use std::str::FromStr;

error_chain! {
    errors {
        WgProcessError { description("Unable to run the wg command") }
        WgMalformedOutput { description("Invalid output from wg") }
    }
}

/// Metadata about a wireguard peer
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Peer {
    pub public_key: String,
    pub tunnel_ips: Vec<IpAddr>,
}

/// Runs `wg show <iface> dump` and returns the peers on that interface.
pub fn get_peers(iface: &str) -> Result<Vec<Peer>> {
    let output = Command::new("/usr/bin/sudo")
        .args(&["/usr/bin/wg", "show", iface, "dump"])
        .output()
        .chain_err(|| ErrorKind::WgProcessError)?;
    if !output.status.success() {
        Err(Error::from(ErrorKind::WgProcessError))
    } else {
        let stdout = String::from_utf8(output.stdout).chain_err(|| ErrorKind::WgMalformedOutput)?;
        Ok(parse_peers(stdout))
    }
}

fn parse_peers(input: String) -> Vec<Peer> {
    let mut peers = Vec::new();
    for line in input.lines() {
        if let Ok(peer) = parse_peer(line) {
            peers.push(peer);
        }
    }
    peers
}

fn parse_peer(input: &str) -> ::std::result::Result<Peer, ()> {
    let parts: Vec<&str> = input.split('\t').collect();
    if parts.len() != 8 {
        Err(())
    } else {
        Ok(Peer {
            public_key: parts[0].to_owned(),
            tunnel_ips: parse_cidrs_to_ips(parts[3])?,
        })
    }
}

fn parse_cidrs_to_ips(input: &str) -> ::std::result::Result<Vec<IpAddr>, ()> {
    input
        .split(',')
        .map(|cidr| parse_cidr_to_ip(cidr))
        .collect::<::std::result::Result<_, ()>>()
        .map_err(|_| ())
}

/// Tries to extract the IP part of a network in CIDR notation.
fn parse_cidr_to_ip(input: &str) -> ::std::result::Result<IpAddr, ()> {
    let parts: Vec<&str> = input.split('/').collect();
    if parts.len() != 2 {
        Err(())
    } else {
        IpAddr::from_str(parts[0]).map_err(|_| ())
    }
}
