use std::process::Command;
use std::net::IpAddr;
use std::str::{self, FromStr};

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
        let stdout = str::from_utf8(&output.stdout).chain_err(|| ErrorKind::WgMalformedOutput)?;
        Ok(parse_peers(stdout))
    }
}

fn parse_peers(input: &str) -> Vec<Peer> {
    let mut peers = Vec::new();
    for line in input.lines() {
        if let Ok(peer) = parse_peer(line) {
            peers.push(peer);
        }
    }
    peers
}

type NoopResult<T> = ::std::result::Result<T, ()>;

/// Parse one line of "dump" output from wg into a `Peer`, if it's a valid line.
fn parse_peer(input: &str) -> NoopResult<Peer> {
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

/// Parses a comma separated list of CIDR networks into their IPs.
fn parse_cidrs_to_ips(input: &str) -> NoopResult<Vec<IpAddr>> {
    input
        .split(',')
        .map(|cidr| parse_cidr_to_ip(cidr))
        .collect::<NoopResult<_>>()
}

/// Tries to extract the IP part of a network in CIDR notation.
fn parse_cidr_to_ip(input: &str) -> NoopResult<IpAddr> {
    let parts: Vec<&str> = input.split('/').collect();
    if parts.len() != 2 {
        Err(())
    } else {
        IpAddr::from_str(parts[0]).map_err(|_| ())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_to_ip() {
        let actual = parse_cidr_to_ip("1.2.3.4/16").unwrap();
        assert_eq!(actual, IpAddr::from_str("1.2.3.4").unwrap());
    }

    #[test]
    fn cidrs_to_ips() {
        let actual = parse_cidrs_to_ips("1.2.3.4/16,5678::3/120").unwrap();
        let expected = &[
            IpAddr::from_str("1.2.3.4").unwrap(),
            IpAddr::from_str("5678::3").unwrap(),
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_cidrs_to_ips() {
        assert!(parse_cidrs_to_ips("1.2.3.4/16,not_ip").is_err());
    }

    #[test]
    fn peers() {
        let peers = "XYZ_peer_key1=	XYZ_SECRET1	51820	off\n\
                     XYZ_peer_key2=	XYZ_SECRET2	1.2.3.4:51000	10.99.0.2/32	1616548461	\
                     4571604	6969624	off";
        let actual = parse_peers(peers);
        let expected = vec![
            Peer {
                public_key: String::from("XYZ_peer_key2="),
                tunnel_ips: vec![IpAddr::from_str("10.99.0.2").unwrap()],
            },
        ];
        assert_eq!(actual, expected);
    }
}
