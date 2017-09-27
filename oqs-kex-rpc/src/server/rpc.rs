use oqs::kex::SharedKey;

use std::net::SocketAddr;
use std::str::FromStr;

use jsonrpc_core::IoHandler;
use jsonrpc_http_server::{self, ServerBuilder};

mod api {
    use jsonrpc_core::Error;
    use oqs::kex::{AliceMsg, BobMsg, SharedKey};

    build_rpc_trait! {
        pub trait OqsKexRpcServerApi {
            #[rpc(name = "kex")]
            fn kex(&self, Vec<AliceMsg>) -> Result<Vec<BobMsg>, Error>;
        }
    }

    pub struct OqsKexRpcServer<F>
    where
        F: Fn(Vec<SharedKey>) + Send + Sync + 'static,
    {
        pub on_kex: F,
    }

    impl<F> OqsKexRpcServerApi for OqsKexRpcServer<F>
    where
        F: Fn(Vec<SharedKey>) + Send + Sync + 'static,
    {
        fn kex(&self, _alice_msgs: Vec<AliceMsg>) -> Result<Vec<BobMsg>, Error> {
            unimplemented!();
        }
    }
}
use self::api::{OqsKexRpcServer, OqsKexRpcServerApi};

error_chain! {
    foreign_links {
        AddrParseError(::std::net::AddrParseError);
        HttpServerError(jsonrpc_http_server::Error);
    }
}

/// Tries to start a HTTP JSON-RPC 2.0 server at `addr`. Will call `on_kex` after each finished
/// negotiation and give it the uuid and the resulting keys of the key exchange.
pub fn start<F>(addr: &str, on_kex: F) -> Result<jsonrpc_http_server::Server>
where
    F: Fn(Vec<SharedKey>) + Send + Sync + 'static,
{
    let parsed_addr = SocketAddr::from_str(addr)?;

    let server = OqsKexRpcServer { on_kex };
    let mut io = IoHandler::new();
    io.extend_with(server.to_delegate());

    ServerBuilder::new(io)
        .start_http(&parsed_addr)
        .map_err(Error::from)
}
