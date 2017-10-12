// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//!
//! Use the [`start`](fn.start.html) function to spawn a key exchange server.

use futures;
use oqs;
use oqs::kex::{AliceMsg, BobMsg, OqsKex, SharedKey};
use oqs::rand::{OqsRand, OqsRandAlg};

use error_chain::ChainedError;

use std::net::SocketAddr;
use std::marker::PhantomData;
use std::result::Result as StdResult;

use jsonrpc_core::{BoxFuture, Error as JsonError, MetaIoHandler};
use jsonrpc_http_server::ServerBuilder;

pub use jsonrpc_core::Metadata;
pub use jsonrpc_http_server::{MetaExtractor, Server};
pub use jsonrpc_http_server::hyper::server::Request;


error_chain! {
    errors {
        /// There was an error while initializing the HTTP server.
        RpcError { description("RPC server error") }
        /// There was an error in the cryptographic operations in `oqs`.
        OqsError { description("OQS error") }
        /// There was an error in the user supplied callback.
        CallbackError { description("Error in on_kex callback") }
    }
}


/// Tries to start a HTTP JSON-RPC 2.0 server bound to `addr`.
///
/// Will call `on_kex` after each finished negotiation and give it the resulting keys of the key
/// exchange.
///
/// `meta_extractor` should be a type that, given a HTTP request, should compute some metadata that
/// one want to associate with the final shared key. The `meta_extractor` will be called before
/// any key exchange starts, and the resulting metadata will be fed to `on_kex` together with the
/// resulting shared keys.
pub fn start<ME, M, E, F>(addr: SocketAddr, meta_extractor: ME, on_kex: F) -> Result<Server>
where
    M: Metadata + Sync,
    ME: MetaExtractor<M>,
    E: ::std::error::Error + Send + 'static,
    F: Fn(M, Vec<SharedKey>) -> StdResult<(), E> + Send + Sync + 'static,
{
    let server = OqsKexRpcServer::new(on_kex);
    let mut io = MetaIoHandler::default();
    io.extend_with(server.to_delegate());

    ServerBuilder::new(io)
        .meta_extractor(meta_extractor)
        .start_http(&addr)
        .chain_err(|| ErrorKind::RpcError)
}


mod api {
    use jsonrpc_core::{BoxFuture, Error};
    use oqs::kex::{AliceMsg, BobMsg};

    build_rpc_trait! {
        pub trait OqsKexRpcServerApi {
            type Metadata;

            #[rpc(meta, name = "kex")]
            fn kex(&self, Self::Metadata, Vec<AliceMsg>) -> BoxFuture<Vec<BobMsg>, Error>;
        }
    }
}
use self::api::OqsKexRpcServerApi;

struct OqsKexRpcServer<M, E, F>
where
    M: Metadata,
    E: ::std::error::Error + Send + 'static,
    F: Fn(M, Vec<SharedKey>) -> StdResult<(), E> + Send + Sync + 'static,
{
    pub on_kex: F,
    _meta: PhantomData<M>,
}

impl<M, E, F> OqsKexRpcServer<M, E, F>
where
    M: Metadata + Sync,
    E: ::std::error::Error + Send + 'static,
    F: Fn(M, Vec<SharedKey>) -> StdResult<(), E> + Send + Sync + 'static,
{
    pub fn new(on_kex: F) -> Self {
        OqsKexRpcServer {
            on_kex,
            _meta: PhantomData,
        }
    }

    fn perform_exchange(&self, meta: M, alice_msgs: &[AliceMsg]) -> Result<Vec<BobMsg>> {
        let rand = OqsRand::new(OqsRandAlg::default()).chain_err(|| ErrorKind::OqsError)?;
        let kexs = Self::init_kex(&rand, &alice_msgs)?;
        let (bob_msgs, keys) = Self::bob(&kexs, alice_msgs)?;
        (self.on_kex)(meta, keys).chain_err(|| ErrorKind::CallbackError)?;
        Ok(bob_msgs)
    }

    fn init_kex<'r>(rand: &'r OqsRand, msgs: &[AliceMsg]) -> Result<Vec<OqsKex<'r>>> {
        msgs.iter()
            .map(|msg| OqsKex::new(&rand, msg.algorithm()))
            .collect::<oqs::kex::Result<_>>()
            .chain_err(|| ErrorKind::OqsError)
    }

    fn bob<'r>(
        kexs: &[OqsKex<'r>],
        alice_msgs: &[AliceMsg],
    ) -> Result<(Vec<BobMsg>, Vec<SharedKey>)> {
        let mut bob_msgs = Vec::with_capacity(alice_msgs.len());
        let mut keys = Vec::with_capacity(alice_msgs.len());

        for (kex, alice_msg) in kexs.iter().zip(alice_msgs) {
            let (bob_msg, key) = kex.bob(alice_msg).chain_err(|| ErrorKind::OqsError)?;
            bob_msgs.push(bob_msg);
            keys.push(key);
        }
        Ok((bob_msgs, keys))
    }
}

impl<M, E, F> OqsKexRpcServerApi for OqsKexRpcServer<M, E, F>
where
    M: Metadata + Sync,
    E: ::std::error::Error + Send + 'static,
    F: Fn(M, Vec<SharedKey>) -> StdResult<(), E> + Send + Sync + 'static,
{
    type Metadata = M;

    fn kex(
        &self,
        meta: Self::Metadata,
        alice_msgs: Vec<AliceMsg>,
    ) -> BoxFuture<Vec<BobMsg>, JsonError> {
        let result = self.perform_exchange(meta, &alice_msgs).map_err(|e| {
            error!("Error during key exchange: {}", e.display_chain());
            JsonError::internal_error()
        });
        Box::new(futures::future::result(result))
    }
}
