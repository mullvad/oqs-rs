#![feature(test)]

extern crate oqs;
extern crate test;

use test::Bencher;
use oqs::kex::{OqsKex, OqsKexAlg};
use oqs::rand::{OqsRand, OqsRandAlg};

/// Macro generating all benchmarks for a given KEX algorithm
macro_rules! bench_kex {
    ($alg:ident) => (
        #[allow(non_snake_case)]
        mod $alg {
            use super::*;
            bench_alice0!($alg);
            bench_bob!($alg);
            bench_full_kex!($alg);
        }
    )
}

macro_rules! bench_alice0 {
    ($algo:ident) => (
        #[bench]
        fn alice_0(b: &mut Bencher) {
            let rand = OqsRand::new(OqsRandAlg::default()).unwrap();
            let kex = OqsKex::new(&rand, OqsKexAlg::$algo).unwrap();
            b.iter(|| {
                kex.alice_0().unwrap()
            });
        }
    )
}

macro_rules! bench_bob {
    ($algo:ident) => (
        #[bench]
        fn bob(b: &mut Bencher) {
            let rand = OqsRand::new(OqsRandAlg::default()).unwrap();
            let kex = OqsKex::new(&rand, OqsKexAlg::$algo).unwrap();
            let kex_alice = kex.alice_0().unwrap();
            b.iter(|| {
                kex.bob(kex_alice.get_alice_msg()).unwrap()
            });
        }
    )
}

macro_rules! bench_full_kex {
    ($algo:ident) => (
        #[bench]
        fn full_kex(b: &mut Bencher) {
            let rand = OqsRand::new(OqsRandAlg::default()).unwrap();
            b.iter(|| {
                let kex_alice = OqsKex::new(&rand, OqsKexAlg::$algo).unwrap();
                let kex_alice_0 = kex_alice.alice_0().unwrap();

                let (bob_msg, shared_key1) = OqsKex::new(&rand, OqsKexAlg::$algo)
                    .unwrap()
                    .bob(kex_alice_0.get_alice_msg())
                    .unwrap();

                let shared_key2 = kex_alice_0.alice_1(&bob_msg).unwrap();
                (shared_key1, shared_key2)
            })
        }
    )
}

mod kex_benches {
    use super::*;
    bench_kex!(RlweNewhope);
    bench_kex!(CodeMcbits);
    bench_kex!(SidhCln16);
}
