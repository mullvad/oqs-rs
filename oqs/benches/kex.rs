#![feature(test)]

extern crate oqs;
extern crate test;

use test::Bencher;
use oqs::kex::{OqsKex, OqsKexAlg};
use oqs::rand::{OqsRand, OqsRandAlg};

macro_rules! bench_alice0 {
    ($name:ident, $algo:ident) => (
        #[bench]
        fn $name(b: &mut Bencher) {
            let rand = OqsRand::new(OqsRandAlg::default()).unwrap();
            let kex = OqsKex::new(&rand, OqsKexAlg::$algo).unwrap();
            b.iter(|| {
                kex.alice_0().unwrap()
            });
        }
    )
}

bench_alice0!(kex_alice_0_rlwe_newhope, RlweNewhope);
bench_alice0!(kex_alice_0_code_mcbits, CodeMcbits);
bench_alice0!(kex_alice_0_sidh_cln16, SidhCln16);

macro_rules! bench_full_kex {
    ($name:ident, $algo:ident) => (
        #[bench]
        fn $name(b: &mut Bencher) {
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

bench_full_kex!(full_kex_rlwe_newhope, RlweNewhope);
bench_full_kex!(full_kex_code_mcbits, CodeMcbits);
bench_full_kex!(full_kex_sidh_cln16, SidhCln16);
