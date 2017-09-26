#![feature(test)]

extern crate oqs;
extern crate test;

use test::Bencher;
use oqs::kex::{OqsKex, OqsKexAlg, OqsRand, OqsRandAlg};

#[bench]
fn create_rand_default(b: &mut Bencher) {
    b.iter(|| OqsRand::new(OqsRandAlg::Default));
}

#[bench]
fn create_rand_urandom_chacha20(b: &mut Bencher) {
    b.iter(|| OqsRand::new(OqsRandAlg::UrandomChacha20));
}

#[bench]
fn create_rand_urandom_aesctr(b: &mut Bencher) {
    b.iter(|| OqsRand::new(OqsRandAlg::UrandomAesctr));
}

macro_rules! bench_alice0 {
    ($name:ident, $algo:ident) => (
        #[bench]
        fn $name(b: &mut Bencher) {
            b.iter(|| {
                let kex = OqsKex::new(OqsRandAlg::default(), OqsKexAlg::$algo).unwrap();
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
            b.iter(|| {
                let kex_alice = OqsKex::new(OqsRandAlg::default(), OqsKexAlg::$algo)
                    .unwrap()
                    .alice_0()
                    .unwrap();

                let (bob_msg, shared_key1) = OqsKex::new(OqsRandAlg::default(), OqsKexAlg::$algo)
                    .unwrap()
                    .bob(kex_alice.get_alice_msg())
                    .unwrap();

                let shared_key2 = kex_alice.alice_1(&bob_msg).unwrap();
                (shared_key1, shared_key2)
            })
        }
    )
}

bench_full_kex!(full_kex_rlwe_newhope, RlweNewhope);
bench_full_kex!(full_kex_code_mcbits, CodeMcbits);
bench_full_kex!(full_kex_sidh_cln16, SidhCln16);
