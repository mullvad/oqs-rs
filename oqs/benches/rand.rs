#![feature(test)]

extern crate oqs;
extern crate test;

use test::Bencher;
use oqs::rand::{OqsRand, OqsRandAlg};

/// Macro generating all the benchmark functions for a given PRNG algorithm
macro_rules! bench_rand {
    ($alg:ident) => (
        #[allow(non_snake_case)]
        mod $alg {
            use super::*;
            #[bench]
            fn new(b: &mut Bencher) {
                b.iter(|| OqsRand::new(OqsRandAlg::$alg).unwrap());
            }

            bench_rand_i!($alg, rand_8);
            bench_rand_i!($alg, rand_32);
            bench_rand_i!($alg, rand_64);

            #[bench]
            fn rand_n_1024(b: &mut Bencher) {
                let mut buf = [0; 1024];
                let rand = OqsRand::new(OqsRandAlg::$alg).unwrap();
                b.iter(|| {
                    rand.rand_n(&mut buf)
                });
            }
        }
    )
}

/// Helper macro generating rand_X benchmarks
macro_rules! bench_rand_i {
    ($alg:ident, $func:ident) => (
        #[bench]
        fn $func(b: &mut Bencher) {
            let rand = OqsRand::new(OqsRandAlg::$alg).unwrap();
            b.iter(|| {
                rand.$func()
            });
        }
    )
}

mod rand_benches {
    use super::*;
    bench_rand!(Default);
    bench_rand!(UrandomChacha20);
    bench_rand!(UrandomAesctr);
}
