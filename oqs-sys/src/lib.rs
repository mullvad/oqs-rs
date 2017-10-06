// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! FFI bindings to [liboqs] - Open Quantum Safe. [liboqs] is a C library for quantum-resistant
//! cryptographic algorithms.
//!
//! This library is just [bindgen] generated bindings to [liboqs]. See the [oqs] crate for a safe
//! abstraction.
//!
//! This library supports `no_std` and can thus be used without the Rust standard library.
//!
//! [liboqs]: https://github.com/open-quantum-safe/liboqs
//! [bindgen]: https://crates.io/crates/bindgen
//! [oqs]: https://github.com/mullvad/oqs-rs

#![no_std]

extern crate libc;

/// The key exchange part of liboqs.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod kex {
    pub static SUCCESS: ::libc::c_int = 1;
    pub static FAILURE: ::libc::c_int = 0;

    include!(concat!(env!("OUT_DIR"), "/kex.rs"));
}

/// The PRNG part of liboqs.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod rand {
    include!(concat!(env!("OUT_DIR"), "/rand.rs"));
}
