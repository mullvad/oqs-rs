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
//! # Building oqs-sys
//!
//! To make the buildscript for `oqs-sys` find [liboqs], both the required headers and the compiled
//! library (`liboqs.a`), you must set the environment variable `OQS_DIR` to the **absolute**
//! path to your [liboqs] directory.
//!
//! ```bash
//! export OQS_DIR=/absolute/path/to/liboqs
//! cargo build
//! ```
//!
//! # Building liboqs
//!
//! See [`build-liboqs.sh`] in the repository root for instructions on building [liboqs] with all
//! crypto algorithms enabled. See the [liboqs] README for more detailed instructions.
//!
//!
//! [liboqs]: https://github.com/open-quantum-safe/liboqs
//! [bindgen]: https://crates.io/crates/bindgen
//! [oqs]: https://crates.io/crates/oqs
//! [`build-liboqs.sh`]: https://github.com/mullvad/oqs-rs/blob/master/build-liboqs.sh

#![no_std]

extern crate libc;

/// The key exchange part of liboqs.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod kex {
    /// The `OQS_KEX_*` functions return this value on success.
    pub static SUCCESS: ::libc::c_int = 1;
    /// The `OQS_KEX_*` functions return this value on failure.
    pub static FAILURE: ::libc::c_int = 0;

    include!(concat!(env!("OUT_DIR"), "/kex.rs"));
}

/// The PRNG part of liboqs.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod rand {
    include!(concat!(env!("OUT_DIR"), "/rand.rs"));
}

/// Common shared functionality and constants.
pub mod common {
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}
