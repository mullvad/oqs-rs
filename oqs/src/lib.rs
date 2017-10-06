// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! [liboqs], Open Quantum Safe, library bindings and safe abstraction.
//!
//! See the [oqs-sys] crate for low level FFI bindings to [liboqs]. This crate abstracts over those
//! bindings, to create a safe interface to the C library.
//!
//! [liboqs]: https://github.com/open-quantum-safe/liboqs
//! [oqs-sys]: https://github.com/mullvad/oqs-rs

extern crate core;
extern crate libc;
extern crate oqs_sys;

#[cfg_attr(feature = "serde", macro_use)]
#[cfg(feature = "serde")]
extern crate serde;

/// The key exchange primitives.
pub mod kex;

mod buf;
