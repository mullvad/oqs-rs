// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![no_std]

extern crate libc;

/// The key exchange part of `liboqs`.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod kex {
    pub static SUCCESS: ::libc::c_int = 1;
    pub static FAILURE: ::libc::c_int = 0;

    include!(concat!(env!("OUT_DIR"), "/kex.rs"));
}
