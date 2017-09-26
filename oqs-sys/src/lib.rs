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
