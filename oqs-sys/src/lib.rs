#![no_std]

extern crate libc;

/// The key exchange part of `liboqs`.
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod kex {
    include!(concat!(env!("OUT_DIR"), "/kex.rs"));
}
