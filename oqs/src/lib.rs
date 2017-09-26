extern crate core;
extern crate libc;
extern crate oqs_sys;

#[cfg_attr(feature = "serde", macro_use)]
#[cfg(feature = "serde")]
extern crate serde;


pub mod kex;
mod buf;
