extern crate core;
extern crate libc;
extern crate oqs_sys;

#[cfg_attr(feature = "serialize", macro_use)]
#[cfg(feature = "serialize")]
extern crate serde_derive;


pub mod kex;
mod buf;
