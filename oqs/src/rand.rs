// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::ptr;
use std::fmt;

use oqs_sys::rand as ffi;

/// Enum representation of the supported PRNG algorithms. Used to select backing algorithm when
/// creating [`OqsRand`](struct.OqsRand.html) instances.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OqsRandAlg {
    Default,
    UrandomChacha20,
    UrandomAesctr,
}

impl From<OqsRandAlg> for ffi::OQS_RAND_alg_name {
    fn from(alg: OqsRandAlg) -> Self {
        use self::OqsRandAlg::*;
        match alg {
            Default => ffi::OQS_RAND_alg_name::OQS_RAND_alg_default,
            UrandomChacha20 => ffi::OQS_RAND_alg_name::OQS_RAND_alg_urandom_chacha20,
            UrandomAesctr => ffi::OQS_RAND_alg_name::OQS_RAND_alg_urandom_aesctr,
        }
    }
}

impl Default for OqsRandAlg {
    fn default() -> Self {
        OqsRandAlg::Default
    }
}

pub struct OqsRand {
    algorithm: OqsRandAlg,
    pub(crate) oqs_rand: *mut ffi::OQS_RAND,
}

impl OqsRand {
    /// Initializes and returns a new PRNG based on the given algorithm.
    pub fn new(algorithm: OqsRandAlg) -> Result<Self> {
        let oqs_rand = unsafe { ffi::OQS_RAND_new(ffi::OQS_RAND_alg_name::from(algorithm)) };
        if oqs_rand != ptr::null_mut() {
            Ok(OqsRand {
                algorithm,
                oqs_rand,
            })
        } else {
            Err(Error)
        }
    }

    /// Returns the algorithm backing this PRNG.
    pub fn algorithm(&self) -> OqsRandAlg {
        self.algorithm
    }

    /// Returns an 8-bit random unsigned integer
    pub fn rand_8(&self) -> u8 {
        unsafe { ffi::OQS_RAND_8(self.oqs_rand) }
    }

    /// Returns an 32-bit random unsigned integer
    pub fn rand_32(&self) -> u32 {
        unsafe { ffi::OQS_RAND_32(self.oqs_rand) }
    }

    /// Returns an 64-bit random unsigned integer
    pub fn rand_64(&self) -> u64 {
        unsafe { ffi::OQS_RAND_64(self.oqs_rand) }
    }

    /// Fills the given buffer with random data
    pub fn rand_n(&self, buffer: &mut [u8]) {
        unsafe { ffi::OQS_RAND_n(self.oqs_rand, buffer.as_mut_ptr(), buffer.len()) }
    }
}

impl Drop for OqsRand {
    fn drop(&mut self) {
        unsafe { ffi::OQS_RAND_free(self.oqs_rand) };
    }
}


pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, Hash)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        use std::error::Error;
        self.description().fmt(f)
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        "Error during PRNG initialization"
    }
}
