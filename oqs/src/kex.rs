// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libc;
use core::{mem, ptr};
use std::fmt;

use oqs_sys::kex as ffi;
use buf::Buf;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OqsRandAlg {
    Default = ffi::OQS_RAND_alg_name::OQS_RAND_alg_default as u32,
    UrandomChacha20 = ffi::OQS_RAND_alg_name::OQS_RAND_alg_urandom_chacha20 as u32,
    UrandomAesctr = ffi::OQS_RAND_alg_name::OQS_RAND_alg_urandom_aesctr as u32,
}

impl From<OqsRandAlg> for ffi::OQS_RAND_alg_name {
    fn from(alg: OqsRandAlg) -> Self {
        unsafe { mem::transmute_copy::<OqsRandAlg, ffi::OQS_RAND_alg_name>(&alg) }
    }
}

impl Default for OqsRandAlg {
    fn default() -> Self {
        OqsRandAlg::Default
    }
}

pub struct OqsRand {
    algorithm: OqsRandAlg,
    oqs_rand: *mut ffi::OQS_RAND,
}

impl OqsRand {
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

    pub fn algorithm(&self) -> OqsRandAlg {
        self.algorithm
    }
}

impl Drop for OqsRand {
    fn drop(&mut self) {
        unsafe { ffi::OQS_RAND_free(self.oqs_rand) };
    }
}


#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OqsKexAlg {
    Default = ffi::OQS_KEX_alg_name::OQS_KEX_alg_default as u32,
    RlweBcns15 = ffi::OQS_KEX_alg_name::OQS_KEX_alg_rlwe_bcns15 as u32,
    RlweNewhope = ffi::OQS_KEX_alg_name::OQS_KEX_alg_rlwe_newhope as u32,
    RlweMsrln16 = ffi::OQS_KEX_alg_name::OQS_KEX_alg_rlwe_msrln16 as u32,
    LweFrodo = ffi::OQS_KEX_alg_name::OQS_KEX_alg_lwe_frodo as u32,
    SidhCln16 = ffi::OQS_KEX_alg_name::OQS_KEX_alg_sidh_cln16 as u32,
    SidhCln16Compressed = ffi::OQS_KEX_alg_name::OQS_KEX_alg_sidh_cln16_compressed as u32,
    CodeMcbits = ffi::OQS_KEX_alg_name::OQS_KEX_alg_code_mcbits as u32,
    Ntru = ffi::OQS_KEX_alg_name::OQS_KEX_alg_ntru as u32,
    SidhIqcRef = ffi::OQS_KEX_alg_name::OQS_KEX_alg_sidh_iqc_ref as u32,
    MlweKyber = ffi::OQS_KEX_alg_name::OQS_KEX_alg_mlwe_kyber as u32,
}

impl Default for OqsKexAlg {
    fn default() -> Self {
        OqsKexAlg::Default
    }
}

impl From<OqsKexAlg> for ffi::OQS_KEX_alg_name {
    fn from(alg: OqsKexAlg) -> Self {
        unsafe { mem::transmute_copy::<OqsKexAlg, ffi::OQS_KEX_alg_name>(&alg) }
    }
}


pub struct OqsKex<'r> {
    _rand: &'r OqsRand,
    algorithm: OqsKexAlg,
    oqs_kex: *mut ffi::OQS_KEX,
}

impl<'r> OqsKex<'r> {
    pub fn new(rand: &'r OqsRand, algorithm: OqsKexAlg) -> Result<Self> {
        let ffi_kex_alg = ffi::OQS_KEX_alg_name::from(algorithm);
        let oqs_kex =
            unsafe { ffi::OQS_KEX_new(rand.oqs_rand, ffi_kex_alg, ptr::null(), 0, ptr::null()) };
        if oqs_kex != ptr::null_mut() {
            Ok(OqsKex {
                _rand: rand,
                algorithm,
                oqs_kex,
            })
        } else {
            Err(Error)
        }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.algorithm
    }

    pub fn alice_0<'a>(&'a self) -> Result<OqsKexAlice<'a, 'r>> {
        let mut alice_priv = ptr::null_mut();
        let mut alice_msg_ptr = ptr::null_mut();
        let mut alice_msg_len = 0;
        let result = unsafe {
            ffi::OQS_KEX_alice_0(
                self.oqs_kex,
                &mut alice_priv,
                &mut alice_msg_ptr,
                &mut alice_msg_len,
            )
        };
        if result == ffi::SUCCESS {
            let alice_msg_buf = Buf::from_c(alice_msg_ptr, alice_msg_len);
            let alice_msg = AliceMsg::new(self.algorithm, alice_msg_buf);
            Ok(OqsKexAlice {
                parent: self,
                alice_priv,
                alice_msg,
            })
        } else {
            Err(Error)
        }
    }

    pub fn bob(&self, alice_msg: &AliceMsg) -> Result<(BobMsg, SharedKey)> {
        let mut bob_msg = ptr::null_mut();
        let mut bob_msg_len = 0;
        let mut key = ptr::null_mut();
        let mut key_len = 0;
        let result = unsafe {
            ffi::OQS_KEX_bob(
                self.oqs_kex,
                alice_msg.data().as_ptr(),
                alice_msg.data().len(),
                &mut bob_msg,
                &mut bob_msg_len,
                &mut key,
                &mut key_len,
            )
        };
        if result == ffi::SUCCESS {
            Ok((
                BobMsg::new(self.algorithm, Buf::from_c(bob_msg, bob_msg_len)),
                SharedKey::new(self.algorithm, Buf::from_c(key, key_len)),
            ))
        } else {
            Err(Error)
        }
    }
}

impl<'r> Drop for OqsKex<'r> {
    fn drop(&mut self) {
        unsafe { ffi::OQS_KEX_free(self.oqs_kex) };
    }
}

pub struct OqsKexAlice<'a, 'r>
where
    'r: 'a,
{
    parent: &'a OqsKex<'r>,
    alice_priv: *mut libc::c_void,
    alice_msg: AliceMsg,
}

impl<'a, 'r> OqsKexAlice<'a, 'r> {
    pub fn alice_1(self, bob_msg: &BobMsg) -> Result<SharedKey> {
        let mut key = ptr::null_mut();
        let mut key_len = 0;
        let result = unsafe {
            ffi::OQS_KEX_alice_1(
                self.parent.oqs_kex,
                self.alice_priv,
                bob_msg.data().as_ptr(),
                bob_msg.data().len(),
                &mut key,
                &mut key_len,
            )
        };
        if result == ffi::SUCCESS {
            Ok(SharedKey::new(
                self.parent.algorithm,
                Buf::from_c(key, key_len),
            ))
        } else {
            Err(Error)
        }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.parent.algorithm
    }

    pub fn get_alice_msg(&self) -> &AliceMsg {
        &self.alice_msg
    }
}

impl<'a, 'r> Drop for OqsKexAlice<'a, 'r> {
    fn drop(&mut self) {
        unsafe {
            ffi::OQS_KEX_alice_priv_free(self.parent.oqs_kex, self.alice_priv);
        };
    }
}


#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AliceMsg {
    algorithm: OqsKexAlg,
    data: Buf,
}

impl AliceMsg {
    fn new(algorithm: OqsKexAlg, data: Buf) -> Self {
        AliceMsg { algorithm, data }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.algorithm
    }

    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

impl AsRef<[u8]> for AliceMsg {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BobMsg {
    algorithm: OqsKexAlg,
    data: Buf,
}

impl BobMsg {
    fn new(algorithm: OqsKexAlg, data: Buf) -> Self {
        BobMsg { algorithm, data }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.algorithm
    }

    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

impl AsRef<[u8]> for BobMsg {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SharedKey {
    algorithm: OqsKexAlg,
    data: Buf,
}

impl SharedKey {
    fn new(algorithm: OqsKexAlg, data: Buf) -> Self {
        SharedKey { algorithm, data }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.algorithm
    }

    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

impl AsRef<[u8]> for SharedKey {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
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
        "Unspecified error in liboqs"
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    static TEST_RAND_ALG: OqsRandAlg = OqsRandAlg::UrandomChacha20;

    macro_rules! test_full_kex {
        ($name:ident, $algo:ident) => (
            #[test]
            fn $name() {
                let rand_alice = OqsRand::new(TEST_RAND_ALG).unwrap();
                let kex_alice = OqsKex::new(&rand_alice, OqsKexAlg::$algo).unwrap();
                let kex_alice_0 = kex_alice.alice_0().unwrap();

                let (bob_msg, key1) = helper_bob(kex_alice_0.get_alice_msg());

                let key2 = kex_alice_0.alice_1(&bob_msg).unwrap();

                assert!(!key1.data().is_empty());
                assert_eq!(key1, key2);
            }
        )
    }

    test_full_kex!(full_kex_default, Default);
    test_full_kex!(full_kex_rlwe_newhope, RlweNewhope);
    test_full_kex!(full_kex_code_mcbits, CodeMcbits);
    test_full_kex!(full_kex_sidh_cln16, SidhCln16);

    fn helper_bob(alice_msg: &AliceMsg) -> (BobMsg, SharedKey) {
        let rand = OqsRand::new(TEST_RAND_ALG).unwrap();
        let (bob_msg, shared_key) = OqsKex::new(&rand, alice_msg.algorithm())
            .unwrap()
            .bob(alice_msg)
            .unwrap();
        (bob_msg, shared_key)
    }
}
