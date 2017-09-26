use libc;
use core::{mem, ptr};
use std::fmt;

use oqs_sys::kex as ffi;
use buf::Buf;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
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
    pub fn new(algorithm: OqsRandAlg) -> Result<Self, Error> {
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
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
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


pub struct OqsKex {
    _rand: OqsRand,
    kex_alg: OqsKexAlg,
    oqs_kex: *mut ffi::OQS_KEX,
}

impl OqsKex {
    pub fn new(rand_alg: OqsRandAlg, kex_alg: OqsKexAlg) -> Result<Self, Error> {
        let rand = OqsRand::new(rand_alg)?;
        let ffi_kex_alg = ffi::OQS_KEX_alg_name::from(kex_alg);
        let oqs_kex =
            unsafe { ffi::OQS_KEX_new(rand.oqs_rand, ffi_kex_alg, ptr::null(), 0, ptr::null()) };
        if oqs_kex != ptr::null_mut() {
            Ok(OqsKex {
                _rand: rand,
                kex_alg,
                oqs_kex,
            })
        } else {
            Err(Error)
        }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.kex_alg
    }

    pub fn alice_0(self) -> Result<OqsKexAlice, Error> {
        let mut alice_priv = ptr::null_mut();
        let mut alice_msg = ptr::null_mut();
        let mut alice_msg_len = 0;
        let result = unsafe {
            ffi::OQS_KEX_alice_0(
                self.oqs_kex,
                &mut alice_priv,
                &mut alice_msg,
                &mut alice_msg_len,
            )
        };
        if result == ffi::SUCCESS {
            let kex_alg = self.kex_alg;
            Ok(OqsKexAlice {
                parent: self,
                alice_priv,
                alice_msg: AliceMsg::new(kex_alg, Buf::from_c(alice_msg, alice_msg_len)),
            })
        } else {
            Err(Error)
        }
    }

    pub fn bob(self, alice_msg: &AliceMsg) -> Result<(BobMsg, SharedKey), Error> {
        let mut bob_msg = ptr::null_mut();
        let mut bob_msg_len = 0;
        let mut key = ptr::null_mut();
        let mut key_len = 0;
        let result = unsafe {
            ffi::OQS_KEX_bob(
                self.oqs_kex,
                alice_msg.data.ptr(),
                alice_msg.data.len(),
                &mut bob_msg,
                &mut bob_msg_len,
                &mut key,
                &mut key_len,
            )
        };
        if result == ffi::SUCCESS {
            Ok((
                BobMsg::new(self.kex_alg, Buf::from_c(bob_msg, bob_msg_len)),
                SharedKey::new(self.kex_alg, Buf::from_c(key, key_len)),
            ))
        } else {
            Err(Error)
        }
    }
}

impl Drop for OqsKex {
    fn drop(&mut self) {
        unsafe { ffi::OQS_KEX_free(self.oqs_kex) };
    }
}

pub struct OqsKexAlice {
    parent: OqsKex,
    alice_priv: *mut libc::c_void,
    alice_msg: AliceMsg,
}

impl OqsKexAlice {
    pub fn alice_1(self, bob_msg: &BobMsg) -> Result<SharedKey, Error> {
        let mut key = ptr::null_mut();
        let mut key_len = 0;
        let result = unsafe {
            ffi::OQS_KEX_alice_1(
                self.parent.oqs_kex,
                self.alice_priv,
                bob_msg.data.ptr(),
                bob_msg.data.len(),
                &mut key,
                &mut key_len,
            )
        };
        if result == ffi::SUCCESS {
            Ok(SharedKey::new(
                self.parent.kex_alg,
                Buf::from_c(key, key_len),
            ))
        } else {
            Err(Error)
        }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.parent.kex_alg
    }

    pub fn get_alice_msg(&self) -> &AliceMsg {
        &self.alice_msg
    }
}

impl Drop for OqsKexAlice {
    fn drop(&mut self) {
        unsafe {
            ffi::OQS_KEX_alice_priv_free(self.parent.oqs_kex, self.alice_priv);
        };
    }
}


#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct AliceMsg {
    kex_alg: OqsKexAlg,
    data: Buf,
}

impl AliceMsg {
    fn new(kex_alg: OqsKexAlg, data: Buf) -> Self {
        AliceMsg { kex_alg, data }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.kex_alg
    }

    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct BobMsg {
    kex_alg: OqsKexAlg,
    data: Buf,
}

impl BobMsg {
    fn new(kex_alg: OqsKexAlg, data: Buf) -> Self {
        BobMsg { kex_alg, data }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.kex_alg
    }

    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct SharedKey {
    kex_alg: OqsKexAlg,
    data: Buf,
}

impl SharedKey {
    fn new(kex_alg: OqsKexAlg, data: Buf) -> Self {
        SharedKey { kex_alg, data }
    }

    pub fn algorithm(&self) -> OqsKexAlg {
        self.kex_alg
    }

    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}



#[derive(Debug, Copy, Clone, Hash)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
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
                let kex_alice = OqsKex::new(TEST_RAND_ALG, OqsKexAlg::$algo)
                    .unwrap()
                    .alice_0()
                    .unwrap();

                let (bob_msg, shared_key1) = OqsKex::new(TEST_RAND_ALG, OqsKexAlg::$algo)
                    .unwrap()
                    .bob(kex_alice.get_alice_msg())
                    .unwrap();

                let shared_key2 = kex_alice.alice_1(&bob_msg).unwrap();

                let key1 = shared_key1.data();
                let key2 = shared_key2.data();

                assert!(!key1.is_empty());
                assert_eq!(key1, key2);
            }
        )
    }

    test_full_kex!(full_kex_rlwe_newhope, RlweNewhope);
    test_full_kex!(full_kex_code_mcbits, CodeMcbits);
    test_full_kex!(full_kex_sidh_cln16, SidhCln16);

}
