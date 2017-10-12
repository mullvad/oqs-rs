// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::mem;
use libc;


/// Internal binary buffer for key data and kex messages. Can hold data allocated from C or Rust,
/// and will take care of freeing the memory accordingly when it goes out of scope.
///
/// # Warning!
///
/// The order of the enum fields are important! When deserializing it will match the first variant,
/// and that must be `RustAlloc` since a deserialized object will be backed by a buffer allocated
/// from Rust. Only the `from_c` constructor should create the `CAlloc` variant.
/// See https://serde.rs/enum-representations.html#untagged for details.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum Buf {
    RustAlloc(Box<[u8]>),
    CAlloc(Option<Box<[u8]>>),
}

impl Buf {
    /// Creates and returns a new `Buf` instance backed by the data at the given raw pointer.
    /// Not to be used except for wrapping data given out by `liboqs` from C.
    ///
    /// `Buf` instances created from this method will be freed with `libc::free`, to match how they
    /// were allocated in `liboqs`.
    pub fn from_c(msg: *mut u8, len: usize) -> Self {
        Buf::CAlloc(Some(
            unsafe { Vec::from_raw_parts(msg, len, len) }.into_boxed_slice(),
        ))
    }

    /// Returns the underlying data as a slice.
    pub fn data(&self) -> &[u8] {
        match *self {
            Buf::CAlloc(ref buf_option) => buf_option.as_ref().unwrap(),
            Buf::RustAlloc(ref buf) => buf,
        }
    }
}

impl AsRef<[u8]> for Buf {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl Clone for Buf {
    /// Returns a new `Buf` backed by a clone of the same data as the `Buf` being cloned.
    /// Any clone is not considered as allocated from C, and will be freed in the normal Rust way
    /// instead of by `libc::free`.
    fn clone(&self) -> Self {
        Buf::RustAlloc(self.data().to_vec().into_boxed_slice())
    }
}

impl PartialEq for Buf {
    fn eq(&self, other: &Self) -> bool {
        self.data() == other.data()
    }
}

impl Eq for Buf {}

impl Drop for Buf {
    fn drop(&mut self) {
        if let &mut Buf::CAlloc(ref mut buf_option) = self {
            unsafe {
                let mut buf = buf_option.take().unwrap();
                libc::free(buf.as_mut_ptr() as *mut libc::c_void);
                mem::forget(buf);
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn rust_eq_rust() {
        let buf1 = Buf::RustAlloc(vec![3, 8, 55].into_boxed_slice());
        let buf2 = Buf::RustAlloc(vec![3, 8, 55].into_boxed_slice());
        let buf3 = Buf::RustAlloc(vec![9, 99, 0, 0, 0, 1].into_boxed_slice());

        assert_eq!(buf1, buf2);
        assert_ne!(buf1, buf3);
        assert_eq!(buf1.as_ref(), &[3, 8, 55]);
    }

    #[test]
    fn rust_eq_c() {
        let rust_buf = Buf::RustAlloc(vec![0, 9, 2, 200].into_boxed_slice());
        let c_buf = Buf::CAlloc(Some(vec![0, 9, 2, 200].into_boxed_slice()));

        assert_eq!(rust_buf, c_buf);
        assert_eq!(c_buf.as_ref(), &[0, 9, 2, 200]);
        mem::forget(c_buf);
    }

    #[test]
    fn from_c() {
        let mut data = vec![5, 53, 19];
        let buf = Buf::from_c(data.as_mut_ptr(), 3);
        let expected = Buf::CAlloc(Some(vec![5, 53, 19].into_boxed_slice()));

        assert_eq!(buf, expected);
        mem::forget(buf);
        mem::forget(expected);
    }

    #[test]
    fn clone() {
        let mut data = vec![5, 53, 19];
        let c_buf = Buf::from_c(data.as_mut_ptr(), 3);
        let rust_buf = c_buf.clone();

        assert_eq!(c_buf, rust_buf);
        assert_ne!(c_buf.as_ref().as_ptr(), rust_buf.as_ref().as_ptr());
        assert_eq!(rust_buf, Buf::RustAlloc(vec![5, 53, 19].into_boxed_slice()));
        mem::forget(c_buf);
    }
}
