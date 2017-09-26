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
    pub fn from_c(msg: *mut u8, len: usize) -> Self {
        Buf::CAlloc(Some(
            unsafe { Vec::from_raw_parts(msg, len, len) }.into_boxed_slice(),
        ))
    }

    pub fn data(&self) -> &[u8] {
        match *self {
            Buf::CAlloc(ref buf_option) => buf_option.as_ref().unwrap(),
            Buf::RustAlloc(ref buf) => buf,
        }
    }

    pub fn ptr(&self) -> *const u8 {
        self.data().as_ptr() as *const u8
    }

    pub fn len(&self) -> usize {
        self.data().len()
    }
}

impl Clone for Buf {
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
