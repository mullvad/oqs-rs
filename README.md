# oqs - Open Quantum Safe bindings for Rust

This repository contains the following crates:
* `oqs-sys` - Low level FFI bindings for [`liboqs`](https://github.com/open-quantum-safe/liboqs).
* `oqs` - Higher level Rust representations.
* `oqs-kex-rpc` - JSON-RPC 2.0 server and client for key exchange via `oqs`.


# Building liboqs

Here are instructions for building `liboqs` with `-fPIC` (Needed for linking from Rust) and with all crypto algorithms enabled.

If you build `liboqs` without some crypto algorithms and then try to use those from rust, you will
get a panic.

```bash
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs
autoreconf -i
./configure AM_CPPFLAGS="-fPIC" \
    --enable-kex-code-mcbits \
    --enable-aes-ni \
    --enable-kex-lwe-frodo \
    --enable-kex-mlwe-kyber \
    --enable-kex-ntru \
    --enable-kex-rlwe-msrln16 \
    --enable-kex-rlwe-newhope \
    --enable-kex-sidh-cln16
make clean
make
```

# Building oqs-sys

To make the buildscript for `oqs-sys` find `liboqs`, both the required headers and the compiled library (`liboqs.a`), you must set the environment variable `OQS_DIR` to the **absolute** path to your `liboqs` directory.

```bash
export OQS_DIR=/absolute/path/to/liboqs
cargo build
```
