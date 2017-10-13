# oqs-sys

FFI bindings to [liboqs] - Open Quantum Safe. [liboqs] is a C library for quantum-resistant
cryptographic algorithms.

This library is just [bindgen] generated bindings to [liboqs]. See the [oqs] crate for a safe
abstraction.

This library supports `no_std` and can thus be used without the Rust standard library.

## Building oqs-sys

To make the buildscript for `oqs-sys` find [liboqs], both the required headers and the compiled
library (`liboqs.a`), you must set the environment variable `OQS_DIR` to the **absolute**
path to your [liboqs] directory.

```bash
export OQS_DIR=/absolute/path/to/liboqs
cargo build
```

## Building liboqs

See `build-liboqs.sh` in the repository root for instructions on building [liboqs] with all
crypto algorithms enabled. See the [liboqs] README for more detailed instructions.


[liboqs]: https://github.com/open-quantum-safe/liboqs
[bindgen]: https://crates.io/crates/bindgen
[oqs]: https://github.com/mullvad/oqs-rs

License: MIT/Apache-2.0
