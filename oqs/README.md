# oqs

[liboqs], Open Quantum Safe, library bindings and safe abstraction.

See the [oqs-sys] crate for low level FFI bindings to [liboqs]. This crate abstracts over those
bindings, to create a safe interface to the C library.

This crate mostly focuses on exposing the PRNG and key exchange parts of [liboqs]. See the
respective modules for more detailed documentation.

[liboqs]: https://github.com/open-quantum-safe/liboqs
[oqs-sys]: https://crates.io/crates/oqs-sys

License: MIT/Apache-2.0
