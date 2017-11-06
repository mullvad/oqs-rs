# oqs - Open Quantum Safe bindings for Rust

This repository contains the following crates:
* [`oqs-sys`] - Low level FFI bindings for [`liboqs`].
* [`oqs`] - Higher level Rust representations.
* [`oqs-kex-rpc`] - JSON-RPC 2.0 server and client for key exchange via [`oqs`].
* [`wireguard-psk-exchange`] - Server and client programs for negotiating a wireguard compatible
  pre-shared key over a wireguard tunnel. This key can later be used to upgrade the tunnel to be
  post-quantum safe.

# Building

See [oqs-sys README] for instructions on how to get the [`liboqs`] library and compile it. The rest
of the crates should be fairly straight forward, check out their respective documentation.



[`liboqs`]: https://github.com/open-quantum-safe/liboqs
[`oqs-sys`]: oqs-sys/
[oqs-sys README]: oqs-sys/README.md
[`oqs`]: oqs/
[`oqs-kex-rpc`]: oqs-kex-rpc/
[`wireguard-psk-exchange`]: wireguard-psk-exchange/

## Building statically linked binaries

In order to build statically linked binaries, a musl toolchain and openssl built for musl is needed.
A script is provided in the root folder of this repo to help with this: [`build-static.sh`].
Run it in order to install needed dependencies and producing statically linked binaries.
