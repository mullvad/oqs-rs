# oqs

[liboqs], Open Quantum Safe, library bindings and safe abstraction.

See the [oqs-sys] crate for low level FFI bindings to [liboqs]. This crate abstracts over those
bindings, to create a safe interface to the C library.

This crate mostly focuses on exposing the PRNG and key exchange parts of [liboqs]. See the
respective modules for more detailed documentation.

See the [oqs-kex-rpc] crate for a client and server implementation that can perform full key
exchanges over JSON-RPC 2.0 over HTTP.

## Example

Here is a simple example how one can perform a key exchange operation. This code performs both
the Alice and Bob roles. In a real use case Alice and Bob would be two different entities who
want to exchange a shared key over an untrusted channel.

See `OqsKex` documentation for more details.

```rust
extern crate oqs;

use oqs::rand::{OqsRand, OqsRandAlg};
use oqs::kex::{OqsKex, OqsKexAlg, SharedKey};

fn example_kex(algorithm: OqsKexAlg) -> Result<SharedKey, KexError> {
    // Create the PRNG that oqs will use as entropy source
    let rand = OqsRand::new(OqsRandAlg::default())?;

    // Create the key exchange object that Alice will use
    let kex_alice = OqsKex::new(&rand, algorithm)?;
    // Run the first cryptographic operation, alice_0, to compute Alice's public message
    let kex_alice_0 = kex_alice.alice_0()?;

    // Create the key exchange object that Bob will use
    let kex_bob = OqsKex::new(&rand, algorithm)?;
    // When bob receives Alice's public message he can compute the
    // shared key and his public message
    let (bob_msg, key_bob) = kex_bob.bob(kex_alice_0.get_alice_msg())?;

    // With Bob's public message Alice can now compute the shared key.
    let key_alice = kex_alice_0.alice_1(&bob_msg)?;

    // Both parties should of course come up with the same shared key
    if key_alice != key_bob {
        Err(KexError)
    } else {
        Ok(key_alice)
    }
}

```

[liboqs]: https://github.com/open-quantum-safe/liboqs
[oqs-sys]: https://crates.io/crates/oqs-sys
[oqs-kex-rpc]: https://crates.io/crates/oqs-kex-rpc

License: MIT/Apache-2.0
