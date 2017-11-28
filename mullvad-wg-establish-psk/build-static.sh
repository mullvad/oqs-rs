#!/usr/bin/env bash

set -e

# Build liboqs
cd ../oqs-sys
./build-liboqs.sh

# Set library path for liboqs
export OQS_DIR=$PWD/liboqs

cd ../mullvad-wg-establish-psk

# Build everything
cargo +stable build --release --target=x86_64-unknown-linux-musl
