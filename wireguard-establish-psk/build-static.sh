#!/usr/bin/env bash

set -e

# Install needed dependencies
sudo apt-get -qq update && sudo apt-get install -y \
    autoconf \
    automake \
    libtool \
    make \
    musl-dev \
    musl-tools \
    libclang-dev

# Build liboqs
cd ../oqs-sys
./build-liboqs.sh

# Set library path for liboqs
export OQS_DIR=$PWD/liboqs

cd ../wireguard-establish-psk

# Add rustup target for musl
rustup target add x86_64-unknown-linux-musl

# Build everything
cargo build --release --target=x86_64-unknown-linux-musl
