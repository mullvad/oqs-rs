#!/usr/bin/env bash

set -e

cd liboqs

# Enabled algorithms for liboqs
enabled_algorithms=(
    --enable-aes-ni
    --enable-kex-lwe-frodo
    --enable-kex-mlwe-kyber
    --enable-kex-ntru
    --enable-kex-rlwe-msrln16
    --enable-kex-rlwe-newhope
    --enable-kex-sidh-cln16
)

if [[ $OQS_WITH_SODIUM -eq 1 ]]; then
    echo "Building with libsodium"
    enabled_algorithms+=(
        --enable-kex-code-mcbits
    )
fi

if [[ $OQS_WITH_GMP -eq 1 ]]; then
    echo "Building with libgmp"
    enabled_algorithms+=(
        --enable-sidhiqc
    )
fi

autoreconf -i

# Building with -fPIC is needed for linking with Rust

./configure AM_CPPFLAGS="-fPIC" "${enabled_algorithms[@]}"

make clean
make
