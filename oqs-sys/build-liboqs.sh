#! /usr/bin/env bash

set -e

if [ -e liboqs/liboqs.a ]; then
    echo "Found existing liboqs/liboqs.a, not installing"
    exit 0
fi

cd liboqs

autoreconf -i

# Building with -fPIC is needed for linking with RUST

EXTRA_ARGS=()

if [ -n "$OQS_WITH_SODIUM" ]; then
    EXTRA_ARGS+=" --enable-kex-code-mcbits"
fi

if [ -n "$OQS_WITH_GMP" ]; then \
    EXTRA_ARGS+=" --enable-sidhiqc"
fi


./configure AM_CPPFLAGS="-fPIC" \
    --enable-aes-ni \
    --enable-kex-lwe-frodo \
    --enable-kex-mlwe-kyber \
    --enable-kex-ntru \
    --enable-kex-rlwe-msrln16 \
    --enable-kex-rlwe-newhope \
    --enable-kex-sidh-cln16 \
    $EXTRA_ARGS

make clean
make
