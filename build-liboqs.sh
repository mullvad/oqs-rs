#! /usr/bin/env bash

set -e

DIR=$1
if [[ $# -ne 1 || ! -d $DIR ]]; then
    echo "Give directory to build in as first argument"
    exit 1
fi
echo "Downloading and building liboqs in $DIR"

if [ -e $DIR/liboqs/liboqs.a ]; then
    echo "Found existing $DIR/liboqs/liboqs.a, not installing"
    exit 0
fi

cd $DIR
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
