#!/usr/bin/env bash

set -e

# Install needed dependencies
sudo apt-get -qq update && sudo apt-get install -y \
    autoconf \
    automake \
    libtool \
    build-essential \
    libclang-dev \
    pkg-config \
    musl-dev \
    musl-tools \
    linux-headers-amd64 \
    xutils-dev

# Build liboqs
cd oqs-sys
./build-liboqs.sh
cd ..

# Set library path for liboqs
export OQS_DIR=$PWD/oqs-sys/liboqs

# Create build directories and setup paths
mkdir -p build
mkdir -p build/musl

export MUSL_PREFIX=$PWD/build/musl
export PATH=$MUSL_PREFIX/bin:$PATH

cd build

# Symlink some headers to make openssl build
ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm && \
    ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic && \
    ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux

# Download and compile zlib
ZLIB_VERSION="1.2.11"
ZLIB_HASH="c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1"

wget https://zlib.net/zlib-1.2.11.tar.gz && \
  echo "${ZLIB_HASH} zlib-${ZLIB_VERSION}.tar.gz" | sha256sum -c - && \
  tar xfz zlib-${ZLIB_VERSION}.tar.gz && \
  rm zlib-${ZLIB_VERSION}.tar.gz

cd zlib-${ZLIB_VERSION} && \
    CC="musl-gcc -fPIE -pie" \
    LDFLAGS="-L/musl/lib/" \
    CFLAGS="-I/musl/include" \
    ./configure --prefix=$MUSL_PREFIX && \
    make -j$(nproc) && \
    make install

cd ..

# Download and compile openssl
OPENSSL_VERSION="1.0.2m"
OPENSSL_HASH="8c6ff15ec6b319b50788f42c7abc2890c08ba5a1cdcd3810eb9092deada37b0f"

wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz && \
  echo "${OPENSSL_HASH} openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c - && \
  tar xfz openssl-${OPENSSL_VERSION}.tar.gz && \
  rm openssl-${OPENSSL_VERSION}.tar.gz

cd openssl-${OPENSSL_VERSION} && \
    CC="musl-gcc -fPIE -pie" \
    LDFLAGS="-L/musl/lib/" \
    CFLAGS="-I/musl/include" \
    ./Configure no-shared no-async --prefix=$MUSL_PREFIX --openssldir=$MUSL_PREFIX/ssl linux-x86_64 && \
    make depend && \
    make -j$(nproc) && \
    make install

cd ..

# Export environment variables needed for building against musl libraries
export PKG_CONFIG_ALLOW_CROSS=true
export PKG_CONFIG_ALL_STATIC=true
export PKG_CONFIG_PATH=$MUSL_PREFIX/lib/pkgconfig
export OPENSSL_STATIC=true
export OPENSSL_DIR=$MUSL_PREFIX
export LIBZ_SYS_STATIC=1

# Add rustup target for musl
rustup target add x86_64-unknown-linux-musl

# Build everything
cargo build --release --target=x86_64-unknown-linux-musl
