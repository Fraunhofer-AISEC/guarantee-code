#!/bin/bash
export CC=clang-11

make ra_tls_options.c

mkdir -p deps
make -j`nproc` deps

echo "Building wolfSSL SGX library ..."
make -f ratls-wolfssl.mk clean || exit 1
make -f ratls-wolfssl.mk || exit 1
make -f ratls-wolfssl.mk clean

