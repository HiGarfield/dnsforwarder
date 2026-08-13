#!/bin/sh
# Build and run the IP/CIDR parser mutation fuzzer under sanitizers.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_ipchunk_fuzz

Sources="
$Root/test/ipchunk_fuzz/main.c
$Root/ipchunk.c
$Root/stablebuffer.c
$Root/bst.c
$Root/stringchunk.c
$Root/stringlist.c
$Root/array.c
$Root/simpleht.c
$Root/utils.c
$Root/addresslist.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm
"$Out" "$@"
