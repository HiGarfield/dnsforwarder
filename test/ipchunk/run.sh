#!/bin/sh
# Build and run the ipchunk CIDR-matching regression tests.
#
# Usage:
#   sh test/ipchunk/run.sh          build and run
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_ipchunk

Sources="
$Root/test/ipchunk/main.c
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

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread -lm
"$Out"
