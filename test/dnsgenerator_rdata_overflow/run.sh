#!/bin/sh
# Build and run the DnsGenerator RDATA overflow regression tests.
#
# Usage:
#   sh test/dnsgenerator_rdata_overflow/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/dnsgenerator_rdata_overflow/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsgenerator_rdata_overflow

Sources="
$Root/test/dnsgenerator_rdata_overflow/main.c
$Root/dnsgenerator.c
$Root/dnsparser.c
$Root/dnsrelated.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
