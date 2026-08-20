#!/bin/sh
# Build and run the ipchunk IpAddr_Parse invariant regression tests.
#
# Usage:
#   sh test/ipchunk_parse_invariant/run.sh
#   VALGRIND=1 sh test/ipchunk_parse_invariant/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_ipchunk_parse_invariant

Sources="
$Root/test/ipchunk_parse_invariant/main.c
$Root/ipchunk.c
$Root/bst.c
$Root/stablebuffer.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
