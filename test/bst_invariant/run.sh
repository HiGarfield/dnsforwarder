#!/bin/sh
# Build and run the bst structural invariant regression tests.
#
# Usage:
#   sh test/bst_invariant/run.sh
#   VALGRIND=1 sh test/bst_invariant/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/bst_invariant/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_bst_invariant

Sources="
$Root/test/bst_invariant/main.c
$Root/bst.c
$Root/stablebuffer.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
