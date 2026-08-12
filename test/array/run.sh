#!/bin/sh
# Build and run the Array regression tests (grow-down sorting and iteration).
#
# Usage:
#   sh test/array/run.sh              build and run
#   VALGRIND=1 sh test/array/run.sh   run under valgrind
#
# Running under valgrind is what proves the iteration fix: the pre-fix
# Array_GetNext steps one element *past* a->Data on a grow-down array, which
# valgrind reports as an invalid read of the caller's buffer.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_array

Sources="
$Root/test/array/main.c
$Root/array.c
$Root/utils.c
$Root/stringchunk.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/simpleht.c
$Root/addresslist.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
