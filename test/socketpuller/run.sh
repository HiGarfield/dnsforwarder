#!/bin/sh
# Build and run the socketpuller memory-leak regression test.
#
# Usage:
#   sh test/socketpuller/run.sh              build and run
#   VALGRIND=1 sh test/socketpuller/run.sh   verify with valgrind (leak check)
#
# The valgrind pass is the one that proves the fix: the pre-fix code leaks the
# contiguous SocketPuller Buffer array (definitely lost) on every Free() call.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_socketpuller

Sources="
$Root/test/socketpuller/main.c
$Root/socketpuller.c
$Root/socketpool.c
$Root/utils.c
$Root/bst.c
$Root/stablebuffer.c
$Root/stringchunk.c
$Root/stringlist.c
$Root/array.c
$Root/simpleht.c
$Root/addresslist.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
