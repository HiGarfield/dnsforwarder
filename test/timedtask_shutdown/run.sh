#!/bin/sh
# Build and run the end-to-end TimedTask shutdown-deadlock regression test.
# A hang (killed by timeout) means the JOIN_THREAD deadlock is back.
#
# Usage:
#   sh test/timedtask_shutdown/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/timedtask_shutdown/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_timedtask_shutdown

Sources="
$Root/test/timedtask_shutdown/main.c
$Root/timedtask.c
$Root/linkedqueue.c
$Root/pipes.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stringchunk.c
$Root/stablebuffer.c
$Root/simpleht.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

timeout 10 "$Out"
