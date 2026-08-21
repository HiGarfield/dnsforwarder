#!/bin/sh
# Build and run the TimedTask Add-vs-Cleanup TOCTOU regression test.
#
# Usage:
#   sh test/timedtask_shutdown_race/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/timedtask_shutdown_race/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_timedtask_shutdown_race

Sources="
$Root/test/timedtask_shutdown_race/main.c
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

"$Out"
