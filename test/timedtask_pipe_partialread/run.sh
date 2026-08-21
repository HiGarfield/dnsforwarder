#!/bin/sh
# Build and run the timedtask self-pipe partial-read regression tests.
#
# Usage:
#   sh test/timedtask_pipe_partialread/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/timedtask_pipe_partialread/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_timedtask_partial

Sources="
$Root/test/timedtask_pipe_partialread/main.c
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

${CC:-cc} -I"$Root" -g -Wall -DTIMEDTASK_UNITTEST $CFLAGS -o "$Out" $Sources -lpthread

"$Out"
