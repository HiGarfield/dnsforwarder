#!/bin/sh
# Build and run the GoodIpList_Get locked-copy regression tests.
#
# Usage:
#   sh test/goodiplist_get/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/goodiplist_get/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_goodiplist_get

Sources="
$Root/test/goodiplist_get/main.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/array.c
$Root/stringlist.c
$Root/addresslist.c
$Root/socketpuller.c
$Root/socketpool.c
$Root/bst.c
$Root/ptimer.c
$Root/utils.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

# LeakSanitizer's end-of-run scan hangs in some containerised environments;
# keep ASan/UBSan's memory-error detection but skip the leak scan there.
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Out"
