#!/bin/sh
# Build and run the mmgr uninitialized-module regression tests.
#
# Usage:
#   sh test/mmgr_storeamodule/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/mmgr_storeamodule/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_mmgr_storeamodule

Sources="
$Root/test/mmgr_storeamodule/main.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/array.c
$Root/stringlist.c
$Root/readline.c
$Root/addresslist.c
$Root/utils.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

# LeakSanitizer's end-of-run scan hangs in some containerised environments;
# keep ASan/UBSan's memory-error detection but skip the leak scan there.
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Out"
