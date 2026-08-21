#!/bin/sh
# Build and run the dynamichosts reload/teardown race regression tests.
#
# Usage:
#   sh test/dynamichosts_reloadflag/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/dynamichosts_reloadflag/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dynamichosts_reloadflag

Sources="
$Root/test/dynamichosts_reloadflag/main.c
$Root/hostscontainer.c
$Root/readline.c
$Root/ipchunk.c
$Root/bst.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/stringlist.c
$Root/array.c
$Root/addresslist.c
$Root/utils.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

# timeout guards against the Bug #1 regression (cleanup spin loop hanging
# the process forever).
#
# LeakSanitizer's end-of-run scan hangs in some containerised environments;
# keep ASan/UBSan's memory-error detection but skip the leak scan there.
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
timeout 15 "$Out"
