#!/bin/sh
# Build and run the cachettlcrtl exact-command regression tests.
#
# Usage:
#   sh test/cachettlcrtl_exact/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/cachettlcrtl_exact/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_cachettlcrtl_exact

Sources="
$Root/test/cachettlcrtl_exact/main.c
$Root/cachettlcrtl.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

"$Out"
