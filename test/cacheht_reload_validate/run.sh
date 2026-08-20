#!/bin/sh
# Build and run the cache-reload validation regression tests.
#
# Usage:
#   sh test/cacheht_reload_validate/run.sh
#   VALGRIND=1 sh test/cacheht_reload_validate/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/cacheht_reload_validate/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_cacheht_reload_validate

Sources="
$Root/test/cacheht_reload_validate/main.c
$Root/cacheht.c
$Root/array.c
$Root/utils.c
$Root/addresslist.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
