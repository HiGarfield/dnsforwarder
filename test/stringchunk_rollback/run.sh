#!/bin/sh
# Build and run the StringChunk_Add payload-rollback regression test.
# ASan/UBSan prove the failed-key path no longer leaks the payload block.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_stringchunk_rollback

Sources="
$Root/test/stringchunk_rollback/main.c
$Root/stringchunk.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/array.c
$Root/simpleht.c
$Root/utils.c
$Root/addresslist.c
"

${CC:-cc} -I"$Root" -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -pthread -DDOWNLOAD_LIBCURL $Sources -o "$Out"
"$Out"
