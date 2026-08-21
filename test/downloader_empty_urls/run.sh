#!/bin/sh
# Build and run the downloader empty-URL-list regression tests.
#
# Usage:
#   sh test/downloader_empty_urls/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/downloader_empty_urls/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_downloader_empty_urls

# DOWNLOAD_WGET makes downloader.c compile its real merge logic; the test only
# exercises the empty-list path, so no actual wget invocation happens.
Sources="
$Root/test/downloader_empty_urls/main.c
$Root/downloader.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/test/stubs.c
"

${CC:-cc} -DDOWNLOAD_WGET -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources

if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Out"
