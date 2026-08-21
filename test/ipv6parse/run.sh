#!/bin/sh
# Build and run the IPv6AddressToNum validation regression tests.
#
# Usage:
#   sh test/ipv6parse/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/ipv6parse/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_ipv6parse

Sources="
$Root/test/ipv6parse/main.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources

if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Out"
