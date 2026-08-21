#!/bin/sh
# Build and run the ipchunk zone-handling regression tests.
#
# Usage:
#   sh test/ipchunk_zone/run.sh          build and run
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_ipchunk_zone

Sources="
$Root/test/ipchunk_zone/main.c
$Root/ipchunk.c
$Root/stablebuffer.c
$Root/bst.c
$Root/array.c
$Root/utils.c
$Root/addresslist.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread
"$Out"
