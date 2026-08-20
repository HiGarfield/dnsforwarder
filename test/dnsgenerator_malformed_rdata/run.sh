#!/bin/sh
# Build and run the dnsgenerator malformed-RDATA regression tests.
#
# Usage:
#   sh test/dnsgenerator_malformed_rdata/run.sh
#   VALGRIND=1 sh test/dnsgenerator_malformed_rdata/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsgenerator_malformed_rdata

Sources="
$Root/test/dnsgenerator_malformed_rdata/main.c
$Root/dnsparser.c
$Root/dnsgenerator.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/dnsrelated.c
$Root/iheader.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
