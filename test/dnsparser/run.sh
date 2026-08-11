#!/bin/sh
# Build and run the dnsparser / address helper regression tests.
#
# Usage:
#   sh test/dnsparser/run.sh          build and run
#   VALGRIND=1 sh test/dnsparser/run.sh   run under valgrind as well
#
# The valgrind pass matters: several of the cases only fail as an
# out-of-bounds read, which a plain run cannot detect.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsparser

Sources="
$Root/test/dnsparser/main.c
$Root/dnsparser.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/dnsrelated.c
$Root/iheader.c
$Root/dnsgenerator.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
