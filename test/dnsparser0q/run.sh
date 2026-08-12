#!/bin/sh
# Build and run the dnsparser zero-question-section regression test.
#
# This guards the fix for mis-computed section positions when the question
# section is empty (QDCOUNT == 0): previously the following non-empty section
# was mis-classified and iteration stopped after the first record.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsparser0q

Sources="
$Root/test/dnsparser0q/main.c
$Root/dnsparser.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/dnsrelated.c
$Root/iheader.c
$Root/dnsgenerator.c
$Root/test/tcpfrontend_stub.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 --leak-check=full -q "$Out"
else
    "$Out"
fi
