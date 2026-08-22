#!/bin/sh
# Build and run the DNSCompress CNAME-chain semantic validation under
# AddressSanitizer + UndefinedBehaviorSanitizer.
#
# Unlike the mutation fuzzers (which only assert "no crash"), this test checks
# the *meaning* of a compressed response: every owner name, record type and
# RDATA must survive the DNSCompress() round-trip.  That is exactly the path
# DNSCompress() corrupts if its CNAME branch computes the RDATA offset against
# a stale CurrentPosition after the memmove().
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnscompress_cname

Sources="
$Root/test/dnscompress_cname/main.c
$Root/dnsparser.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/dnsrelated.c
$Root/dnsgenerator.c
$Root/iheader.c
$Root/test/tcpfrontend_stub.c
"

${CC:-cc} -fsanitize=address,undefined -I"$Root" -g -O1 -Wall -o "$Out" $Sources -lpthread -lm
"$Out" "$@"
