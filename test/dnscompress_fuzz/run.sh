#!/bin/sh
# Build and run the DNSCompress mutation fuzzer under sanitizers.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnscompress_fuzz

Sources="
$Root/test/dnscompress_fuzz/main.c
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

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm
"$Out" "$@"
