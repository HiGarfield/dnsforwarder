#!/bin/sh
# Build and run the DNS generator (DNSLabelizedName / DnsGenerator_* / DNSCompress)
# mutation fuzzer under AddressSanitizer + UndefinedBehaviorSanitizer.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsgen_align_fuzz

Sources="
$Root/test/dnsgen_align_fuzz/main.c
$Root/dnsgenerator.c
$Root/dnsparser.c
$Root/dnsrelated.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/iheader.c
$Root/test/tcpfrontend_stub.c
"

${CC:-cc} -I"$Root" -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -o "$Out" $Sources -lpthread -lm
"$Out" "$@"
