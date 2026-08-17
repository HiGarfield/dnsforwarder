#!/bin/sh
# Build and run the structured DNS message fuzzer under AddressSanitizer +
# UndefinedBehaviorSanitizer.  Unlike the random mutation fuzzer in run.sh,
# this generator builds well-formed messages whose individual fields stress
# the parser boundary handling (name-compression pointer chains to every
# offset, over-long/truncated RDATA per type, multiple questions, pure-answer
# packets, pointer chains).
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsparser_struct_fuzz

Sources="
$Root/test/dnsparser_fuzz/struct_fuzz.c
$Root/dnsparser.c
$Root/dnsgenerator.c
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
