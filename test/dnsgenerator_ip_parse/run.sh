#!/bin/sh
# Build and run the DnsGenerator A/AAAA IP-literal validation tests.
#
# Usage:
#   sh test/dnsgenerator_ip_parse/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/dnsgenerator_ip_parse/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsgenerator_ip_parse

Sources="
$Root/test/dnsgenerator_ip_parse/main.c
$Root/dnsparser.c
$Root/dnsrelated.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread -lm

"$Out"
