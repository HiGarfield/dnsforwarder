#!/bin/sh
# Build and run the DnsGenerator_CName NULL-deref regression test under sanitizers.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnsgenerator_cname_null

Sources="
$Root/test/dnsgenerator_cname_null/main.c
$Root/dnsparser.c
$Root/dnsgenerator.c
$Root/dnsrelated.c
$Root/utils.c
$Root/addresslist.c
$Root/array.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/stringchunk.c
$Root/bst.c
$Root/simpleht.c
"

${CC:-cc} -fsanitize=address,undefined -I"$Root" -g -O1 -Wall -o "$Out" $Sources -lpthread -lm
"$Out" "$@"
