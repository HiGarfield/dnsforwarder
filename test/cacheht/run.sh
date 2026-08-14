#!/bin/sh
# Build and run the cacheht standalone regression test under sanitizers.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_cacheht

Sources="
$Root/test/cacheht/main.c
$Root/cacheht.c
$Root/array.c
$Root/utils.c
$Root/addresslist.c
$Root/test/cacheht/logstub.c
"

${CC:-cc} -I"$Root" ${SAN_FLAGS:--fsanitize=address,undefined -g -O1} -o "$Out" $Sources -lpthread -lm
"$Out"
