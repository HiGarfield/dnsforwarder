#!/bin/sh
# Regression test: resource records whose RDLENGTH is too small for their type
# must not make the field parsers read past the end of the packet.
set -e

Here=$(cd "$(dirname "$0")" && pwd)
Root=$(cd "$Here/../.." && pwd)
Binary=$(mktemp /tmp/t_short_rdata.XXXXXX)

CC=${CC:-cc}

"$CC" -I"$Root" -g -O1 -o "$Binary" \
    "$Here/main.c" \
    "$Root/dnsparser.c" \
    "$Root/dnsrelated.c" \
    "$Root/utils.c" \
    "$Root/addresslist.c" \
    "$Root/array.c" \
    "$Root/stringlist.c" \
    "$Root/stablebuffer.c" \
    -lpthread

Status=0
"$Binary" || Status=$?

rm -f "$Binary"

if [ "$Status" -ne 0 ]; then
    echo "FAIL: short-RDATA regression test failed (status $Status)"
    exit 1
fi

echo "PASS: short-RDATA regression test"
