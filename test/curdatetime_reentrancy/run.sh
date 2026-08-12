#!/bin/sh
# Regression test: GetCurDateAndTime() must be reentrant, i.e. it must not
# hand out (or overwrite) the process-wide struct tm of localtime().
set -e

Here=$(cd "$(dirname "$0")" && pwd)
Root=$(cd "$Here/../.." && pwd)

CC=${CC:-cc}

Sources="$Here/main.c $Root/utils.c $Root/addresslist.c $Root/array.c $Root/stringlist.c $Root/stablebuffer.c $Root/dnsparser.c $Root/dnsrelated.c"

Binary=$(mktemp /tmp/t_curdatetime.XXXXXX)
"$CC" -I"$Root" -g -O1 -o "$Binary" $Sources -lpthread

Status=0
"$Binary" || Status=$?
rm -f "$Binary"

if [ "$Status" -ne 0 ]; then
    echo "FAIL: GetCurDateAndTime() reentrancy test failed (status $Status)"
    exit 1
fi

# The functional check above catches the shared-buffer misuse; ThreadSanitizer
# additionally catches the race itself. Only run it when the toolchain has it.
TsanBinary=$(mktemp /tmp/t_curdatetime_tsan.XXXXXX)
if "$CC" -I"$Root" -g -O1 -fsanitize=thread -o "$TsanBinary" $Sources \
        -lpthread >/dev/null 2>&1; then
    Status=0
    TSAN_OPTIONS="halt_on_error=1:exitcode=66" "$TsanBinary" >/dev/null 2>&1 \
        || Status=$?
    rm -f "$TsanBinary"
    if [ "$Status" -ne 0 ]; then
        echo "FAIL: ThreadSanitizer reported a problem (status $Status)"
        exit 1
    fi
    echo "PASS: GetCurDateAndTime() reentrancy test (with ThreadSanitizer)"
else
    rm -f "$TsanBinary"
    echo "PASS: GetCurDateAndTime() reentrancy test (ThreadSanitizer unavailable)"
fi
