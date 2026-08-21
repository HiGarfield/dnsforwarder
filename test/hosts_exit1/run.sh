#!/bin/sh
# Build and run the hosts.c EXIT_1 teardown regression tests.
#
# Usage:
#   sh test/hosts_exit1/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/hosts_exit1/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_hosts_exit1

Sources="
$Root/test/hosts_exit1/main.c
$Root/socketpuller.c
$Root/socketpool.c
$Root/bst.c
$Root/stablebuffer.c
$Root/array.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

# LeakSanitizer's end-of-run scan hangs in some containerised environments;
# keep ASan/UBSan's memory-error detection but skip the leak scan there.
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Out"
