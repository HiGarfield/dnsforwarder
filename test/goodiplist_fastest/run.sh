#!/bin/sh
# Build and run the CheckAList "fastest address" regression test.
#
# Usage:
#   sh test/goodiplist_fastest/run.sh              build and run
#   VALGRIND=1 sh test/goodiplist_fastest/run.sh   run under valgrind
#
# Before the fix CheckAList() returned a pointer fabricated out of the bytes of
# a sockaddr_in (sin_family/sin_port/sin_addr), so the assertions on the
# returned pointer fail and ThreadJod() would write through a wild pointer.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_goodiplist_fastest

Sources="
$Root/test/goodiplist_fastest/main.c
$Root/socketpuller.c
$Root/socketpool.c
$Root/timedtask.c
$Root/linkedqueue.c
$Root/pipes.c
$Root/ptimer.c
$Root/dnsrelated.c
$Root/dnsparser.c
$Root/readconfig.c
$Root/readline.c
$Root/logs.c
$Root/utils.c
$Root/bst.c
$Root/stablebuffer.c
$Root/stringchunk.c
$Root/stringlist.c
$Root/array.c
$Root/simpleht.c
$Root/addresslist.c
"

${CC:-cc} -I"$Root" -g -Wall -o "$Out" $Sources -lpthread -lm

if [ -n "$VALGRIND" ]; then
    valgrind --error-exitcode=9 -q "$Out"
else
    "$Out"
fi
