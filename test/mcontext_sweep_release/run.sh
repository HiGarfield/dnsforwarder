#!/bin/sh
# Regression test: ModuleContext_Sweep() must release the TCP client socket hold
# for a query it abandons as timed-out.
#
# The TCP socket ownership is a reference count in the frontend
# (TcpSocketInFlight[s]). It is bumped when a query is dispatched from client
# socket s and dropped by TcpFrontend_ReleaseSocket() once the module thread is
# done. TcpFrontend_ClientGone() closes s only after the count hits zero, so the
# descriptor stays open for later answers until then.
#
# ModuleContext_Sweep() used to delete the timed-out entry without releasing the
# hold. A TCP client query the upstream silently dropped therefore left
# TcpSocketInFlight[s] pinned at 1 forever, TcpFrontend_ClientGone() then refused
# to close s, and the daemon leaked one descriptor per timed-out TCP query.
#
# The test registers a TCP query, forces it past the 2-second sweep deadline,
# and asserts the recording stub saw exactly one release for that socket. Under
# ASan/UBSan the whole path must stay clean.
#
# Usage:
#   sh test/mcontext_sweep_release/run.sh

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Here="$Root/test/mcontext_sweep_release"
Bin=/tmp/mcontext_sweep_release

Sources="$Here/main.c
$Here/tcpfrontend_rec.c
$Root/mcontext.c
$Root/bst.c
$Root/array.c
$Root/stablebuffer.c
$Root/dnsgenerator.c
$Root/dnsparser.c
$Root/dnsrelated.c
$Root/iheader.c
$Root/utils.c
$Root/addresslist.c
$Root/stringlist.c"

# shellcheck disable=SC2086
cc -I"$Root" -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
   -Wall -o "$Bin" $Sources -lpthread -lm

echo "Part 1: ModuleContext_Sweep releases the TCP socket hold"
if ! ASAN_OPTIONS=detect_leaks=1 "$Bin"; then
    echo "  [FAIL] the sweep did not release the TCP socket hold" >&2
    exit 1
fi
echo "  [ ok ] sweep released the hold; clean under ASan/UBSan"

echo "ModuleContext_Sweep TCP socket release: OK"
exit 0
