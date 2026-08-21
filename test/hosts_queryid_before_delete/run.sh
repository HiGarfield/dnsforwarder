#!/bin/sh
# Regression test: hosts.c must capture the query identifier BEFORE
# GenAnswerHeaderAndRemove() resets/deletes the back-trace context, never read
# it from the deleted node afterwards.
#
# Part 1 (behaviour): drives the real ModuleContext/BST to show that a node
#   deleted by GenAnswerHeaderAndRemove() is immediately recycled by the next
#   Add() -- the old "read after delete" order would pick up the new bytes.
# Part 2 (structure): scans hosts.c to enforce the ordering -- the
#   DNSGetQueryIdentifier(BackTraceHeader + 1) capture must precede the
#   GenAnswerHeaderAndRemove() call, and the DNS*QueryIdentifier write-back
#   must follow it.
#
# Usage:
#   sh test/hosts_queryid_before_delete/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/hosts_queryid_before_delete/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Here="$Root/test/hosts_queryid_before_delete"
Bin=/tmp/dnsforwarder_test_hosts_queryid

Sources="$Here/main.c
$Root/mcontext.c
$Root/bst.c
$Root/stablebuffer.c
$Root/array.c
$Root/dnsparser.c
$Root/dnsrelated.c
$Root/iheader.c
$Root/utils.c
$Root/addresslist.c
$Root/stringlist.c
$Root/dnsgenerator.c
$Root/test/stubs.c
"

echo "Part 1: behaviour -- deleted node is recycled by the next Add"
${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Bin" $Sources -lpthread -lm
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Bin"

echo "Part 2: structure -- hosts.c captures the ID before the delete"
python3 - "$Root/hosts.c" <<'PY'
import re, sys

path = sys.argv[1]
# Strip comments so only real code is examined.
text = re.sub(r'/\*.*?\*/', '', open(path).read(), flags=re.S)
text = re.sub(r'//[^\n]*', '', text)

get = re.search(r'DNSGetQueryIdentifier\s*\(\s*BackTraceHeader\s*\+\s*1\s*\)', text)
rem = re.search(r'Context\.GenAnswerHeaderAndRemove\s*\(', text)
set = re.search(r'DNSSetQueryIdentifier\s*\(\s*InnerHeader\s*\+\s*1\s*,', text)

Failures = []
if not get:
    Failures.append('DNSGetQueryIdentifier(BackTraceHeader + 1) capture not found')
if not rem:
    Failures.append('Context.GenAnswerHeaderAndRemove call not found')
if not set:
    Failures.append('DNSSetQueryIdentifier(InnerHeader + 1, ...) write-back not found')

if not Failures:
    if get.start() > rem.start():
        Failures.append('ID capture is AFTER the delete call -- the read would '
                        'touch the recycled node')
    if set.start() < rem.end():
        Failures.append('ID write-back is BEFORE the delete call -- write-back '
                        'and capture are out of order')

# No other use of BackTraceHeader may follow the GenAnswerHeaderAndRemove call.
if not Failures:
    after = text[rem.end():]
    if re.search(r'\bBackTraceHeader\b', after):
        Failures.append('BackTraceHeader is still referenced after the delete '
                        'call; capture everything up front')

for f in Failures:
    print('  [FAIL] %s' % f)
if Failures:
    sys.exit(1)
print('  [ ok ] capture precedes the delete; no use after it')
PY

echo "hosts query-ID capture: OK"
exit 0
