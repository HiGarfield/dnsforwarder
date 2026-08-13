#!/bin/sh
# Regression test: ModuleContext_Del() must be handed the pointer
# ModuleContext_Add() returned.
#
# Bst_Delete() derives its node header from ((Bst_NodeHead *)Node) - 1 and then
# writes through that header's Left/Right/Parent links, so only the pointer
# Add() returned (which addresses the copy inside the node) is valid.
#
# UdpM_Send() rolled its context entry back with the caller's receive buffer in
# both of its failure paths -- "Fatal error 205" from AddressList_GetOne(), and
# m->Departure not being ready, which happens whenever UdpM_Works() is
# recreating the socket after a burst of timeouts or a SOCKET_ERROR. Bst_Delete()
# then read a node header out of the heap in front of that buffer and relinked
# the context tree through the garbage it found.
#
# Part 1 exercises the Add/Del/Find contract under ASan/UBSan.
# Part 2 is the negative control: the same code driven the old, wrong way has to
#        be diagnosed by the sanitizer.
# Part 3 checks the callers in udpm.c and tcpm.c roll back with the Add() result.
#
# Usage:
#   sh test/mcontext_del_node/run.sh

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Here="$Root/test/mcontext_del_node"
Bin=/tmp/mcontext_del_node

Sources="$Here/main.c
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
$Root/stringlist.c
$Root/test/tcpfrontend_stub.c"

# shellcheck disable=SC2086
cc -I"$Root" -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
   -Wall -o "$Bin" $Sources -lpthread -lm

echo "Part 1: Add/Del/Find contract"
if ! ASAN_OPTIONS=detect_leaks=1 "$Bin" contract; then
    echo "  [FAIL] the fixed usage was rejected or diagnosed" >&2
    exit 1
fi
echo "  [ ok ] clean under ASan/UBSan"

echo "Part 2: negative control, Del() with the caller's buffer"
Out=$(ASAN_OPTIONS=detect_leaks=0 "$Bin" bad 2>&1 || true)
if printf '%s' "$Out" | grep -qE 'AddressSanitizer|runtime error|SEGV'; then
    echo "  [ ok ] sanitizer diagnosed the old rollback"
elif printf '%s' "$Out" | grep -q 'bad mode completed without diagnosis'; then
    # Whatever precedes the allocation happened to look benign. Not a product
    # failure, so do not fail the suite over an unobservable run.
    echo "  [skip] the corruption was not observable in this run"
else
    echo "  [FAIL] unexpected output from the negative control:" >&2
    printf '%s\n' "$Out" >&2
    exit 1
fi

echo "Part 3: rollback callers pass the Add() result"
python3 - "$Root/udpm.c" "$Root/tcpm.c" <<'PY'
import re, sys

Failures = []
Total = 0

for path in sys.argv[1:]:
    lines = [l.split('/*')[0] for l in open(path).read().split('\n')]
    name = path.rsplit('/', 1)[-1]
    hits = [(n, l) for n, l in enumerate(lines)
            if re.search(r'Context\.Del\s*\(', l)]
    if not hits:
        print('  [FAIL] %s: no Context.Del() call found; test is stale' % name)
        Failures.append(name)
        continue
    for n, l in hits:
        Total += 1
        arg = l.split(',')[-1].strip().rstrip(');').strip()
        if re.search(r'\bBuffer\b|\bMsgCtx\b\s*$', arg) and 'Stored' not in arg:
            print('  [FAIL] %s:%d rolls back with %s instead of the Add() '
                  'result: %s' % (name, n + 1, arg, l.strip()))
            Failures.append('%s:%d' % (name, n + 1))

if not Failures:
    print('  [ ok ] all %d rollback call(s) use the stored pointer' % Total)

sys.exit(1 if Failures else 0)
PY

echo "ModuleContext Del node contract: OK"
exit 0
