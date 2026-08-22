#!/bin/sh
# Regression test: hosts.c must capture OuterHeader->Parent / Domain BEFORE
# recvfrom() overwrites OuterBuffer with the response, must match the response
# identifier against the in-flight query, must parse the response from the
# beginning of OuterBuffer (not from the stale OuterEntity), and must clear
# the parent slot once the context is removed.
#
# Part 1 (behaviour): reproduces the byte-level overwrite on a real buffer and
#   shows the old read order observes response bytes while the new capture
#   order stays valid, that a stray datagram is rejected by its identifier,
#   and that the response bytes sit at OuterBuffer[0 .. State).
# Part 2 (structure): scans hosts.c to enforce the ordering -- the Parent and
#   Domain captures must precede the OuterSocket recvfrom(); the response must
#   be parsed from OuterBuffer; the parent slot must be cleared after removal.
#
# Usage:
#   sh test/hosts_response_overwrite/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/hosts_response_overwrite/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Here="$Root/test/hosts_response_overwrite"
Bin=/tmp/dnsforwarder_test_hosts_overwrite

Sources="$Here/main.c
$Root/dnsparser.c
$Root/dnsrelated.c
$Root/iheader.c
$Root/utils.c
$Root/addresslist.c
$Root/stringlist.c
$Root/dnsgenerator.c
$Root/test/stubs.c
"

echo "Part 1: behaviour -- the response overwrites OuterBuffer; capture must precede recvfrom"
${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Bin" $Sources -lpthread -lm
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Bin"

echo "Part 2: structure -- hosts.c captures before recvfrom and parses from OuterBuffer"
python3 - "$Root/hosts.c" <<'PY'
import re, sys

path = sys.argv[1]
# Strip comments so only real code is examined.
text = re.sub(r'/\*.*?\*/', '', open(path).read(), flags=re.S)
text = re.sub(r'//[^\n]*', '', text)

Failures = []

# 1. The Parent capture must appear BEFORE the OuterSocket recvfrom().
recv = re.search(r'recvfrom\s*\(\s*OuterSocket', text)
cap  = re.search(r'BackTraceHeader\s*=\s*OuterHeader->Parent', text)
if not recv:
    Failures.append('OuterSocket recvfrom not found')
if not cap:
    Failures.append('BackTraceHeader = OuterHeader->Parent capture not found')
elif recv and cap.start() > recv.start():
    Failures.append('Parent is captured AFTER the recvfrom -- the receive overwrites it')

# 2. The recursed domain must also be captured before the recvfrom.
dcap = re.search(r'strncpy\s*\(\s*RecursedDomain\s*,\s*OuterHeader->Domain', text)
if not dcap:
    Failures.append('RecursedDomain capture (strncpy from OuterHeader->Domain) not found')
elif recv and dcap.start() > recv.start():
    Failures.append('RecursedDomain is captured AFTER the recvfrom')

# 3. The response identifier must be matched against the in-flight query.
idchk = re.search(r'DNSGetQueryIdentifier\s*\(\s*OuterBuffer\s*\)\s*!=\s*OuterQueryIdentifier', text)
if not idchk:
    Failures.append('response identifier check against OuterQueryIdentifier not found')

# 4. CombineRecursedResponse must be fed the beginning of OuterBuffer.
comb = re.search(r'HostsUtils_CombineRecursedResponse', text)
if not comb:
    Failures.append('HostsUtils_CombineRecursedResponse call not found')
elif text.count('OuterEntity') > 0:
    Failures.append('OuterEntity is still referenced -- the response is at OuterBuffer[0..State)')

# 5. The parent slot must be cleared after the context is removed.
clear = re.search(r'OuterHeader->Parent\s*=\s*NULL\s*;\s*OuterQueryIdentifier\s*=\s*0', text)
if not clear:
    Failures.append('parent slot is not cleared after the context is removed')

for f in Failures:
    print('  [FAIL] %s' % f)
if Failures:
    sys.exit(1)
print('  [ ok ] capture precedes recvfrom; response parsed from OuterBuffer; slot cleared')
PY

echo "hosts outer-response overwrite: OK"
exit 0
