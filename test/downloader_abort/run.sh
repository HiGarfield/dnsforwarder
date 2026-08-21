#!/bin/sh
# Build and run the downloader infinite-retry abort regression test.
#
# Part 1 (structural): downloader.c's retry loop must observe the
# Downloader_Aborted flag -- both at the top of
# `while( RetryTimes != 0 ... )' and right before the retry SLEEP -- so a
# shutdown requested during a failing download is noticed immediately.
#
# Part 2 (structural): DynamicHosts_Cleanup() must call Downloader_Abort()
# BEFORE its `while( Reloading ) SLEEP(10)' spin; otherwise a reload thread
# stuck in an infinite retry loop keeps Reloading TRUE and the cleanup waits
# forever (shutdown hang).
#
# Part 3 (runtime): GetFromInternet_SingleFile(..., RetryTimes = -1) running
# in a helper thread must return promptly once Downloader_Abort() is called,
# the abort flag must persist until Downloader_AbortReset(), and a download
# started after the reset must run normally again.
#
# Usage:
#   sh test/downloader_abort/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/downloader_abort/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_downloader_abort

echo "Part 1: retry loop guards against Downloader_Aborted"
python3 - "$Root/downloader.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
# Drop every comment first so doc comments cannot satisfy the scan.
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

# The retry loop condition must include the abort flag.
loop = [l for l in lines
        if 'RetryTimes != 0' in l and 'Downloader_Aborted' in l]
if not loop:
    print('  [FAIL] retry loop condition does not check Downloader_Aborted')
    sys.exit(1)

# And there must be an abort check right before the retry SLEEP.
ok = False
for n, l in enumerate(lines):
    if 'SLEEP(RetryInterval * 1000)' in l:
        pre = lines[max(0, n - 12):n]
        if any('Downloader_Aborted' in p for p in pre):
            ok = True
        break
if not ok:
    print('  [FAIL] no Downloader_Aborted check before SLEEP(RetryInterval * 1000)')
    sys.exit(1)
print('  [ ok ] retry loop and pre-sleep path both observe Downloader_Aborted')
sys.exit(0)
PY

echo "Part 2: DynamicHosts_Cleanup aborts before waiting on Reloading"
python3 - "$Root/dynamichosts.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'DynamicHosts_Cleanup(void)' in l), None)
if start is None:
    print('  [FAIL] DynamicHosts_Cleanup not found; test is stale')
    sys.exit(1)

end = next((n for n in range(start, len(lines))
            if 'while( Reloading )' in lines[n]), None)
if end is None:
    print('  [FAIL] while( Reloading ) not found inside DynamicHosts_Cleanup')
    sys.exit(1)

body = lines[start:end]
if not any('Downloader_Abort(' in l for l in body):
    print('  [FAIL] Downloader_Abort() is not called before while( Reloading )')
    sys.exit(1)
print('  [ ok ] Downloader_Abort() precedes the Reloading wait')
sys.exit(0)
PY

echo "Part 3: infinite retry is interruptible, flag persists, reset restores"
${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" \
    "$Root/test/downloader_abort/main.c" \
    "$Root/downloader.c" \
    -lpthread

"$Out"
