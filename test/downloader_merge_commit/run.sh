#!/bin/sh
# Regression test for the incomplete-merge commit bug in
# GetFromInternet_MultiFiles() (downloader.c, Round-9 review).
#
# Bug: when the record-separator append failed (fopen/fputc/fclose of the
# temp file), the merge loop only did `break` without clearing
# AllSucceeded, so the final `if( AllSucceeded ) rename(...)` committed a
# PARTIAL merge over the good target file (silent data loss on a full
# disk / I/O error after all downloads "succeeded").
#
# Fix: every failing path clears AllSucceeded so the commit is suppressed.
# Also verifies the retry loop no longer sleeps after its final attempt.
#
# Usage:
#   sh test/downloader_merge_commit/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

echo "Part 1: a failed separator append suppresses the merge commit"
python3 - "$Root/downloader.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'fopen(TempFile, "a+")' in l), None)
if start is None:
    print('  [FAIL] merge-loop fopen not found; test is stale')
    sys.exit(1)

loop = '\n'.join(lines[start:start + 26])

# Every one of the three failure exits (fopen, fputc, fclose) must clear
# AllSucceeded; checking the whole block for one occurrence is not enough,
# a mutation could remove just one of the three.
def block_has(lines, i, needle):
    # collect until the closing brace at nesting depth 0
    depth = 0
    block = []
    for j in range(i, len(lines)):
        depth += lines[j].count('{') - lines[j].count('}')
        block.append(lines[j])
        if depth <= 0 and lines[j].strip().startswith('}'):
            break
    return needle in '\n'.join(block)

i_fopen = next((n for n in range(start, start + 6)
                if 'fp == NULL' in lines[n]), None)
i_fputc = next((n for n in range(start, start + 20)
                if 'fputc(\'\\n\', fp) == EOF' in lines[n]), None)
i_fclose = next((n for n in range(start, start + 26)
                 if 'fclose(fp) != 0' in lines[n]), None)

ok = True
for name, i in (('fopen', i_fopen), ('fputc', i_fputc), ('fclose', i_fclose)):
    if i is None:
        print('  [FAIL] %s failure exit not found; test is stale' % name)
        sys.exit(1)
    if not block_has(lines, i, 'AllSucceeded = FALSE'):
        print('  [FAIL] %s failure path does not clear AllSucceeded (partial merge committed)' % name)
        ok = False

if not ok:
    sys.exit(1)
print('  [ ok ] all separator-append failure paths suppress the commit')
sys.exit(0)
PY

echo "Part 2: no sleep after the final failed retry"
python3 - "$Root/downloader.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

sleep = next((n for n, l in enumerate(lines)
              if 'SLEEP(RetryInterval * 1000)' in l), None)
if sleep is None:
    print('  [FAIL] retry-loop SLEEP not found; test is stale')
    sys.exit(1)
if 'RetryTimes != 0' not in '\n'.join(lines[sleep - 6:sleep]):
    print('  [FAIL] SLEEP is not guarded by RetryTimes != 0 (extra delay after final attempt)')
    sys.exit(1)
print('  [ ok ] retry loop skips the sleep on its final attempt')
sys.exit(0)
PY
