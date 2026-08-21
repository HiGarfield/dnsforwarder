#!/bin/sh
# Regression test for two OOM-path bugs in goodiplist.c (found in the
# Round-6 review).  Both are init-time allocation failures that a normal
# configuration never hits, so this is a structural test: it scans the
# source (comments stripped) for the required invariants.
#
# Bug 1: InitListsAndTimes() freed GoodIpList but left the pointer
#        dangling when StringChunk_Init() failed.  GoodIpList_Init() had
#        already registered atexit(GoodIpList_Cleanup) at that point, so
#        on process exit the handler saw GoodIpList != NULL and ran
#        StringChunk_Enum_NoWildCard / StringChunk_Free / SafeFree on a
#        freed chunk: use-after-free and double-free.
#        Invariant: the failure branch must NULL the pointer after the
#        free, so the atexit handler skips it.
#
# Bug 2: InitListsAndTimes() ignored the return value of
#        StringChunk_Add().  When it fails (OOM) the list is not
#        registered, but the per-list heap buffer m.List.Data (which
#        GoodIpList_Cleanup would otherwise release) leaks.
#        Invariant: the call must check for failure and free
#        m.List.Data in that branch.
#
# Usage:
#   sh test/goodiplist_oom_cleanup/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

echo "Part 1: failed StringChunk_Init leaves GoodIpList NULL (no atexit UAF)"
python3 - "$Root/goodiplist.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

# Locate the StringChunk_Init failure branch inside InitListsAndTimes.
start = next((n for n, l in enumerate(lines)
              if 'StringChunk_Init(GoodIpList, NULL)' in l), None)
if start is None:
    print('  [FAIL] StringChunk_Init(GoodIpList, ...) call not found; test is stale')
    sys.exit(1)

branch = '\n'.join(lines[start:start + 8])
if 'SafeFree(GoodIpList)' not in branch:
    print('  [FAIL] failure branch does not free GoodIpList')
    sys.exit(1)
if 'GoodIpList = NULL' not in branch:
    print('  [FAIL] failure branch does not NULL GoodIpList (atexit UAF/double-free)')
    sys.exit(1)
print('  [ ok ] failed-init branch frees and NULLs GoodIpList')
sys.exit(0)
PY

echo "Part 2: StringChunk_Add failure releases the per-list buffer"
python3 - "$Root/goodiplist.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

# The call must be guarded by an if (...) != 0 whose body frees m.List.Data.
guard = next((n for n, l in enumerate(lines)
              if 'StringChunk_Add(GoodIpList, n, (const char *)&m, sizeof(ListInfo))' in l), None)
if guard is None:
    print('  [FAIL] StringChunk_Add(GoodIpList, n, ...) call not found; test is stale')
    sys.exit(1)

if not lines[guard].lstrip().startswith('if( StringChunk_Add('):
    print('  [FAIL] StringChunk_Add return value is not checked (leak on OOM)')
    sys.exit(1)

body = '\n'.join(lines[guard:guard + 8])
if 'SafeFree(m.List.Data)' not in body:
    print('  [FAIL] failure branch does not free m.List.Data (leak on OOM)')
    sys.exit(1)
print('  [ ok ] StringChunk_Add failure frees the per-list buffer')
sys.exit(0)
PY
