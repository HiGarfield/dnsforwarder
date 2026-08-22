#!/bin/sh
# Regression test for an OOM-path crash in mmgr.c (found in the Round-3
# review).  Init-time allocation failures are not reachable with a normal
# configuration, so this is a structural test: it scans the source (comments
# stripped) for the required invariant.
#
# Bug: Modules_Load() allocated NewModuleMap with SafeMalloc() (plain
#      malloc(), no zeroing) and only then set the fields one by one.  The
#      failure path (the ModulesFree label) reads -- and cleans up through --
#      NewModuleMap->Modules / NewModuleMap->ModuleArray, which are still
#      uninitialised garbage when an earlier step fails (InitChunk, or the
#      Modules/ModuleArray allocation).  A garbage non-NULL value makes
#      `if( NewModuleMap->Modules != NULL )` take the cleanup branch and
#      dereference a wild StableBuffer/Array pointer: crash on an OOM error
#      path.  If the garbage happened to be NULL instead, Modules_Free() then
#      read the other still-garbage field and crashed the same way.
#      Invariant: the whole map must be zeroed immediately after allocation,
#      so every unset field reads as NULL and both cleanup paths are safe
#      no-ops.
#
# Usage:
#   sh test/mmgr_init_failure/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

echo "Part 1: Modules_Load zeroes NewModuleMap before any failure branch"
python3 - "$Root/mmgr.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'NewModuleMap = SafeMalloc(sizeof(ModuleMap))' in l), None)
if start is None:
    print('  [FAIL] NewModuleMap allocation not found; test is stale')
    sys.exit(1)

# The zeroing must sit between the allocation and the first `goto ModulesFree`.
window = '\n'.join(lines[start:start + 12])
if 'memset(NewModuleMap, 0, sizeof(ModuleMap))' not in window:
    print('  [FAIL] NewModuleMap is not zeroed after allocation '
          '(garbage Modules/ModuleArray dereferenced on the OOM path)')
    sys.exit(1)
if 'goto ModulesFree' in window:
    print('  [FAIL] a failure branch is reachable before the memset')
    sys.exit(1)
print('  [ ok ] NewModuleMap is zeroed before any failure branch')
sys.exit(0)
PY

echo "Part 2: Modules_Free tolerates NULL Modules / ModuleArray fields"
python3 - "$Root/mmgr.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'static void Modules_Free(ModuleMap *ModuleMap)' in l), None)
if start is None:
    print('  [FAIL] Modules_Free not found; test is stale')
    sys.exit(1)

body = '\n'.join(lines[start:start + 30])
for needle in ('ModuleMap->Modules != NULL',
               'ModuleMap->ModuleArray != NULL',
               'ModuleMap->Distributor != NULL'):
    if needle not in body:
        print('  [FAIL] Modules_Free does not NULL-guard %s' % needle)
        sys.exit(1)
print('  [ ok ] Modules_Free NULL-guards every field')
sys.exit(0)
PY
