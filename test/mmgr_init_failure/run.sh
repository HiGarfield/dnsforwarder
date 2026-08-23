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

# Locate the zeroing and the first failure branch; the zeroing must precede it.
memset_pos = next((n for n in range(start, min(start + 25, len(lines)))
                   if 'memset(NewModuleMap, 0, sizeof(ModuleMap))' in lines[n]),
                  None)
if memset_pos is None:
    print('  [FAIL] NewModuleMap is not zeroed after allocation '
          '(garbage Modules/ModuleArray dereferenced on the OOM path)')
    sys.exit(1)

goto_pos = next((n for n in range(start, min(start + 40, len(lines)))
                 if 'goto ModulesFree' in lines[n]), None)
if goto_pos is None:
    print('  [FAIL] the ModulesFree failure label is not reached after the '
          'allocation; test is stale')
    sys.exit(1)
if memset_pos > goto_pos:
    print('  [FAIL] a failure branch is reachable before the memset')
    sys.exit(1)
print('  [ ok ] NewModuleMap is zeroed before any failure branch '
      '(memset line %d, first goto line %d)' % (memset_pos + 1, goto_pos + 1))
sys.exit(0)
PY

echo "Part 2: Modules_Free(Inner) tolerates NULL Modules / ModuleArray fields"
python3 - "$Root/mmgr.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

# The per-field free logic lives in Modules_FreeInner (the now-removed
# Modules_Free wrapper only delegated to it and freed the struct).  The inner
# routine must still NULL-guard every field so an OOM/partial-load path never
# dereferences garbage Modules/ModuleArray/Distributor pointers.
inner_start = next((n for n, l in enumerate(lines)
                    if 'static void Modules_FreeInner(ModuleMap *ModuleMap)' in l), None)
if inner_start is None:
    print('  [FAIL] Modules_FreeInner not found; test is stale')
    sys.exit(1)

# Modules_SafeCleanup must tear down the internals via Modules_FreeInner
# (leaving the struct itself to the caller, so a stack-owned map is never
# bad-freed) -- this is the invariant fixed in the round-1 bad-free bug.
safe_start = next((n for n, l in enumerate(lines)
                   if 'Modules_SafeCleanup(ModuleMap *ModuleMap)' in l), None)
if safe_start is None:
    print('  [FAIL] Modules_SafeCleanup not found; test is stale')
    sys.exit(1)
if 'Modules_FreeInner(ModuleMap);' not in '\n'.join(lines[safe_start:safe_start + 80]):
    print('  [FAIL] Modules_SafeCleanup does not free internals via Modules_FreeInner')
    sys.exit(1)

body = '\n'.join(lines[inner_start:inner_start + 30])
for needle in ('ModuleMap->Modules != NULL',
               'ModuleMap->ModuleArray != NULL',
               'ModuleMap->Distributor != NULL'):
    if needle not in body:
        print('  [FAIL] Modules_FreeInner does not NULL-guard %s' % needle)
        sys.exit(1)
print('  [ ok ] Modules_Free delegates to Modules_FreeInner, which NULL-guards every field')
sys.exit(0)
PY
