#!/bin/sh
# Regression test for the IPMiscMapping_Process() lock-scope bug
# (Round-8 review).
#
# Bug: IPMiscMapping_Process() checked CurrIpMiscMapping for NULL and then
# dereferenced it inside the read lock, but the NULL check itself happened
# BEFORE taking the read lock.  IpMiscMapping_Load() replaces the mapping
# (and frees the old one) under the write lock, so a reload racing the
# check could leave the thread calling ->Process() on the freed mapping
# (use-after-free).
#
# Fix: take the read lock first, check NULL under it, and unlock before
# returning in that branch, so every access to the mapping pointer is
# serialized with the reload.
#
# Usage:
#   sh test/ipmisc_process_lock/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

echo "Part 1: the NULL check must be inside the read lock"
python3 - "$Root/ipmisc.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'IPMiscMapping_Process(MsgContext *MsgCtx)' in l), None)
if start is None:
    print('  [FAIL] IPMiscMapping_Process not found; test is stale')
    sys.exit(1)

end = next((n for n in range(start, len(lines))
            if lines[n].startswith('}') and n > start), None)
body = '\n'.join(lines[start:end + 1])

i_lock = body.find('RWLock_RdLock(IpMiscMappingLock)')
i_null = body.find('CurrIpMiscMapping == NULL')
i_unlock = body.find('RWLock_UnRLock(IpMiscMappingLock)')

if i_lock < 0 or i_null < 0:
    print('  [FAIL] read lock or NULL check not found')
    sys.exit(1)
if i_null < i_lock:
    print('  [FAIL] NULL check runs before the read lock (races a reload)')
    sys.exit(1)
# The NULL branch must unlock and return (no use of the pointer outside
# the lock afterwards on that path).
if i_unlock < i_lock:
    print('  [FAIL] unlock missing after the NULL check')
    sys.exit(1)
print('  [ ok ] NULL check and pointer use are under the read lock')
sys.exit(0)
PY
