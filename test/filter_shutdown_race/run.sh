#!/bin/sh
# Build and run the filter shutdown-cleanup race regression test.
#
# Part 1 (structural): FilterType_Cleanup() must NOT destroy DisabledDomainLock
# nor free DisabledTypes, and DisabledDomain_Cleanup() must free DisabledDomain
# under the write lock and NULL the pointer -- and must NOT destroy the lock --
# because atexit LIFO order runs these handlers before Modules_Cleanup() stops
# the module workers: IsDisabledDomain()/IsDisabledType() may still be running.
# Both bodies must carry a comment explaining that rationale.
#
# Part 2 (runtime): a worker thread keeps locking DisabledDomainLock and
# dereferencing DisabledDomain; DisabledDomain_Cleanup() runs while the thread
# is live, and the thread then does one more locked access.  The old cleanup
# made that access a heap-use-after-free (ASan catches it); the new one NULLs
# the pointer under the lock so the worker sees NULL.
#
# Usage:
#   sh test/filter_shutdown_race/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/filter_shutdown_race/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_filter_shutdown_race

echo "Part 1: filter.c cleanups leave the lock / BST to the OS and NULL the container"
python3 - "$Root/filter.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

def find_body(fn):
    start = next((n for n, l in enumerate(lines) if fn in l), None)
    if start is None:
        print('  [FAIL] %s not found; test is stale' % fn)
        sys.exit(1)
    end = next((n for n in range(start + 1, len(lines))
                if lines[n].strip() == '}'), None)
    if end is None:
        print('  [FAIL] could not find the end of %s' % fn)
        sys.exit(1)
    return '\n'.join(lines[start:end + 1])

type_body = find_body('FilterType_Cleanup(void)')
for banned, why in (
    ('RWLock_Destroy', 'destroying the lock races module workers'),
    ('DisabledTypes', 'freeing the BST races the lock-free IsDisabledType reader'),
):
    if banned in type_body:
        print('  [FAIL] FilterType_Cleanup still contains %s (%s)' % (banned, why))
        sys.exit(1)
print('  [ ok ] FilterType_Cleanup does not destroy the lock or free the BST')

domain_body = find_body('DisabledDomain_Cleanup(void)')
for banned, why in (
    ('RWLock_Destroy', 'destroying the lock races module workers'),
):
    if banned in domain_body:
        print('  [FAIL] DisabledDomain_Cleanup still contains %s (%s)' % (banned, why))
        sys.exit(1)
if 'RWLock_WrLock' not in domain_body:
    print('  [FAIL] DisabledDomain_Cleanup does not take the write lock')
    sys.exit(1)
if 'DisabledDomain = NULL' not in domain_body:
    print('  [FAIL] DisabledDomain_Cleanup does not NULL the pointer')
    sys.exit(1)
free_at = domain_body.find('StringChunk_Free')
lock_at = domain_body.find('RWLock_WrLock')
if free_at < 0 or free_at < lock_at:
    print('  [FAIL] DisabledDomain_Cleanup frees before taking the write lock')
    sys.exit(1)
print('  [ ok ] DisabledDomain_Cleanup frees under the lock and NULLs the pointer')
sys.exit(0)
PY

echo "Part 2: container pointer visible as NULL after cleanup runs"
TmpDir=$(mktemp -d)
cat > "$TmpDir/logs_stub.c" <<'EOF'
#include <stdarg.h>
#include "common.h"
int Log_Init(void *c, int p, int d){ (void)c;(void)p;(void)d; return 0; }
int Log_Inited(void){ return 1; }
int Log_DebugOn(void){ return 0; }
void Log_Print(const char *t, const char *f, ...){ (void)t;(void)f; }
EOF
cat > "$TmpDir/conf_stub.c" <<'EOF'
#include "common.h"
#include "readconfig.h"
#include "stringlist.h"
int ConfigGetInt32(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return 0; }
int ConfigGetBoolean(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return 0; }
const char *ConfigGetRawString(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return NULL; }
StringList *ConfigGetStringList(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return NULL; }
EOF
cat > "$TmpDir/addr_stub.c" <<'EOF'
#include "common.h"
int AddressList_ConvertFromString(void *a, const char *s, int p){ (void)a;(void)s;(void)p; return 0; }
EOF
# filter.c's Filter_Out() (not exercised here) references these; provide
# stubs so the link is complete without dragging in mcontext.c / logs.c.
cat > "$TmpDir/ext_stub.c" <<'EOF'
#include "common.h"
#include "domainstatistic.h"
#include "iheader.h"
#include "mcontext.h"
int DomainStatistic_Add(IHeader *h, StatisticType Type){ (void)h;(void)Type; return 0; }
void ShowRefusingMessage(IHeader *h, const char *Message){ (void)h;(void)Message; }
int MsgContext_SendBackRefusedMessage(MsgContext *MsgCtx){ (void)MsgCtx; return 0; }
EOF

# main.c #includes filter.c itself (static-export trick), so filter.c is NOT
# linked separately here.
${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" \
    "$Root/test/filter_shutdown_race/main.c" \
    "$Root/bst.c" \
    "$Root/stringchunk.c" \
    "$Root/stringlist.c" \
    "$Root/stablebuffer.c" \
    "$Root/array.c" \
    "$Root/simpleht.c" \
    "$Root/utils.c" \
    "$Root/readline.c" \
    "$TmpDir/logs_stub.c" \
    "$TmpDir/conf_stub.c" \
    "$TmpDir/addr_stub.c" \
    "$TmpDir/ext_stub.c" \
    -lpthread -lm
rc=$?
rm -rf "$TmpDir"
if [ $rc -ne 0 ]; then
    exit $rc
fi

if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
timeout 30 "$Out"
