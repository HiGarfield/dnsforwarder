#!/bin/sh
# Build and run the dnscache shutdown-cleanup race regression test.
#
# Part 1 (structural): DNSCache_Cleanup() must NOT destroy CacheLock, free
# the cache storage, free TtlCtrl or unmap the cache file, because atexit
# LIFO order runs this handler before TimedTask_Cleanup()/Modules_Cleanup():
# the TTL countdown task and the module workers may still be mid-access.
# It must carry a comment explaining that rationale.
#
# Part 2 (runtime): a worker thread keeps locking CacheLock and writing to
# MapStart; DNSCache_Cleanup() runs while the thread is live, and the thread
# then does one more locked write.  The old cleanup made that write a
# heap-use-after-free / NULL deref (ASan catches it); the new one is a no-op
# and everything stays valid.
#
# Usage:
#   sh test/dnscache_shutdown_race/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/dnscache_shutdown_race/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_dnscache_shutdown_race

echo "Part 1: DNSCache_Cleanup leaves the lock and storage to the OS"
python3 - "$Root/dnscache.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'DNSCache_Cleanup(void)' in l), None)
if start is None:
    print('  [FAIL] DNSCache_Cleanup not found; test is stale')
    sys.exit(1)

end = next((n for n in range(start, len(lines))
            if lines[n].startswith('}') and n > start), None)
if end is None:
    print('  [FAIL] could not find the end of DNSCache_Cleanup')
    sys.exit(1)

body = '\n'.join(lines[start:end + 1])
for banned, why in (
    ('RWLock_Destroy', 'destroying the lock races the TTL task / workers'),
    ('SafeFree(MapStart)', 'freeing the storage races the TTL task / workers'),
    ('UNMAP_FILE', 'unmapping races a still-live TTL task'),
    ('CLOSE_FILE', 'closing the file handle is pointless at exit and risky'),
):
    if banned in body:
        print('  [FAIL] DNSCache_Cleanup still contains %s (%s)' % (banned, why))
        sys.exit(1)
print('  [ ok ] no lock destroy / storage free / unmap in the cleanup body')
sys.exit(0)
PY

echo "Part 2: storage and lock usable after cleanup runs"
# main.c #includes dnscache.c itself (static-export trick), so dnscache.c is
# NOT linked separately here.  The real dependency chain (array/cacheht/
# cachettlcrtl/stringchunk/stringlist/simpleht/stablebuffer/utils/dnsparser)
# is linked in, with stubs for the config/timedtask/log/address helpers that
# those units reference but this test does not exercise.
TmpDir=$(mktemp -d)
cat > "$TmpDir/logs_stub.c" <<'EOF'
#include <stdarg.h>
#include "common.h"
int Log_Init(void *c, int p, int d){ (void)c;(void)p;(void)d; return 0; }
int Log_Inited(void){ return 1; }
int Log_DebugOn(void){ return 0; }
void Log_Print(const char *t, const char *f, ...){ (void)t;(void)f; }
EOF
cat > "$TmpDir/addr_stub.c" <<'EOF'
#include "common.h"
int AddressList_ConvertFromString(void *a, const char *s, int p){ (void)a;(void)s;(void)p; return 0; }
EOF
cat > "$TmpDir/conf_stub.c" <<'EOF'
#include "common.h"
#include "readconfig.h"
#include "stringlist.h"
int ConfigGetInt32(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return 0; }
int ConfigGetBoolean(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return 0; }
const char *ConfigGetRawString(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return NULL; }
StringList *ConfigGetStringList(ConfigFileInfo *Info, const char *KeyName){ (void)Info;(void)KeyName; return NULL; }
int TimedTask_Add(int Persistent, int Asynchronous, int Milliseconds, int (*Func)(void *, void *), void *Arg1, void *Arg2, int Immediate)
{ (void)Persistent;(void)Asynchronous;(void)Milliseconds;(void)Func;(void)Arg1;(void)Arg2;(void)Immediate; return 0; }
EOF
# dnscache.c's cache-hit response path (not exercised here) calls
# DnsGenerator_Init / DNSCompress / MsgContext_SendBack / ShowNormalMessage /
# DomainStatistic_Add; dnsparser.c calls DNSGetTypeName/DNS_TYPENAME_UNKNOWN
# (provided by the real dnsrelated.c, linked below).  Stub the former five so
# the link is complete without dragging in iheader.c/mcontext.c/domainstatistic.c.
cat > "$TmpDir/ext_stub.c" <<'EOF'
#include "common.h"
#include "dnsgenerator.h"
#include "mcontext.h"
#include "iheader.h"
#include "domainstatistic.h"
int DnsGenerator_Init(DnsGenerator *g, char *Buffer, int BufferLength, const char *CopyFrom, int SourceLength, BOOL Strip)
{ (void)g;(void)Buffer;(void)BufferLength;(void)CopyFrom;(void)SourceLength;(void)Strip; return -1; }
int DNSCompress(char *DNSBody, int DNSBodyLength){ (void)DNSBody;(void)DNSBodyLength; return -1; }
int MsgContext_SendBack(MsgContext *MsgCtx){ (void)MsgCtx; return 0; }
void ShowNormalMessage(IHeader *h, char Protocol){ (void)h;(void)Protocol; }
int DomainStatistic_Add(IHeader *h, StatisticType Type){ (void)h;(void)Type; return 0; }
EOF

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" \
    "$Root/test/dnscache_shutdown_race/main.c" \
    "$Root/cacheht.c" \
    "$Root/array.c" \
    "$Root/cachettlcrtl.c" \
    "$Root/stringchunk.c" \
    "$Root/stringlist.c" \
    "$Root/simpleht.c" \
    "$Root/stablebuffer.c" \
    "$Root/utils.c" \
    "$Root/dnsparser.c" \
    "$Root/dnsrelated.c" \
    "$TmpDir/logs_stub.c" \
    "$TmpDir/addr_stub.c" \
    "$TmpDir/conf_stub.c" \
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
