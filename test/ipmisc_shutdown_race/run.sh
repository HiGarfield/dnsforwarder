#!/bin/sh
# Build and run the ipmisc shutdown-cleanup race regression test.
#
# Part 1 (structural): IpMiscMapping_Cleanup() must free CurrIpMiscMapping
# under the write lock and NULL the pointer -- and must NOT destroy
# IpMiscMappingLock -- because atexit LIFO order runs this handler before
# Modules_Cleanup() stops the module workers: IPMiscMapping_Process() may
# still be running.  The body must carry a comment explaining that rationale.
#
# Part 2 (runtime): a worker thread keeps calling the real
# IPMiscMapping_Process() on a DNS answer containing a blocked 1.2.3.4 A
# record; IpMiscMapping_Cleanup() runs while the thread is live, and the
# thread then calls Process() once more.  The old cleanup freed the mapping
# without the lock and destroyed the lock, so that final call is a
# heap-use-after-free (ASan catches it) or locks a destroyed rwlock; the new
# one NULLs the pointer under the lock so the worker gets IP_MISC_NOTHING.
#
# Usage:
#   sh test/ipmisc_shutdown_race/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/ipmisc_shutdown_race/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_ipmisc_shutdown_race

echo "Part 1: IpMiscMapping_Cleanup frees under the lock and NULLs the pointer"
python3 - "$Root/ipmisc.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'IpMiscMapping_Cleanup(void)' in l), None)
if start is None:
    print('  [FAIL] IpMiscMapping_Cleanup not found; test is stale')
    sys.exit(1)

end = next((n for n in range(start, len(lines))
            if lines[n].startswith('}') and n > start), None)
if end is None:
    print('  [FAIL] could not find the end of IpMiscMapping_Cleanup')
    sys.exit(1)
body = '\n'.join(lines[start:end + 1])

for banned, why in (
    ('RWLock_Destroy', 'destroying the lock races module workers'),
):
    if banned in body:
        print('  [FAIL] IpMiscMapping_Cleanup still contains %s (%s)' % (banned, why))
        sys.exit(1)
if 'RWLock_WrLock' not in body:
    print('  [FAIL] IpMiscMapping_Cleanup does not take the write lock')
    sys.exit(1)
if 'CurrIpMiscMapping = NULL' not in body:
    print('  [FAIL] IpMiscMapping_Cleanup does not NULL the pointer')
    sys.exit(1)
free_at = body.find('IpMiscMapping_Free')
lock_at = body.find('RWLock_WrLock')
if free_at < 0 or free_at < lock_at:
    print('  [FAIL] IpMiscMapping_Cleanup frees before taking the write lock')
    sys.exit(1)
print('  [ ok ] IpMiscMapping_Cleanup frees under the lock and NULLs the pointer')
sys.exit(0)
PY

echo "Part 2: mapping pointer visible as NULL after cleanup runs"
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
# dnsparser.c / dnsrelated.c reference these (not exercised here); provide
# stubs so the link is complete without dragging in iheader.c / mcontext.c.
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

# main.c #includes ipmisc.c itself (static-export trick), so ipmisc.c is NOT
# linked separately here.  The dependency chain (ipchunk/bst/stablebuffer/
# stringchunk/stringlist/array/simpleht/utils/readline/dnsparser/dnsrelated)
# is linked in, with stubs for the config/log helpers that those units
# reference but this test does not exercise.
${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" \
    "$Root/test/ipmisc_shutdown_race/main.c" \
    "$Root/ipchunk.c" \
    "$Root/bst.c" \
    "$Root/stablebuffer.c" \
    "$Root/stringchunk.c" \
    "$Root/stringlist.c" \
    "$Root/array.c" \
    "$Root/simpleht.c" \
    "$Root/utils.c" \
    "$Root/readline.c" \
    "$Root/dnsparser.c" \
    "$Root/dnsrelated.c" \
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
