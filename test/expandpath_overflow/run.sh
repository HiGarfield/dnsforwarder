#!/bin/sh
# Regression test for the ExpandPath() silent-failure bug (Round-7 review).
#
# Part 1 (structural): the POSIX wordexp branch must reject an expansion
# that does not fit into BufferLength (return -1) instead of silently
# skipping the copy and returning success.
#
# Part 2 (runtime): a plain path expands successfully; "$PATH" into a
# small buffer must fail without touching the buffer.
#
# Usage:
#   sh test/expandpath_overflow/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/expandpath_overflow/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_expandpath_overflow

echo "Part 1: ExpandPath rejects an oversized expansion (POSIX branch)"
python3 - "$Root/utils.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'strlen(Result.we_wordv[0])' in l), None)
if start is None:
    print('  [FAIL] wordexp expansion not found; test is stale')
    sys.exit(1)

branch = '\n'.join(lines[start - 2:start + 10])
if '> BufferLength' not in branch:
    print('  [FAIL] POSIX branch has no BufferLength overflow check')
    sys.exit(1)
if 'return -1' not in branch:
    print('  [FAIL] POSIX branch does not fail on overflow (silent success)')
    sys.exit(1)
print('  [ ok ] oversized expansion is reported as failure')
sys.exit(0)
PY

echo "Part 3: Base64Decode OpenSSL branch compiles (dead code, must not rot)"
if [ -f /usr/include/openssl/bio.h ]; then
    if ${CC:-cc} -fsyntax-only -DBASE64_DECODER_OPENSSL -DMASKED "$Root/utils.c" \
        > /tmp/dnsf_expandpath_openssl.log 2>&1; then
        echo "  [ ok ] BASE64_DECODER_OPENSSL branch passes a syntax check"
    else
        echo "  [FAIL] BASE64_DECODER_OPENSSL branch has a syntax error:"
        head -5 /tmp/dnsf_expandpath_openssl.log
        exit 1
    fi
else
    echo "  [skip] openssl headers not present"
fi

echo "Part 2: runtime behavior"
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

# utils.c only needs HAVE_WORDEXP for the branch under test; -DHAVE_WORDEXP
# also exposes the wordexp() dependency, which is plain libc.
${CC:-cc} -I"$Root" -g -Wall -DHAVE_WORDEXP $CFLAGS -o "$Out" \
    "$Root/test/expandpath_overflow/main.c" \
    "$Root/utils.c" \
    "$TmpDir/logs_stub.c" \
    "$TmpDir/addr_stub.c" \
    "$TmpDir/conf_stub.c" \
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
