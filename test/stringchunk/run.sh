#!/bin/sh
# Build and run the StringChunk regression test under ASan/UBSan.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_stringchunk

TmpDir=$(mktemp -d)
trap 'rm -rf "$TmpDir"' EXIT

# stringchunk.c pulls in the logging and address-list symbols through utils.c /
# stringlist.c; stub them so the test links standalone.
cat > "$TmpDir/stubs.c" <<'EOF'
#include "common.h"
int Log_Init(void *c, int p, int d){ (void)c;(void)p;(void)d; return 0; }
int Log_Inited(void){ return 1; }
int Log_DebugOn(void){ return 0; }
void Log_Print(const char *t, const char *f, ...){ (void)t;(void)f; }
int AddressList_ConvertFromString(void *a, const char *s, int p){ (void)a;(void)s;(void)p; return 0; }
EOF

${CC:-cc} -I"$Root" -g -fsanitize=address,undefined -o "$Out" \
    "$Root/test/stringchunk/nulldata.c" \
    "$Root/stringchunk.c" \
    "$Root/stringlist.c" \
    "$Root/stablebuffer.c" \
    "$Root/array.c" \
    "$Root/simpleht.c" \
    "$Root/utils.c" \
    "$TmpDir/stubs.c" \
    -lpthread -lm

"$Out"
