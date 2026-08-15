#!/bin/sh
# Build and run the short-read / short-write regression test under ASan/UBSan.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_shortio

TmpDir=$(mktemp -d)
trap 'rm -rf "$TmpDir"' EXIT

cat > "$TmpDir/stubs.c" <<'EOF'
#include "common.h"
int Log_Init(void *c, int p, int d){ (void)c;(void)p;(void)d; return 0; }
int Log_Inited(void){ return 1; }
int Log_DebugOn(void){ return 0; }
void Log_Print(const char *t, const char *f, ...){ (void)t;(void)f; }
int AddressList_ConvertFromString(void *a, const char *s, int p){ (void)a;(void)s;(void)p; return 0; }
EOF

${CC:-cc} -I"$Root" -g -fsanitize=address,undefined -o "$Out" \
    "$Root/test/shortio/main.c" \
    "$Root/utils.c" \
    "$TmpDir/stubs.c" \
    -lpthread -lm

"$Out"
