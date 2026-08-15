#!/bin/sh
# Build and run the CacheHT free-list / NodeChunk consistency regression test.
#
# The crash only reproduces as a NULL-pointer dereference inside the parser's
# free-list walk, so run it under AddressSanitizer to turn that into a hard
# failure (a plain run would just segfault and the shell would report non-zero,
# which is also acceptable, but ASan gives a precise diagnosis).
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_cacheht

# log.c pulls in large parts of the project (config, dnsparser, ...). For this
# standalone unit test we only need the DEBUG/Log_* symbols, so provide stubs.
# Same for AddressList_ConvertFromString, referenced by utils.c.
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

${CC:-cc} -I"$Root" -g -fsanitize=address,undefined -Wall -o "$Out" \
    "$Root/test/cacheht/main.c" \
    "$Root/cacheht.c" \
    "$Root/array.c" \
    "$Root/utils.c" \
    "$TmpDir/logs_stub.c" \
    "$TmpDir/addr_stub.c" \
    -lpthread -lm

"$Out"
rc=$?
rm -rf "$TmpDir"
exit $rc
