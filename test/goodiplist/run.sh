#!/bin/sh
# Regression test for the goodiplist "fastest-IP swap" overlap bug.
#
# Builds twice under ASan+UBSan:
#   1) -DGI_USE_MEMCPY  -> old, broken memcpy() path. The partial-overlap
#      rotate MUST fail (memcpy corrupts overlapping regions -> proves the
#      defect is real and memmove is required).
#   2) default          -> fixed memmove() path. MUST pass cleanly (no
#      regression; self-swap and rotate both correct).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
CC="${CC:-cc}"
SAN_FLAGS="${SAN_FLAGS:--fsanitize=address,undefined -O0 -g -Wall -fno-sanitize-recover=all}"

cat > "$DIR/_stub_utils.c" <<'EOF'
#include <stdlib.h>
#include "common.h"
int SafeRealloc(void **Memory_ptr, size_t NewBytes) {
    void *New = realloc(*Memory_ptr, NewBytes);
    if (New != NULL) { *Memory_ptr = New; return 0; }
    return -1;
}
EOF

# ---- Build 1: old memcpy path must fail on partial overlap ----
OUT_OLD="$DIR/goodiplist_memcpy"
"$CC" $SAN_FLAGS -DGI_USE_MEMCPY -I"$ROOT" -o "$OUT_OLD" \
    "$DIR/main.c" "$ROOT/array.c" "$DIR/_stub_utils.c"

if "$OUT_OLD" >/dev/null 2>&1; then
    echo "UNEXPECTED: old memcpy path produced correct output (defect not reproduced)"
    exit 1
fi
echo "OK: old memcpy path fails on overlapping copy (defect reproduced)"

# ---- Build 2: fixed memmove path must pass cleanly ----
OUT_NEW="$DIR/goodiplist_memmove"
"$CC" $SAN_FLAGS -I"$ROOT" -o "$OUT_NEW" \
    "$DIR/main.c" "$ROOT/array.c" "$DIR/_stub_utils.c"

if ! "$OUT_NEW"; then
    echo "FAIL: fixed memmove path did not pass"
    exit 1
fi
echo "OK: fixed memmove path passes cleanly"

rm -f "$DIR/_stub_utils.c" "$OUT_OLD" "$OUT_NEW"
echo "GOODIPLIST_OVERLAP_TEST_PASSED"
