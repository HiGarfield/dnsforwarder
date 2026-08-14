#!/bin/sh
# Regression test for simpleht.c: standalone compilation must succeed even
# when no other project source drags <stdint.h> (SIZE_MAX) into scope.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
CC="${CC:-cc}"
Out="$DIR/simpleht_test"
"$CC" -I"$ROOT" ${SAN_FLAGS:--g -Wall} -o "$Out" "$DIR/main.c" "$ROOT/simpleht.c" "$ROOT/array.c" "$ROOT/utils.c" "$ROOT/addresslist.c" -lpthread
"$Out"
