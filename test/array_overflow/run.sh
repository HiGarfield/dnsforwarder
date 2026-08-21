#!/bin/sh
set -e
# Build and run the array integer-overflow regression test.  The test code is
# pure ISO C; -lws2_32 was only meaningful when cross-compiling for MinGW, and
# on Linux the link used to fail with "cannot find -lws2_32".  Link the
# Windows socket lib only on Windows toolchains.
Root="$(cd "$(dirname "$0")/../.." && pwd -P)"
Out="${Root}/_t_array_overflow"
LIBS="-lpthread -lm"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) LIBS="-lws2_32 $LIBS"; Out="${Out}.exe" ;;
esac
${CC:-gcc} -g -O2 -DWIN32_LEAN_AND_MEAN -I"${Root}" \
    "${Root}/test/array_overflow/main.c" \
    "${Root}/array.c" "${Root}/utils.c" "${Root}/addresslist.c" \
    $LIBS -o "${Out}"
"${Out}"
