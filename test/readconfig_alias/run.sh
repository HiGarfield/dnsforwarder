#!/bin/sh
set -e
# Build and run the config alias-resolution regression test.  The test code is
# pure ISO C; -lws2_32/-lshlwapi were only meaningful when cross-compiling for
# MinGW, and on Linux the link used to fail with "cannot find -lws2_32 /
# -lshlwapi".  Link the Windows libs only on Windows toolchains.
Root="$(cd "$(dirname "$0")/../.." && pwd -P)"
Out="${Root}/_t_readconfig_alias"
LIBS="-lpthread -lm"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) LIBS="-lws2_32 -lshlwapi $LIBS"; Out="${Out}.exe" ;;
esac
${CC:-gcc} -g -O2 -DWIN32_LEAN_AND_MEAN -I"${Root}" \
    "${Root}/test/readconfig_alias/main.c" \
    "${Root}/readconfig.c" "${Root}/stringchunk.c" "${Root}/stringlist.c" \
    "${Root}/array.c" "${Root}/stablebuffer.c" "${Root}/bst.c" "${Root}/simpleht.c" \
    "${Root}/utils.c" "${Root}/addresslist.c" "${Root}/readline.c" \
    "${Root}/test/readconfig_alias/logs_stub.c" \
    $LIBS -o "${Out}"
"${Out}"
