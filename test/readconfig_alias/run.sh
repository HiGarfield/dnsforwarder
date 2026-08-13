#!/bin/sh
set -e
# Build and run the config alias-resolution regression test (Windows/MinGW).
Root="$(cd "$(dirname "$0")/../.." && pwd -P)"
Out="${Root}/_t_readconfig_alias.exe"
${CC:-gcc} -g -O2 -DWIN32_LEAN_AND_MEAN -I"${Root}" \
    "${Root}/test/readconfig_alias/main.c" \
    "${Root}/readconfig.c" "${Root}/stringchunk.c" "${Root}/stringlist.c" \
    "${Root}/array.c" "${Root}/stablebuffer.c" "${Root}/bst.c" "${Root}/simpleht.c" \
    "${Root}/utils.c" "${Root}/addresslist.c" "${Root}/readline.c" \
    "${Root}/test/readconfig_alias/logs_stub.c" \
    -lws2_32 -lshlwapi -lpthread -lm -o "${Out}"
"${Out}"
