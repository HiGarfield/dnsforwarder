#!/bin/sh
set -e
# Build and run the array integer-overflow regression test (Windows/MinGW).
Root="$(cd "$(dirname "$0")/../.." && pwd -P)"
Out="${Root}/_t_array_overflow.exe"
${CC:-gcc} -g -O2 -DWIN32_LEAN_AND_MEAN -I"${Root}" \
    "${Root}/test/array_overflow/main.c" \
    "${Root}/array.c" "${Root}/utils.c" "${Root}/addresslist.c" \
    -lws2_32 -lpthread -lm -o "${Out}"
"${Out}"
