#!/bin/sh
# Build and run the mmgr partial group-file reload failure regression tests.
#
# Usage:
#   sh test/mmgr_load_failure/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/mmgr_load_failure/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_mmgr_load_failure

Sources="
$Root/test/mmgr_load_failure/main.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/array.c
$Root/stringlist.c
$Root/readline.c
$Root/addresslist.c
$Root/utils.c
$Root/test/stubs.c
"

# The production sources compiled into this unit test need the Windows socket
# and shell-path-matching libraries on MinGW/MSVC; on POSIX those symbols live
# in libc.
case "$(uname -s)" in
    *Windows_NT*|MINGW*|MSYS*)
        LIBS="-lws2_32 -lshlwapi -lpthread" ;;
    *)
        LIBS="-lpthread" ;;
esac

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources $LIBS

# LeakSanitizer's end-of-run scan hangs in some containerised environments;
# keep ASan/UBSan's memory-error detection but skip the leak scan there.
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi

# The pre-fix build hangs here (the worker thread spins on freed memory, or
# Modules_SafeCleanup spins on the uninitialized lock); a timeout turns that
# hang into a failure so the bug stays detectable in CI.
if command -v timeout >/dev/null 2>&1; then
    timeout 30 "$Out"
else
    "$Out"
fi
