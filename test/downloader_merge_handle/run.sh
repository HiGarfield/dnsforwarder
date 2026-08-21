#!/bin/sh
# Build and run the downloader merge-loop FILE-handle regression test.
#
# Part 1 (structural): the merge loop in GetFromInternet_MultiFiles() must
# call fclose() on every path after fopen(TempFile, "a+").  The old code
# `if( fputc(...) == EOF || fclose(fp) != 0 ) break;` skipped fclose() when
# fputc() itself failed.  With buffered stdio fputc() of the first byte
# cannot fail, but the structure must not silently lose the descriptor if
# that ever changes (e.g. an unbuffered stream or a pre-flushed buffer).
#
# Part 2 (runtime): run the merge loop 50 times against a temp file that
# cannot take the separator byte (RLIMIT_FSIZE + SIGXFSZ, so the final
# write fails with EFBIG at fclose/flush time) and assert the process does
# not accumulate file descriptors across the runs.
#
# Usage:
#   sh test/downloader_merge_handle/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/downloader_merge_handle/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_downloader_merge_handle

echo "Part 1: every path after fopen(TempFile, \"a+\") must fclose"
python3 - "$Root/downloader.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
# Drop every comment first (the doc comments describe the old buggy
# short-circuit and would otherwise trip the scan below).
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

# Locate the merge loop body: find fopen(TempFile, "a+")
start = next((n for n, l in enumerate(lines)
              if 'fopen(TempFile, "a+")' in l), None)
if start is None:
    print('  [FAIL] fopen(TempFile, "a+") not found; test is stale')
    sys.exit(1)

# The block right after the successful fopen is:
#   if ( fputc(...) == EOF ) { fclose(fp); break; }
#   if ( fclose(fp) != 0 ) break;
# Every path between the successful fopen and the loop's next iteration
# must contain exactly one fclose(fp) and no short-circuit skip.
end = None
for n in range(start + 1, min(len(lines), start + 40)):
    if re.match(r'^\s*\+\+URLs;', lines[n]):
        end = n
        break
if end is None:
    print('  [FAIL] could not find the end of the merge-loop block')
    sys.exit(1)

block = lines[start + 1:end]
# Drop // comments (/* ... */ were already removed above).
block = [l.split('//')[0] for l in block]
fcloses = [l for l in block if 'fclose(fp)' in l]
buggy = [l for l in block if 'fputc' in l and '||' in l]

if not fcloses:
    print('  [FAIL] no fclose(fp) after fopen(TempFile, "a+")')
    sys.exit(1)
if buggy:
    print('  [FAIL] short-circuit `fputc(...) || fclose(...)` can skip fclose')
    sys.exit(1)
print('  [ ok ] fclose(fp) is reached on every path after fopen')
sys.exit(0)
PY

echo "Part 2: no descriptor growth across 50 failing merge runs"
${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" \
    "$Root/test/downloader_merge_handle/main.c" \
    "$Root/downloader.c" \
    -lpthread

"$Out"
