#!/bin/sh
# Regression test for the unchecked GetDefaultConfigureFile() call in
# main.c (Round-8 review).
#
# Bug: when no config file was given on the command line, main() called
# GetDefaultConfigureFile() but ignored its return value.  On failure the
# function empties the buffer, so the program silently continued with an
# empty config path (bogus working directory, confusing error output).
#
# Fix: the call must be checked and the program must abort with a clear
# message when the default config file cannot be located.
#
# Usage:
#   sh test/main_getdefaultconfig/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

echo "Part 1: GetDefaultConfigureFile result is checked in main()"
python3 - "$Root/main.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'GetDefaultConfigureFile(ConfigFile, 320)' in l), None)
if start is None:
    print('  [FAIL] GetDefaultConfigureFile call not found; test is stale')
    sys.exit(1)

# The call must be wrapped in an if (...) != 0 check.
if not lines[start].lstrip().startswith('if( GetDefaultConfigureFile('):
    print('  [FAIL] GetDefaultConfigureFile return value is not checked')
    sys.exit(1)

branch = '\n'.join(lines[start:start + 6])
if 'Failed to locate the default configure file' not in branch:
    print('  [FAIL] failure branch has no clear error message')
    sys.exit(1)
print('  [ ok ] GetDefaultConfigureFile failure is handled')
sys.exit(0)
PY
