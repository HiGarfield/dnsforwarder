#!/bin/sh
# Regression tests for the round-1 bug fixes.
# Each test proves a specific bug is fixed.  Build & run with gcc (no ASan lib
# on this MinGW toolchain, so we rely on UBSan-free logic tests + valgrind on
# supported platforms).
set -e
cd "$(dirname "$0")"

echo "=== Bug #1: DNSLabelMakePointer compression-pointer encoding ==="
gcc -O2 -Wall -Wextra -I../.. dnslabel_pointer_test.c -o dnslabel_pointer_test
./dnslabel_pointer_test

echo
echo "=== Bug #2: TcpM_Send_Actual use-after-free (value-copy proof) ==="
gcc -O2 -Wall -Wextra tcpm_uaf_repro.c -o tcpm_uaf_repro
./tcpm_uaf_repro

echo
echo "=== Bug #3: FilterType_Init memory leak on iterator-init failure ==="
gcc -O2 -Wall -Wextra filter_leak_repro.c -o filter_leak_repro
./filter_leak_repro

echo
echo "=== Bug #4: ConfigSetDefaultValue NULL-string crash ==="
gcc -O2 -Wall -Wextra readconfig_null_repro.c -o readconfig_null_repro
./readconfig_null_repro

echo
echo "ALL ROUND-1 REGRESSION TESTS PASSED"
