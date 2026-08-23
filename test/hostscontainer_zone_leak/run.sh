#!/bin/sh
# Build and run the HostsContainer Zone-leak regression test under ASan/UBSan.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Out=${TMPDIR:-/tmp}/dnsforwarder_test_hostscontainer_zone_leak
TmpDir=$(mktemp -d)
trap 'rm -rf "$TmpDir"' EXIT

# hostscontainer.c -> stringchunk.c -> utils.c references AddressList_ConvertFromString,
# which the production daemon provides from addresslist.c.  Stub it here so the
# unit test links standalone (the test never reaches that code path).
cat > "$TmpDir/stubs2.c" <<'EOF'
#include "common.h"
sa_family_t AddressList_ConvertFromString(void *Out, const char *Addr_Port, int DefaultPort)
{ (void)Out; (void)Addr_Port; (void)DefaultPort; return 0; }
EOF

Sources="
$Root/test/hostscontainer_zone_leak/main.c
$Root/hostscontainer.c
$Root/stringchunk.c
$Root/stringlist.c
$Root/stablebuffer.c
$Root/array.c
$Root/simpleht.c
$Root/ipchunk.c
$Root/bst.c
$Root/utils.c
$Root/test/stubs.c
$TmpDir/stubs2.c
"

${CC:-cc} -I"$Root" -g -fsanitize=address,undefined -o "$Out" $Sources -lpthread -lm

# Keep ASan/UBSan memory-error detection but skip the end-of-run leak scan,
# which can hang in some containerised environments.
if [ -z "${ASAN_OPTIONS:-}" ]; then
    ASAN_OPTIONS=detect_leaks=0
    export ASAN_OPTIONS
fi
"$Out"
