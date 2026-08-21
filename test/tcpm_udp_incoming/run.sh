#!/bin/sh
# Regression test for two Round-9 findings in tcpm.c.
#
# 1) TcpM_Works()'s UDP-incoming branch read the datagram into
#    ReceiveBuffer (the IHeader slot) but then told IHeader_Fill() to parse
#    at ReceiveBuffer + sizeof(IHeader) with a length reduced by
#    sizeof(IHeader): it parsed a shifted/truncated payload (the real DNS
#    query was in the header slot) and could pass a negative length into
#    the parser.  It must read into the Entity slot and parse from there,
#    exactly like UdpFrontend_Work does.
#
# 2) TcpM_Connect() re-seeded the PRNG on every call with
#    srand(time(NULL)); all connections made within one second then got the
#    same Shift.  It must seed only once.
#
# Usage:
#   sh test/tcpm_udp_incoming/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

echo "Part 1: UDP-incoming datagram lands in the Entity slot"
python3 - "$Root/tcpm.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'State = recvfrom(s,' in l), None)
if start is None:
    print('  [FAIL] UDP-incoming recvfrom not found; test is stale')
    sys.exit(1)

recv = '\n'.join(lines[start:start + 6])
if 'ReceiveBuffer' in recv:
    print('  [FAIL] recvfrom targets ReceiveBuffer (header slot) instead of Entity')
    sys.exit(1)
if 'Entity,' not in recv:
    print('  [FAIL] recvfrom does not target the Entity slot')
    sys.exit(1)

# The IHeader_Fill call right after must parse from Entity with the full
# State length.
fill = '\n'.join(lines[start:start + 34])
if 'ReceiveBuffer + sizeof(IHeader)' in fill:
    print('  [FAIL] IHeader_Fill parses from ReceiveBuffer+sizeof(IHeader) (shifted payload)')
    sys.exit(1)
if 'Entity,' not in fill or 'State,' not in fill:
    print('  [FAIL] IHeader_Fill does not parse from Entity with full State length')
    sys.exit(1)
print('  [ ok ] datagram read into Entity and parsed from offset 0')
sys.exit(0)
PY

echo "Part 2: PRNG is seeded only once in TcpM_Connect"
python3 - "$Root/tcpm.c" <<'PY'
import re, sys

src = open(sys.argv[1]).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
lines = src.split('\n')

start = next((n for n, l in enumerate(lines)
              if 'static BOOL Seeded = FALSE' in l), None)
if start is None:
    print('  [FAIL] seed-once guard not found; test is stale')
    sys.exit(1)

block = '\n'.join(lines[start - 2:start + 10])
if 'srand(' not in block:
    print('  [FAIL] no srand() call inside the seed-once guard')
    sys.exit(1)
if 'Seeded == FALSE' not in block or 'Seeded = TRUE' not in block:
    print('  [FAIL] seed-once guard is incomplete')
    sys.exit(1)
print('  [ ok ] srand() guarded by a one-time flag')
sys.exit(0)
PY
