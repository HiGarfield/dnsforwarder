#!/bin/sh
# End-to-end helgrind check for the GoodIpList concurrency fix.
#
# GoodIpList_Get() (request-handling thread) reads ListInfo.List while the
# list-measurement task ThreadJod (TimedTask thread) rewrites the same array.
# Both must be serialized by ListLock. This script launches the real daemon
# with a GoodIPList config and fires concurrent DNS queries, then asserts that
# helgrind reports zero data races.
#
# Usage:
#   sh test/goodiplist/helgrind.sh
#
# Requires valgrind/helgrind on PATH. Exits non-zero if any race is reported.
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DnsF="$Root/dnsforwarder"
Conf=/tmp/dnsf_goodip_hg.conf
HgLog=/tmp/dnsf_goodip_hg.log
RunLog=/tmp/dnsf_goodip_hg.run

if [ ! -x "$DnsF" ]; then
    echo "dnsforwarder binary not built at $DnsF; run 'make' first." >&2
    exit 1
fi

if ! command -v valgrind >/dev/null 2>&1; then
    echo "valgrind/helgrind not installed; skipping." >&2
    exit 0
fi

cat > "$Conf" <<'EOF'
Log 5
LogFile /tmp/dnsf_goodip_hg.log
UDPLocal 127.0.0.1:15353
GoodIPList list1 300
GoodIPListAddIP list1 127.0.0.1:22
AppendHosts <list1 test.goodip.com
EOF

# Launch under helgrind in the background.
valgrind --tool=helgrind --log-file="$HgLog" --error-exitcode=99 \
    "$DnsF" -f "$Conf" >"$RunLog" 2>&1 &
DPID=$!

# Give the daemon a moment to bind and start the timed task.
sleep 2

# Fire concurrent DNS queries that trigger GoodIpList_Get().
python3 - <<'PY'
import socket, struct, time
def build_query(name, qid):
    parts = name.split('.')
    qname = b''.join(bytes([len(p)]) + p.encode() for p in parts) + b'\x00'
    hdr = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    return hdr + qname + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
for i in range(8):
    try:
        s.sendto(build_query('test.goodip.com', 0x1000 + i), ('127.0.0.1', 15353))
        s.recvfrom(4096)
    except Exception:
        pass
    time.sleep(0.25)
s.close()
PY

# Let ThreadJod run a few more measurement cycles to maximize overlap.
sleep 2

kill -TERM "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true

if grep -q "Possible data race" "$HgLog"; then
    echo "FAILED: helgrind reported a data race for GoodIpList:" >&2
    grep -A6 "Possible data race" "$HgLog" >&2
    exit 1
fi

echo "GoodIpList helgrind check: 0 data races"
exit 0
