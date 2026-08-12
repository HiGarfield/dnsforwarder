#!/bin/sh
# Regression test for the infinite loop in MsgContext_AddFakeEdns().
#
# With "AP true" every outgoing query goes through MsgContext_AddFakeEdns(),
# which used to walk the record counters with
#
#     while( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ADDITIONAL );
#
# DnsGenerator_Init() leaves the counter on the *last non-empty* section of the
# copied request. For a query that already has ARCOUNT > 0 that section is
# ADDITIONAL, so the first NextPurpose() steps *past* the additional counter and
# every following call returns UNKNOWN without moving: the loop never ends and
# the frontend thread spins at 100% CPU, killing the whole forwarder.
#
# The test forwards a normal query (must work), then a query carrying a non-OPT
# additional record, then a normal query again. Before the fix the third query
# times out because the UDP frontend thread is stuck.
#
# Usage:
#   sh test/fakeedns_hang/run.sh
#
# Requires the built dnsforwarder binary and python3.

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DnsF="$Root/dnsforwarder"
Conf=/tmp/dnsf_fakeedns_hang.conf
RunLog=/tmp/dnsf_fakeedns_hang.run

LocalPort=15374
UpstreamPort=15375

if [ ! -x "$DnsF" ]; then
    echo "dnsforwarder binary not built at $DnsF; run 'make' first." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not installed; skipping." >&2
    exit 0
fi

cat > "$Conf" <<EOF
Log 5
LogFile /tmp/dnsf_fakeedns_hang.log
AP true
UseCache false
UDPLocal 127.0.0.1:$LocalPort
TCPLocal
UDPGroup 127.0.0.1:$UpstreamPort * on
TCPGroup
EOF

# Minimal upstream that answers every query with one A record. "AP true" makes
# dnsforwarder discard replies without an OPT record, so add one.
cat > /tmp/dnsf_fakeedns_upstream.py <<PY
import socket, struct, sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $UpstreamPort))
sys.stderr.write('upstream ready\n')
sys.stderr.flush()

while True:
    try:
        data, peer = s.recvfrom(4096)
    except OSError:
        break
    if len(data) < 12:
        continue
    qid = data[:2]
    # Locate the end of QNAME to echo the question back verbatim.
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    end = i + 1 + 4
    question = data[12:end]
    header = qid + struct.pack('>HHHHH', 0x8180, 1, 1, 0, 1)
    answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + bytes([10, 20, 30, 42])
    opt = b'\x00' + struct.pack('>HHIH', 41, 1280, 0, 0)
    s.sendto(header + question + answer + opt, peer)
PY

python3 /tmp/dnsf_fakeedns_upstream.py 2>/dev/null &
UPID=$!

"$DnsF" -f "$Conf" >"$RunLog" 2>&1 &
DPID=$!

Cleanup() {
    kill -TERM "$DPID" 2>/dev/null || true
    kill -TERM "$UPID" 2>/dev/null || true
    sleep 1
    kill -KILL "$DPID" 2>/dev/null || true
    kill -KILL "$UPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
    wait "$UPID" 2>/dev/null || true
}
trap Cleanup EXIT HUP INT TERM

sleep 2

set +e
LocalPort=$LocalPort python3 - <<'PY'
import os, socket, struct, sys

Port = int(os.environ['LocalPort'])


def qname(name):
    return b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'


def plain_query(name, qid):
    return (struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
            + qname(name) + struct.pack('>HH', 1, 1))


def query_with_additional(name, qid):
    """QDCOUNT=1, ARCOUNT=1 where the additional record is an A RR, not OPT."""
    extra = qname('extra.example') + struct.pack('>HHIH', 1, 1, 0, 4) \
        + bytes([192, 0, 2, 9])
    return (struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 1)
            + qname(name) + struct.pack('>HH', 1, 1) + extra)


def ask(payload, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, ('127.0.0.1', Port))
        return s.recv(4096)
    except socket.timeout:
        return None
    finally:
        s.close()


if ask(plain_query('first.example.com', 0x1001)) is None:
    print("SKIP: the forwarder did not answer the initial plain query, "
          "the test environment is not usable")
    sys.exit(0)
print("ok: plain query answered")

# This one used to make MsgContext_AddFakeEdns() spin forever.
ask(query_with_additional('hang.example.com', 0x1002), timeout=3.0)

# The frontend thread must still be alive and serving.
if ask(plain_query('third.example.com', 0x1003)) is None:
    print("FAILED: no answer after a query carrying additional records; "
          "MsgContext_AddFakeEdns() is stuck in an endless loop")
    sys.exit(1)

print("ok: still serving after a query carrying additional records")
sys.exit(0)
PY
RC=$?
set -e

if [ "$RC" -ne 0 ]; then
    echo "fake EDNS hang test FAILED" >&2
    exit 1
fi

echo "MsgContext_AddFakeEdns loop termination: OK"
exit 0
