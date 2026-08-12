#!/bin/sh
# Regression test for the TCP frontend accept() path.
#
# TcpFrontend_Init must register the listening socket with AF_UNSPEC so that
# TcpFrontend_Work recognises it as a listener and calls accept() on it. A
# previous bug registered it with the real family, making the accept() branch
# dead code: the worker then called recv() on the bare listening socket (which
# is in LISTEN state and always errors), so TCP queries were never answered.
#
# This test launches the daemon with a TCPLocal interface and a hosts entry,
# then sends a TCP DNS query and asserts a response is received.
#
# Usage:
#   sh test/tcpfrontend/tcp_test.sh
#
# Requires the built dnsforwarder binary and python3.

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DnsF="$Root/dnsforwarder"
Conf=/tmp/dnsf_tcp.conf
RunLog=/tmp/dnsf_tcp.run

if [ ! -x "$DnsF" ]; then
    echo "dnsforwarder binary not built at $DnsF; run 'make' first." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not installed; skipping." >&2
    exit 0
fi

cat > "$Conf" <<'EOF'
Log 5
LogFile /tmp/dnsf_tcp.log
TCPLocal 127.0.0.1:15354
AppendHosts test.tcponly.com 10.20.30.40
EOF

# Launch the daemon in the background.
"$DnsF" -f "$Conf" >"$RunLog" 2>&1 &
DPID=$!

# Give the daemon a moment to bind the TCP interface.
sleep 2

# Send a TCP DNS query and check we get a full response (2-byte length prefix
# followed by a DNS message). With the bug, recv() on the listen socket fails
# and the daemon never replies, so this times out.
python3 - <<'PY'
import socket, struct, time, sys
def build_query(name, qid):
    parts = name.split('.')
    qname = b''.join(bytes([len(p)]) + p.encode() for p in parts) + b'\x00'
    hdr = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    return hdr + qname + struct.pack('>HH', 1, 1)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('127.0.0.1', 15354))
    q = build_query('test.tcponly.com', 0x2000)
    s.sendall(struct.pack('>H', len(q)) + q)
    # Read the 2-byte length prefix.
    lenb = b''
    while len(lenb) < 2:
        chunk = s.recv(2 - len(lenb))
        if not chunk:
            print("FAILED: connection closed before any response (accept path broken)")
            sys.exit(1)
        lenb += chunk
    total = struct.unpack('>H', lenb)[0]
    if total < 12:
        print("FAILED: response too short (%d bytes)" % total)
        sys.exit(1)
    # Read the rest of the DNS message.
    body = b''
    while len(body) < total:
        chunk = s.recv(total - len(body))
        if not chunk:
            break
        body += chunk
    print("OK: received %d-byte TCP DNS response" % (total + 2))
except socket.timeout:
    print("FAILED: timed out waiting for TCP DNS response (accept path broken)")
    sys.exit(1)
finally:
    s.close()
PY
RC=$?

kill -TERM "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true

if [ "$RC" -ne 0 ]; then
    echo "tcpfrontend TCP query test FAILED" >&2
    exit 1
fi

echo "tcpfrontend TCP accept path: OK"
exit 0
