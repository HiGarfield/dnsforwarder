#!/bin/sh
# Regression test for TcpFrontend_Init() aborting on a listen() failure.
#
# A failing listen() only concerns the interface being set up, exactly like a
# failing socket() or bind(). The buggy code did "break" instead of
# "CLOSE_SOCKET(sock); continue;", so one bad interface leaked its descriptor
# and silently discarded every remaining TCPLocal entry.
#
# The test configures two TCPLocal interfaces and uses an LD_PRELOAD shim that
# makes the first listen() call fail. The second interface must still end up
# listening and answering TCP DNS queries.
#
# Usage:
#   sh test/tcpfrontend_listen_fail/run.sh
#
# Requires the built dnsforwarder binary and python3.

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DnsF="$Root/dnsforwarder"
Conf=/tmp/dnsf_tcp_listenfail.conf
RunLog=/tmp/dnsf_tcp_listenfail.run
Shim=/tmp/dnsf_fail_first_listen.so

if [ ! -x "$DnsF" ]; then
    echo "dnsforwarder binary not built at $DnsF; run 'make' first." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not installed; skipping." >&2
    exit 0
fi

${CC:-cc} -shared -fPIC -O0 -o "$Shim" \
    "$Root/test/tcpfrontend_listen_fail/fail_first_listen.c" -ldl

cat > "$Conf" <<'EOF'
Log 5
LogFile /tmp/dnsf_tcp_listenfail.log
UDPLocal 127.0.0.1:15366
TCPLocal 127.0.0.1:15364, 127.0.0.1:15365
AppendHosts test.listenfail.com 10.20.30.41
EOF

# Launch the daemon in the background with the failing-listen shim.
LD_PRELOAD="$Shim" "$DnsF" -f "$Conf" >"$RunLog" 2>&1 &
DPID=$!

# main() ends with ExitThisThread(), so the thread-group leader becomes a
# zombie while the worker threads keep the ports bound. Always reap the daemon,
# even when an assertion below fails, otherwise the next run finds the ports
# still in use.
Cleanup() {
    kill -TERM "$DPID" 2>/dev/null || true
    sleep 1
    kill -KILL "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
}
trap Cleanup EXIT HUP INT TERM

# Give the daemon a moment to set up both TCP interfaces.
sleep 2

set +e
python3 - <<'PY'
import socket, struct, sys

def build_query(name, qid):
    parts = name.split('.')
    qname = b''.join(bytes([len(p)]) + p.encode() for p in parts) + b'\x00'
    hdr = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    return hdr + qname + struct.pack('>HH', 1, 1)

# Sanity check: the shim really did break the first interface.
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(2)
try:
    probe.connect(('127.0.0.1', 15364))
    print("FAILED: 127.0.0.1:15364 is listening, the listen() shim did not work")
    sys.exit(1)
except OSError:
    pass
finally:
    probe.close()

# The second interface must have been opened despite the first one failing.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('127.0.0.1', 15365))
except OSError as e:
    print("FAILED: 127.0.0.1:15365 not listening (%s); the remaining TCPLocal "
          "interfaces were discarded after the first listen() failure" % e)
    sys.exit(1)

try:
    q = build_query('test.listenfail.com', 0x2100)
    s.sendall(struct.pack('>H', len(q)) + q)
    lenb = b''
    while len(lenb) < 2:
        chunk = s.recv(2 - len(lenb))
        if not chunk:
            print("FAILED: connection closed before any response")
            sys.exit(1)
        lenb += chunk
    total = struct.unpack('>H', lenb)[0]
    if total < 12:
        print("FAILED: response too short (%d bytes)" % total)
        sys.exit(1)
    body = b''
    while len(body) < total:
        chunk = s.recv(total - len(body))
        if not chunk:
            break
        body += chunk
    print("OK: 127.0.0.1:15365 answered with a %d-byte TCP DNS response"
          % (total + 2))
except socket.timeout:
    print("FAILED: timed out waiting for a TCP DNS response")
    sys.exit(1)
finally:
    s.close()
PY
RC=$?
set -e

if [ "$RC" -ne 0 ]; then
    echo "tcpfrontend listen() failure test FAILED" >&2
    exit 1
fi

echo "tcpfrontend listen() failure handling: OK"
exit 0
