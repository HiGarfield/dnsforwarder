#!/bin/sh
# Regression test: a slow or silent TCP client must not wedge the TCP frontend.
#
# TcpFrontend_Work() is the only thread serving every TCP client. It used to
# read the two-octet length prefix and then the whole message body in blocking
# recv() loops, right after select() reported the socket readable. select()
# only promises that *one* read will not block, so a client that connected
# without sending anything, or that sent a single octet and then stalled,
# parked the thread in recv() for as long as it pleased. While it did, no other
# TCP client -- already connected or brand new -- could be served: one idle
# connection was enough to take DNS-over-TCP down completely.
#
# The frontend now performs a single recv() per readiness notification and
# keeps the partially received message in per-connection state.
#
# Usage:
#   sh test/tcpfrontend_stall/run.sh
#
# Requires the built dnsforwarder binary and python3.

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DnsF="$Root/dnsforwarder"
Conf=/tmp/dnsf_tcp_stall.conf
RunLog=/tmp/dnsf_tcp_stall.run
Port=15430

if [ ! -x "$DnsF" ]; then
    echo "dnsforwarder binary not built at $DnsF; run 'make' first." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not installed; skipping." >&2
    exit 0
fi

cat > "$Conf" <<EOF
Log 0
LogFile /tmp/dnsf_tcp_stall.log
UseCache false
UDPLocal 127.0.0.1:$Port
TCPLocal 127.0.0.1:$Port
AppendHosts 10.20.30.42 test.stall.com
EOF

"$DnsF" -f "$Conf" >"$RunLog" 2>&1 &
DPID=$!

# main() ends with ExitThisThread(), so the thread-group leader becomes a
# zombie while the worker threads keep the ports bound. Always reap the daemon,
# even when an assertion below fails, otherwise the next run finds the port
# still in use.
Cleanup() {
    kill -TERM "$DPID" 2>/dev/null || true
    sleep 1
    kill -KILL "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
}
trap Cleanup EXIT HUP INT TERM

sleep 2

set +e
Port=$Port python3 - <<'PY'
import os, socket, struct, sys, time

Port = int(os.environ['Port'])
Failures = []
Kept = []          # connections that must stay open for the whole run


def qname(name):
    return b''.join(bytes([len(p)]) + p.encode()
                    for p in name.split('.')) + b'\x00'


def query(qid, name='test.stall.com'):
    return struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) \
        + qname(name) + struct.pack('>HH', 1, 1)


def read_message(s):
    """Reads one length-prefixed DNS message. Returns None on failure."""
    head = b''
    while len(head) < 2:
        try:
            chunk = s.recv(2 - len(head))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        head += chunk
    total = struct.unpack('>H', head)[0]
    body = b''
    while len(body) < total:
        try:
            chunk = s.recv(total - len(body))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        body += chunk
    return body


def answer_address(msg, qid):
    """Returns the A record of a well-formed answer, or None."""
    if msg is None or len(msg) < 12:
        return None
    if struct.unpack('>H', msg[:2])[0] != qid:
        return None
    if struct.unpack('>H', msg[6:8])[0] < 1:
        return None
    i = 12
    while msg[i] != 0:
        i += 1 + msg[i]
    i += 1 + 4
    while True:
        if msg[i] & 0xC0 == 0xC0:
            i += 2
            break
        l = msg[i]
        i += 1
        if l == 0:
            break
        i += l
    t, k, ttl, rl = struct.unpack('>HHIH', msg[i:i + 10])
    i += 10
    if t != 1 or rl != 4:
        return None
    return '.'.join(str(b) for b in msg[i:i + 4])


def ask(qid, timeout=4):
    """One complete query over its own connection."""
    try:
        s = socket.create_connection(('127.0.0.1', Port), timeout)
    except OSError:
        return None
    s.settimeout(timeout)
    try:
        body = query(qid)
        s.sendall(struct.pack('>H', len(body)) + body)
        return answer_address(read_message(s), qid)
    finally:
        s.close()


def check(name, condition):
    if condition:
        print('  [ ok ] %s' % name)
    else:
        print('  [FAIL] %s' % name)
        Failures.append(name)


def still_serving(name, base_qid):
    served = sum(1 for n in range(3)
                 if ask(base_qid + n) == '10.20.30.42')
    check('%s (%d/3 answered)' % (name, served), served == 3)


def keep(sock):
    Kept.append(sock)
    return sock


# --------------------------------------------------------------- baseline
print('Baseline')
check('a plain TCP query is answered', ask(0x1000) == '10.20.30.42')

# ------------------------------------------------------- silent connection
print('A client that connects and says nothing')
silent = keep(socket.create_connection(('127.0.0.1', Port), 4))
time.sleep(0.3)
still_serving('other TCP clients are still served', 0x1100)

# --------------------------------------------------- half a length prefix
print('A client that sends one octet of the length prefix')
half = keep(socket.create_connection(('127.0.0.1', Port), 4))
half.sendall(b'\x00')
time.sleep(0.3)
still_serving('other TCP clients are still served', 0x1200)

# ------------------------------------------------------- half of the body
print('A client that announces a message and sends half of it')
partial = keep(socket.create_connection(('127.0.0.1', Port), 4))
body = query(0x1300)
partial.sendall(struct.pack('>H', len(body)) + body[:len(body) // 2])
time.sleep(0.3)
still_serving('other TCP clients are still served', 0x1400)

# The stalled client must be served as soon as it finishes its message, and
# the reassembled query must be the one it sent.
partial.settimeout(4)
partial.sendall(body[len(body) // 2:])
check('the stalled client is answered once it completes its message',
      answer_address(read_message(partial), 0x1300) == '10.20.30.42')

# ------------------------------------------------------- dribbled message
print('A client that dribbles its message out octet by octet')
slow = socket.create_connection(('127.0.0.1', Port), 6)
slow.settimeout(6)
body = query(0x1500)
framed = struct.pack('>H', len(body)) + body
for n in range(0, len(framed), 3):
    slow.sendall(framed[n:n + 3])
    time.sleep(0.01)
check('a message split across many segments is reassembled',
      answer_address(read_message(slow), 0x1500) == '10.20.30.42')
slow.close()

# ---------------------------------------------------------- pipelined
print('A client that pipelines two queries in one segment')
pipe = socket.create_connection(('127.0.0.1', Port), 6)
pipe.settimeout(6)
one = query(0x1600)
two = query(0x1601)
pipe.sendall(struct.pack('>H', len(one)) + one
             + struct.pack('>H', len(two)) + two)
first = answer_address(read_message(pipe), 0x1600)
second = answer_address(read_message(pipe), 0x1601)
check('both pipelined queries are answered',
      first == '10.20.30.42' and second == '10.20.30.42')
pipe.close()

# ------------------------------------------------------- oversized prefix
print('A client that announces an impossibly large message')
huge = socket.create_connection(('127.0.0.1', Port), 4)
huge.settimeout(4)
huge.sendall(struct.pack('>H', 0xFFFF) + b'A' * 16)
time.sleep(0.3)
huge.close()
still_serving('other TCP clients are still served', 0x1700)

# ------------------------------------------------------------- teardown
for s in Kept:
    s.close()

# Everything must still work after the stalled connections are gone.
print('After the stalled clients disconnect')
still_serving('the frontend is still healthy', 0x1800)

if Failures:
    print('\n%d check(s) failed' % len(Failures))
    sys.exit(1)
print('\nall checks passed')
PY
RC=$?
set -e

if [ "$RC" -ne 0 ]; then
    echo "tcpfrontend stalled-client test FAILED" >&2
    exit 1
fi

echo "tcpfrontend stalled-client handling: OK"
exit 0
