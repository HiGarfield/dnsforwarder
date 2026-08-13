#!/bin/sh
# Regression test: an answer coming back from a TCP upstream must reach the client.
#
# TcpM_Send() is the ModuleInterface.Send entry MMgr_Send() uses whenever a
# query is routed to a TCP upstream (a TCPGroup, or UDP-to-TCP fallback). It
# forwarded the query but never registered it in m->Context. The worker thread
# matches every answer it reads off an upstream connection against that table
# with ModuleContext_GenAnswerHeaderAndRemove(); with no entry the lookup failed
# with -60 and the answer was thrown away. The upstream was queried, it replied,
# and the client got nothing but a timeout.
#
# The same omission left TcpContext->MsgCtx pointing at the calling frontend's
# receive buffer, which is reused for the next client query, so the keep-alive
# re-send path could put unrelated bytes on the wire.
#
# TcpM_Send() now stores the query in m->Context first (exactly like the
# listen-socket path in TcpM_Works and like UdpM_Send) and hands the stable copy
# to TcpM_Send_Actual.
#
# Once registration worked the answers were still lost: the worker loop blocked
# in select() for TIMEOUT (5s), while ModuleContext_Sweep() discards entries
# older than 2s. A query registered by a frontend thread therefore always aged
# past the deadline before the worker woke up, and the worker swept it before it
# ever polled the upstream socket holding the answer. The worker now polls on a
# 1s interval, below the sweep deadline.
#
# Usage:
#   sh test/tcpm_context/run.sh
#
# Requires the built dnsforwarder binary and python3.

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DnsF="$Root/dnsforwarder"
Conf=/tmp/dnsf_tcpm_ctx.conf
RunLog=/tmp/dnsf_tcpm_ctx.run
Port=15450
UpPort=15451

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
LogFile /tmp/dnsf_tcpm_ctx.log
UseCache false
UDPLocal 127.0.0.1:$Port
TCPLocal 127.0.0.1:$Port
EnableUDPtoTCP true
EnableTCPtoUDP false
TCPGroup 127.0.0.1:$UpPort * off no
EOF

# The fake upstream has to be listening before dnsforwarder starts querying it.
Port=$Port UpPort=$UpPort python3 - "$DnsF" "$Conf" "$RunLog" <<'PY'
import os, signal, socket, struct, subprocess, sys, threading, time

Port = int(os.environ['Port'])
UpPort = int(os.environ['UpPort'])
DnsF, Conf, RunLog = sys.argv[1], sys.argv[2], sys.argv[3]

Answer = (10, 20, 30, 42)
Failures = []
Served = []                 # query IDs the fake upstream actually answered
ServedLock = threading.Lock()
Stop = threading.Event()


def recvn(s, n):
    buf = b''
    while len(buf) < n:
        try:
            chunk = s.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def question_end(msg):
    """Offset just past the single QUESTION record."""
    i = 12
    while msg[i] != 0:
        i += 1 + msg[i]
    return i + 1 + 4


def make_response(q):
    qend = question_end(q)
    header = q[:2] + struct.pack('>HHHHH', 0x8180, 1, 1, 0, 0)
    answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 300, 4) + bytes(Answer)
    return header + q[12:qend] + answer


def serve_client(c):
    c.settimeout(20)
    try:
        while not Stop.is_set():
            head = recvn(c, 2)
            if head is None:
                return
            body = recvn(c, struct.unpack('>H', head)[0])
            if body is None:
                return
            with ServedLock:
                Served.append(struct.unpack('>H', body[:2])[0])
            resp = make_response(body)
            c.sendall(struct.pack('>H', len(resp)) + resp)
    except (OSError, IndexError, struct.error):
        pass
    finally:
        c.close()


def upstream():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', UpPort))
    srv.listen(16)
    srv.settimeout(0.5)
    while not Stop.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=serve_client, args=(c,), daemon=True).start()
    srv.close()


def qname(name):
    return b''.join(bytes([len(p)]) + p.encode()
                    for p in name.split('.')) + b'\x00'


def query(qid, name='tcpm.example.com'):
    return struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) \
        + qname(name) + struct.pack('>HH', 1, 1)


def answer_address(msg, qid):
    """Returns the A record of a well-formed answer, or None."""
    if msg is None or len(msg) < 12:
        return None
    if struct.unpack('>H', msg[:2])[0] != qid:
        return None
    if struct.unpack('>H', msg[6:8])[0] < 1:
        return None
    i = question_end(msg)
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
    return tuple(msg[i:i + 4])


def ask_udp(qid, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query(qid), ('127.0.0.1', Port))
        try:
            return answer_address(s.recv(4096), qid)
        except socket.timeout:
            return None
    finally:
        s.close()


def ask_tcp(qid, timeout=6):
    try:
        s = socket.create_connection(('127.0.0.1', Port), timeout)
    except OSError:
        return None
    s.settimeout(timeout)
    try:
        body = query(qid)
        s.sendall(struct.pack('>H', len(body)) + body)
        head = recvn(s, 2)
        if head is None:
            return None
        return answer_address(recvn(s, struct.unpack('>H', head)[0]), qid)
    finally:
        s.close()


def check(name, condition):
    if condition:
        print('  [ ok ] %s' % name)
    else:
        print('  [FAIL] %s' % name)
        Failures.append(name)


threading.Thread(target=upstream, daemon=True).start()
time.sleep(0.3)

log = open(RunLog, 'wb')
daemon = subprocess.Popen([DnsF, '-f', Conf], stdout=log, stderr=subprocess.STDOUT)
try:
    time.sleep(2)

    print('A UDP client query forwarded to a TCP upstream')
    got = ask_udp(0x2100)
    check('the upstream was queried', 0x2100 in [q for q in Served] or Served)
    check('the client received the upstream answer', got == Answer)

    print('A TCP client query forwarded to a TCP upstream')
    check('the client received the upstream answer', ask_tcp(0x2200) == Answer)

    print('Repeated queries reuse the keep-alive connection')
    ok = sum(1 for n in range(4) if ask_udp(0x2300 + n) == Answer)
    check('all 4 follow-up queries answered (%d/4)' % ok, ok == 4)

    with ServedLock:
        forwarded = len(Served)
    check('every query reached the upstream (%d forwarded)' % forwarded,
          forwarded >= 6)
finally:
    Stop.set()
    daemon.send_signal(signal.SIGTERM)
    time.sleep(1)
    if daemon.poll() is None:
        daemon.kill()
    daemon.wait()
    log.close()

if Failures:
    print('\n%d check(s) failed' % len(Failures))
    sys.exit(1)
print('\nall checks passed')
PY
RC=$?

if [ "$RC" -ne 0 ]; then
    echo "TcpM context-registration test FAILED" >&2
    exit 1
fi

echo "TcpM context registration: OK"
exit 0
