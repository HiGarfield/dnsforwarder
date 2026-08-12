#!/bin/sh
# Regression test for the TCP in-flight counter data race.
#
# TcpFrontend_Work() hands a client socket to a module worker thread and keeps a
# per-descriptor "queries in flight" counter in a global array. The counter is
# written under a mutex on the dispatch / release paths, but the frontend also
# reset it for a freshly accepted connection *without* the mutex -- so the
# accept-time write raced the module worker's release (also a write), which
# ThreadSanitizer reported as a data race at tcpfrontend.c:192. The fix takes
# the ownership lock around the accept-time reset too.
#
# This is a broad ThreadSanitizer test: it fails if TSan reports *any* data
# race while the daemon is under concurrent UDP/TCP load and is shut down.
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

PORT=15477
UPPORT=15478

TSANBIN="$(mktemp /tmp/tir_tsan_XXXXXX)"
CONF="$(mktemp /tmp/tir_conf_XXXXXX)"
UP="$(mktemp /tmp/tir_up_XXXXXX)"
REPORT="/tmp/tir_tsan_report"

cleanup() {
    pkill -KILL -f "$TSANBIN" 2>/dev/null || true
    [ -n "$UPPID" ] && kill -KILL "$UPPID" 2>/dev/null || true
    rm -f "$TSANBIN" "$CONF" "$UP" "$REPORT".*
}
trap cleanup EXIT

gcc -g -O1 -fsanitize=thread -fno-omit-frame-pointer \
    -DHAVE_CONFIG_H -I"$ROOT" -pthread \
    -o "$TSANBIN" "$ROOT"/*.c -lpthread -lm || {
    echo "BUILD FAILED"
    exit 2
}

cat > "$CONF" <<EOF
Log 0
UseCache true
MemoryCache true
CacheSize 1048576
UseHosts false
UDPLocal 127.0.0.1:$PORT
TCPLocal 127.0.0.1:$PORT
UDPGroup 127.0.0.1:$UPPORT * on
EOF

cat > "$UP" <<PY
import socket, struct, random
random.seed(3)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $UPPORT))
while True:
    try:
        data, peer = s.recvfrom(4096)
    except OSError:
        break
    if len(data) < 12:
        continue
    qid = data[:2]
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    end = i + 1 + 4
    question = data[12:end]
    msg = qid + struct.pack('>HHHHH', 0x8180, 1, 1, 0, 0) + question \
        + b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, random.randrange(1, 20), 4) \
        + bytes(random.randrange(256) for _ in range(4))
    s.sendto(msg, peer)
PY
python3 "$UP" &
UPPID=$!

rm -f "$REPORT".*
TSAN_OPTIONS="halt_on_error=0:log_path=$REPORT" \
    "$TSANBIN" -f "$CONF" >/dev/null 2>&1 &
DPID=$!

sleep 3

LocalPort="$PORT" python3 - <<'PY'
import os, socket, struct, threading, random
Port = int(os.environ['LocalPort'])
def qname(n):
    return b''.join(bytes([len(p)]) + p.encode() for p in n.split('.')) + b'\x00'
def worker(idx):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    for r in range(220):
        n = 'w%d.example.com' % random.randrange(25)
        body = struct.pack('>HHHHHH', (idx << 8 | r) & 0xFFFF, 0x0100, 1, 0, 0, 0) \
            + qname(n) + struct.pack('>HH', random.choice([1, 28, 5]), 1)
        try:
            s.sendto(body, ('127.0.0.1', Port))
            s.recv(4096)
        except socket.timeout:
            pass
        if r % 3 == 0:
            try:
                tc = socket.create_connection(('127.0.0.1', Port), 1)
                tc.settimeout(1)
                tc.sendall(struct.pack('>H', len(body)) + body)
                tc.close()
            except OSError:
                pass
    s.close()
ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
for x in ts: x.start()
for x in ts: x.join()
print('load done')
PY

sleep 2
pkill -TERM -f "$TSANBIN" 2>/dev/null || true
sleep 1
pkill -KILL -f "$TSANBIN" 2>/dev/null || true
sleep 1

if ls "$REPORT".* >/dev/null 2>&1 && grep -q "data race" "$REPORT".*; then
    echo "FAIL: ThreadSanitizer reported a data race."
    cat "$REPORT".*
    exit 1
fi

echo "PASS: no data race under concurrent load."
exit 0
