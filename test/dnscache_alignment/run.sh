#!/bin/sh
# Regression test for the cache / response-generator alignment bug.
#
# DNSCache overlays struct Cht_Node / Cht_2DList (which carry 8-byte int64_t
# members) on the cache buffer.  The slot table base was placed at
# BaseAddr + CacheSize - sizeof(Cht_Slot) * Used with Used always odd, leaving
# every node access 4-byte misaligned (undefined behaviour, caught by UBSan).
#
# DNSCache_FetchFromCache() generates the cached answer into a scratch region
# immediately after the (often odd-length) request; that pointer is handed to
# the generator as a DNSHeader* and was therefore misaligned too.
#
# This test runs the daemon under ASan+UBSan, drives a benign upstream so
# responses get cached (exercising both the cache ADD and cache GET /
# answer-generation paths with odd request lengths), and FAILS if UBSan reports
# any "misaligned address" runtime error.  It also asserts that caching actually
# occurred, so a harness failure cannot masquerade as a pass.
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PORT=16771
UPPORT=16772
ASANBIN="$(mktemp /tmp/da_XXXXXX)"
CONF="$(mktemp /tmp/da_conf_XXXXXX)"
UP="$(mktemp /tmp/da_up_XXXXXX)"
RUNLOG="$(mktemp /tmp/da_run_XXXXXX)"

cleanup() {
    [ -n "$DPID" ] && kill -KILL "$DPID" 2>/dev/null || true
    [ -n "$UPPID" ] && kill -KILL "$UPPID" 2>/dev/null || true
    rm -f "$ASANBIN" "$CONF" "$UP" "$RUNLOG"
}
trap cleanup EXIT

# Build with ASan + UBSan (alignment checks on).
gcc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -DHAVE_CONFIG_H \
    -I"$ROOT" -pthread -o "$ASANBIN" "$ROOT"/*.c -lpthread -lm

cat > "$CONF" <<EOF
Log 3
UseCache true
MemoryCache true
CacheSize 1048576
UseHosts true
AppendHosts 127.0.0.2 hosts.example.com
AppendHosts ::1 aaaa.example.com
UDPLocal 127.0.0.1:$PORT
TCPLocal 127.0.0.1:$PORT
UDPGroup 127.0.0.1:$UPPORT * on
TCPGroup
EOF

# Benign upstream: for every query return a valid A response so it gets cached.
cat > "$UP" <<'PY'
import sys, socket, struct, random, time
port = int(sys.argv[1])
random.seed(3)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.bind(('127.0.0.1', port))
def qname_end(data):
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    return i + 1 + 4
cnt = 0
deadline = time.time() + 20
while time.time() < deadline:
    try:
        data, peer = s.recvfrom(4096)
    except socket.timeout:
        continue
    except OSError:
        break
    if len(data) < 12:
        continue
    qid = data[:2]
    try:
        end = qname_end(data)
        question = data[12:end]
    except Exception:
        continue
    resp = qid + struct.pack('>HHHHH', 0x8180, 1, 1, 0, 0) + question \
           + b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 30, 4) \
           + bytes(random.randrange(256) for _ in range(4))
    try:
        s.sendto(resp, peer)
    except OSError:
        break
    cnt += 1
print("upstream done cnt=%d" % cnt, flush=True)
PY

ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:halt_on_error=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
    "$ASANBIN" -f "$CONF" >"$RUNLOG" 2>&1 &
DPID=$!
sleep 2

python3 "$UP" "$UPPORT" >/tmp/da_up.log 2>&1 &
UPPID=$!

# Hammer a fixed set of names (repeatedly) so the cache fills and is then hit on
# nearly every query.  Names are chosen so request EntityLength is odd, which is
# what used to misalign the generated DNSHeader.
python3 - "$PORT" <<'PY'
import sys, os, socket, struct, random, time
Port = int(sys.argv[1])
def qname(n):
    return b''.join(bytes([len(p)]) + p.encode() for p in n.split('.')) + b'\x00'
def send_udp(payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        s.sendto(payload, ('127.0.0.1', Port))
        s.recv(4096)
    except Exception:
        pass
    finally:
        s.close()
deadline = time.time() + 25
while time.time() < deadline:
    n = 'w%d.example.com' % random.randrange(20)
    body = struct.pack('>HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0) \
        + qname(n) + struct.pack('>HH', 1, 1)
    send_udp(body)
    # Exercise the hosts answer-generation path too.
    body = struct.pack('>HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0) \
        + qname('hosts.example.com') + struct.pack('>HH', 1, 1)
    send_udp(body)
print("client load done", flush=True)
PY

sleep 1
[ -n "$DPID" ] && kill -KILL "$DPID" 2>/dev/null || true
[ -n "$UPPID" ] && kill -KILL "$UPPID" 2>/dev/null || true
sleep 1

if ! grep -qE "interface .* opened" "$RUNLOG"; then
    echo "FAIL: daemon did not open its listening interface."
    tail -15 "$RUNLOG"
    exit 1
fi

# The harness only proves something if caching actually happened.
if ! grep -qE "\[C\]" "$RUNLOG"; then
    echo "FAIL: cache was never exercised by this test (harness broken?)."
    tail -15 "$RUNLOG"
    exit 1
fi

if grep -qE "runtime error: member access within misaligned address" "$RUNLOG"; then
    echo "FAIL: UBSan reported misaligned struct access in the cache / generator path:"
    grep -E "runtime error: member access within misaligned address" "$RUNLOG" | head -10
    exit 1
fi
echo "PASS: cache path exercised with no misaligned-access undefined behaviour."
exit 0
