#!/bin/sh
# Regression test: the state UdpM_Send() uses under m->Lock must only be torn
# down under that same lock.
#
# UdpM_Send() reads m->Departure, m->Parallels and m->AddrList and calls sendto()
# while holding m->Lock, and UdpM_Works() creates the socket under the lock too.
# The teardown paths did not follow that contract:
#
#   - UdpM_Works(), select() returning SOCKET_ERROR: closed m->Departure and set
#     it to INVALID_SOCKET unlocked.
#   - UdpM_Works(), the RECREATION_THRESHOLD branch: same.
#   - UdpM_Cleanup(): closed m->Departure, freed m->Parallels.addrs and
#     m->AddrList, and cleared m->IsServer, all unlocked.
#
# A dispatch running on a frontend thread could therefore call sendto() on a
# descriptor that had just been closed -- or, once the kernel recycled the
# number, on a completely unrelated socket -- and walk freed address lists.
#
# Part 1 checks the invariant on the source: inside UdpM_Works() and
# UdpM_Cleanup() every mutation of that shared state has to sit in a region
# guarded by EFFECTIVE_LOCK_GET(m->Lock).
#
# Part 2 is a functional guard for the extra locking itself: queries must still
# be forwarded, and the daemon must still shut down instead of deadlocking on
# the lock UdpM_Cleanup() now takes.
#
# Usage:
#   sh test/udpm_socket_lock/run.sh

set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not installed; skipping." >&2
    exit 0
fi

echo "Part 1: locking invariant in udpm.c"
python3 - "$Root/udpm.c" <<'PY'
import re, sys

lines = [l.split('/*')[0] for l in open(sys.argv[1]).read().split('\n')]

Get = 'EFFECTIVE_LOCK_GET(m->Lock)'
Release = 'EFFECTIVE_LOCK_RELEASE(m->Lock)'

# Only the code that runs once the module is live can race with UdpM_Send().
# UdpM_Init() builds the module before its worker thread exists and before
# MMgr_Send() can reach it, so its setup and error-unwind paths are exempt.
Limit = next((n for n, l in enumerate(lines)
              if re.match(r'^int\s+UdpM_Init\s*\(', l)), len(lines))

# Teardown of state that UdpM_Send() reads while holding m->Lock. Each of these
# has to sit in a region opened by EFFECTIVE_LOCK_GET(m->Lock) and closed by
# EFFECTIVE_LOCK_RELEASE(m->Lock).
Teardown = [
    ('close of m->Departure', re.compile(r'CLOSE_SOCKET\s*\(\s*m->Departure\s*\)')),
    ('retire of m->Departure',
     re.compile(r'm->Departure\s*=\s*INVALID_SOCKET')),
    ('free of m->Parallels.addrs',
     re.compile(r'SafeFree\s*\(\s*m->Parallels\.addrs\s*\)')),
    ('free of m->AddrList',
     re.compile(r'AddressList_Free\s*\(\s*&\s*\(?\s*m->AddrList')),
]

Window = 10
Failures = []
Total = 0

for label, pat in Teardown:
    hits = [n for n, l in enumerate(lines[:Limit]) if pat.search(l)]
    if not hits:
        print('  [FAIL] no %s found in udpm.c; test is stale' % label)
        Failures.append(label)
        continue
    for n in hits:
        Total += 1
        # Nearest lock operation above must be a GET, and a RELEASE must follow
        # before the enclosing block can hand control to another thread.
        opened = None
        for k in range(n - 1, max(-1, n - 1 - Window), -1):
            if Release in lines[k]:
                opened = False
                break
            if Get in lines[k]:
                opened = True
                break
        closed = any(Release in lines[k]
                     for k in range(n + 1, min(len(lines), n + 1 + Window)))
        if opened and closed:
            continue
        why = 'no EFFECTIVE_LOCK_GET(m->Lock) above' if not opened \
            else 'no EFFECTIVE_LOCK_RELEASE(m->Lock) below'
        print('  [FAIL] udpm.c:%d %s is unlocked (%s): %s'
              % (n + 1, label, why, lines[n].strip()))
        Failures.append('%s:%d' % (label, n + 1))

if not Failures:
    print('  [ ok ] all %d teardown site(s) guarded by m->Lock' % Total)

sys.exit(1 if Failures else 0)
PY

echo "Part 2: forwarding still works and shutdown does not deadlock"
DnsF="$Root/dnsforwarder"
if [ ! -x "$DnsF" ]; then
    echo "  dnsforwarder binary not built at $DnsF; skipping functional part." >&2
    exit 0
fi

python3 - "$DnsF" <<'PY'
import os, signal, socket, struct, subprocess, sys, tempfile, threading, time

DnsF = sys.argv[1]
Port, UpPort = 15610, 15611
Answer = (10, 20, 30, 55)
Failures = []
Stop = threading.Event()


def qend(m):
    i = 12
    while m[i] != 0:
        i += 1 + m[i]
    return i + 1 + 4


def upstream():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', UpPort))
    s.settimeout(0.5)
    while not Stop.is_set():
        try:
            d, a = s.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            r = d[:2] + struct.pack('>HHHHH', 0x8180, 1, 1, 0, 0) \
                + d[12:qend(d)] + b'\xc0\x0c' \
                + struct.pack('>HHIH', 1, 1, 300, 4) + bytes(Answer)
            s.sendto(r, a)
        except (IndexError, struct.error, OSError):
            pass
    s.close()


def qname(n):
    return b''.join(bytes([len(p)]) + p.encode() for p in n.split('.')) + b'\x00'


def ask(qid, name):
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) \
        + qname(name) + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(q, ('127.0.0.1', Port))
        d = s.recv(4096)
        return struct.unpack('>H', d[6:8])[0] >= 1
    except socket.timeout:
        return False
    finally:
        s.close()


def check(name, cond):
    print('  [ ok ] %s' % name if cond else '  [FAIL] %s' % name)
    if not cond:
        Failures.append(name)


conf = tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False)
conf.write('UseCache false\n'
           'UDPLocal 127.0.0.1:%d\n'
           'UDPGroup 127.0.0.1:%d * off\n' % (Port, UpPort))
conf.close()

threading.Thread(target=upstream, daemon=True).start()
time.sleep(0.3)

log = open('/tmp/dnsf_udpm_lock.run', 'wb')
daemon = subprocess.Popen([DnsF, '-f', conf.name],
                          stdout=log, stderr=subprocess.STDOUT)
try:
    time.sleep(2)
    ok = sum(1 for n in range(4) if ask(0x3000 + n, 'u%d.example.com' % n))
    check('queries forwarded and answered (%d/4)' % ok, ok == 4)

    # UdpM_Cleanup() now takes m->Lock; make sure shutdown still completes.
    t0 = time.time()
    daemon.send_signal(signal.SIGTERM)
    try:
        daemon.wait(timeout=15)
        check('daemon shut down without deadlocking (%.1fs)'
              % (time.time() - t0), True)
    except subprocess.TimeoutExpired:
        check('daemon shut down without deadlocking (timed out)', False)
finally:
    Stop.set()
    if daemon.poll() is None:
        daemon.kill()
    daemon.wait()
    log.close()
    os.unlink(conf.name)

sys.exit(1 if Failures else 0)
PY

echo "UdpM shared-state locking: OK"
exit 0
