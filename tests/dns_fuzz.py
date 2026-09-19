#!/usr/bin/env python3
"""Malformed-DNS regression / fuzz driver for dnsforwarder.

Sends a battery of malformed, truncated and deliberately hostile DNS
messages to a running dnsforwarder instance over UDP and TCP, then
reports whether the process is still alive.

It is meant to be run against an AddressSanitizer/UBSan build: any
out-of-bounds access, infinite loop or crash inside the parser shows up
either as a dead process or as an entry in the ASan log file.

Usage:
    python3 tests/dns_fuzz.py [--host 127.0.0.1] [--port 15353]
                              [--pid-file FILE] [--asan-log /tmp/asan.log.*]

Exit status:
    0  every message was handled and the process survived
    1  the process died, or an ASan report was produced
"""

import argparse
import glob
import os
import random
import socket
import struct
import sys
import time

# ---------------------------------------------------------------- helpers


def qname(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def header(qid=0x1234, flags=0x0100, qd=1, an=0, ns=0, ar=0):
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def question(name="www.example.com", qtype=1, qclass=1):
    return qname(name) + struct.pack("!HH", qtype, qclass)


# ---------------------------------------------------------------- corpus
#
# Every entry is (description, payload).  `payload` is the raw DNS
# message (no length prefix; the TCP sender adds it).


def build_corpus():
    c = []

    c.append(("empty", b""))
    c.append(("1 byte", b"\x00"))
    c.append(("11 bytes (header - 1)", b"\x00" * 11))
    c.append(("header only, QDCOUNT=1", header(qd=1)))
    c.append(("header only, QDCOUNT=0", header(qd=0)))

    # --- question section -------------------------------------------------
    c.append(("valid A query", header() + question()))
    c.append(("truncated question name", header() + b"\x03www"))
    c.append(("name without root label", header() + b"\x03www\x07example\x03com"))
    c.append(("label length 0x40 (not a pointer)", header() + b"\x40aaaaaa"))
    c.append(("label length 0x41", header() + b"\x41aaaaaa"))
    c.append(("name of 200 one-byte labels", header() + b"\x01a" * 200))
    c.append(
        (
            "name longer than 255 octets",
            header() + b"".join(bytes([63]) + b"a" * 63 for _ in range(6)),
        )
    )
    c.append(("QDCOUNT=1 but no question", header(qd=1)))
    c.append(("QDCOUNT=65535", header(qd=0xFFFF)))

    # --- compression pointers --------------------------------------------
    c.append(("self-referencing pointer at question", header() + b"\xc0\x0c" + b"\x00\x01\x00\x01"))
    c.append(("pointer to offset 0", header() + b"\xc0\x00"))
    c.append(("pointer to out-of-range offset", header() + b"\xc0\xff\xfe"))
    c.append(("pointer with only 1 byte left", header() + b"\xc0"))
    # two pointers pointing at each other
    body = b"\xc0\x0e\xc0\x0c"
    c.append(("mutually referencing pointers", header() + body))
    # pointer loop: 0x0c -> 0x0e -> 0x0c ...
    c.append(("pointer chain loop", header() + b"\xc0\x0e" + b"\xc0\x0c" + b"\x00" * 4))

    # --- answer section ---------------------------------------------------
    ans_a = qname("www.example.com") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    c.append(("valid answer", header(flags=0x8180, an=1) + question() + ans_a))
    c.append(
        (
            "A record with RDLENGTH=65535",
            header(flags=0x8180, an=1) + question() + qname("a.com") + struct.pack("!HHIH", 1, 1, 60, 0xFFFF),
        )
    )
    c.append(
        (
            "A record with RDLENGTH=1",
            header(flags=0x8180, an=1) + question() + qname("a.com") + struct.pack("!HHIH", 1, 1, 60, 1) + b"\x01",
        )
    )
    c.append(
        (
            "AAAA record with RDLENGTH=4",
            header(flags=0x8180, an=1) + question() + qname("a.com") + struct.pack("!HHIH", 28, 1, 60, 4) + b"\x01\x02\x03\x04",
        )
    )
    c.append(
        (
            "CNAME with RDLENGTH=0",
            header(flags=0x8180, an=1) + question() + qname("a.com") + struct.pack("!HHIH", 5, 1, 60, 0),
        )
    )
    c.append(
        (
            "CNAME whose RDATA is a self pointer",
            header(flags=0x8180, an=1)
            + question()
            + qname("a.com")
            + struct.pack("!HHIH", 5, 1, 60, 2)
            + b"\xc0\x0c",
        )
    )
    c.append(
        (
            "MX with RDLENGTH=1 (no preference word)",
            header(flags=0x8180, an=1)
            + question()
            + qname("a.com")
            + struct.pack("!HHIH", 15, 1, 60, 1)
            + b"\x00",
        )
    )
    c.append(
        (
            "truncated SOA",
            header(flags=0x8180, an=1)
            + question()
            + qname("a.com")
            + struct.pack("!HHIH", 6, 1, 60, 4)
            + b"\x00\x00\x00",
        )
    )
    c.append(
        (
            "TXT with length byte running past RDATA",
            header(flags=0x8180, an=1)
            + question()
            + qname("a.com")
            + struct.pack("!HHIH", 16, 1, 60, 3)
            + b"\x05ab",
        )
    )
    c.append(
        (
            "TXT of exactly 256 octets",
            header(flags=0x8180, an=1)
            + question()
            + qname("a.com")
            + struct.pack("!HHIH", 16, 1, 60, 256)
            + b"\xff" + b"z" * 255,
        )
    )
    c.append(
        (
            "TXT of 4000 octets (heap path)",
            header(flags=0x8180, an=1)
            + question()
            + qname("a.com")
            + struct.pack("!HHIH", 16, 1, 60, 400)
            + b"\xff" + b"z" * 399,
        )
    )

    # --- EDNS / OPT --------------------------------------------------------
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    c.append(("query with OPT", header(ar=1) + question() + opt))
    c.append(("query with OPT, ARCOUNT=2", header(ar=2) + question() + opt))
    c.append(
        (
            "OPT with huge RDLENGTH",
            header(ar=1) + question() + b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0xFF00),
        )
    )
    c.append(("ARCOUNT=1 but no OPT", header(ar=1) + question()))

    # --- counts vs. body mismatch -----------------------------------------
    c.append(("ANCOUNT=1, no answer", header(an=1) + question()))
    c.append(("ANCOUNT=65535, no answer", header(an=0xFFFF) + question()))
    c.append(("all counts 65535", header(qd=0xFFFF, an=0xFFFF, ns=0xFFFF, ar=0xFFFF) + question()))
    c.append(("QDCOUNT=2, one question", header(qd=2) + question()))

    # --- random noise ------------------------------------------------------
    rnd = random.Random(20260918)
    for i in range(300):
        n = rnd.randrange(0, 300)
        c.append(("random #%d (%d bytes)" % (i, n), bytes(rnd.randrange(256) for _ in range(n))))
    for i in range(300):
        # random bytes with a plausible header on top
        n = rnd.randrange(0, 300)
        c.append(
            (
                "random-with-header #%d" % i,
                header(qid=rnd.randrange(65536), qd=rnd.randrange(4), an=rnd.randrange(4))
                + bytes(rnd.randrange(256) for _ in range(n)),
            )
        )

    return c


# ---------------------------------------------------------------- senders


def send_udp(host, port, payload, timeout=0.25):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
    except socket.error:
        pass
    try:
        s.recvfrom(4096)
    except socket.error:
        pass
    s.close()


def send_tcp(host, port, payload, timeout=0.25):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except socket.error:
        return
    try:
        if payload:
            s.sendall(struct.pack("!H", len(payload)) + payload)
        # zero-length and oversized length prefixes are interesting too
        s.sendall(struct.pack("!H", 0))
        s.sendall(struct.pack("!H", 0xFFFF))
        s.sendall(b"\x00")  # half a prefix, then abandon
    except socket.error:
        pass
    s.close()


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15353)
    ap.add_argument("--pid-file", default=None)
    ap.add_argument("--asan-log", default="/tmp/asan.log")
    ap.add_argument("--tcp", action="store_true", help="also run the corpus over TCP")
    args = ap.parse_args()

    pid = None
    if args.pid_file and os.path.exists(args.pid_file):
        with open(args.pid_file) as f:
            pid = int(f.read().strip())

    def alive():
        """The daemon's main thread calls pthread_exit() and stays behind as
        the zombie thread-group leader while the worker threads keep serving,
        so /proc/<pid>/stat reports 'Z'.  Look for at least one *live*
        thread instead of trusting the leader's state."""
        if pid is None:
            return True
        taskdir = "/proc/%d/task" % pid
        try:
            tasks = os.listdir(taskdir)
        except OSError:
            return False
        for t in tasks:
            try:
                with open("%s/%s/stat" % (taskdir, t)) as f:
                    state = f.read().rsplit(")", 1)[1].split()[0]
            except (OSError, IndexError):
                continue
            if state not in ("Z", "X"):
                return True
        return False

    corpus = build_corpus()
    print("sending %d messages to %s:%d" % (len(corpus), args.host, args.port))

    for desc, payload in corpus:
        print("  udp: %s" % desc)
        send_udp(args.host, args.port, payload)
        if not alive():
            print("FAIL: process died on '%s'" % desc)
            return 1
        if args.tcp:
            send_tcp(args.host, args.port, payload)
            if not alive():
                print("FAIL: process died on TCP '%s'" % desc)
                return 1

    # give the daemon a moment to finish any deferred work / sweeps
    time.sleep(3)
    if not alive():
        print("FAIL: process died after the corpus")
        return 1

    reports = glob.glob(args.asan_log + "*")
    bad = []
    for r in reports:
        try:
            with open(r, errors="replace") as f:
                txt = f.read()
        except OSError:
            continue
        if txt.strip():
            bad.append(r)
    if bad:
        print("FAIL: sanitizer reports: %s" % ", ".join(bad))
        for r in bad:
            with open(r, errors="replace") as f:
                print(f.read()[:4000])
        return 1

    print("OK: process survived the whole corpus, no sanitizer report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
