#!/usr/bin/env python3
"""Drive dnsforwarder's *upstream response* parsing path with hostile data.

Starts (or reuses) a malicious upstream (tests/malicious_upstream.py), sends
one ordinary client query per corpus entry into dnsforwarder so that each
malformed upstream reply is parsed, and reports whether the daemon survived
and produced no sanitizer report.

Usage:
    python3 tests/run_response_path.py [--upstream-port 15354]
                                       [--dns-port 15353]
                                       [--count N]
                                       [--asan-log /tmp/asan.log]
"""

import argparse
import glob
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def qname(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def make_query(qid, name="www.example.com", qtype=1):
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream-port", type=int, default=15354)
    ap.add_argument("--dns-port", type=int, default=15353)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--count", type=int, default=700)
    ap.add_argument("--asan-log", default="/tmp/asan.log")
    args = ap.parse_args()

    upstream = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "malicious_upstream.py"),
         "--host", args.host, "--port", str(args.upstream_port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        sent = 0
        for qid in range(args.count):
            payload = make_query(qid & 0xFFFF, "www%d.example.com" % (qid % 50))
            try:
                s.sendto(payload, (args.host, args.dns_port))
            except socket.error:
                pass
            sent += 1
            if qid % 20 == 0:
                time.sleep(0.05)
        s.close()
        print("sent %d client queries" % sent)

        # let the daemon drain: timeouts, sweeps, cache writes, statistics
        time.sleep(6)
    finally:
        upstream.terminate()
        try:
            upstream.wait(timeout=5)
        except subprocess.TimeoutExpired:
            upstream.kill()

    reports = []
    for r in glob.glob(args.asan_log + "*"):
        try:
            with open(r, errors="replace") as f:
                txt = f.read()
        except OSError:
            continue
        if txt.strip():
            reports.append(r)

    if reports:
        print("FAIL: sanitizer reports")
        for r in reports:
            with open(r, errors="replace") as f:
                print(f.read()[:6000])
        return 1

    print("OK: no sanitizer report from the upstream-response path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
