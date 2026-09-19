#!/usr/bin/env python3
"""End-to-end regression test for the CName-redirection ("hosts Type 2")
feature of dnsforwarder.

Scenario
--------
    AppendHosts cname-target.test *.cname.test

A query for `www.cname.test` must, per README.md and default.en.config,
resolve through a CName redirection: dnsforwarder's Hosts thread rewrites
the query to `cname-target.test`, forwards it upstream, and recombines the
answer into a response for `www.cname.test`.

Before the fix (FIX(#001)/FIX(#002) in hosts.c) the datagram that comes back
on the internal OuterSocket -- which carries an `IHeader` prefix because the
outer query is filled with ReturnHeader = TRUE -- was parsed as if it started
at offset 0, so the identifier check never matched and every response was
dropped: the client simply timed out.

Usage:
    python3 tests/run_cname_redirect.py [--dns-port 15353]
                                        [--upstream-port 15354]

Exit status: 0 = the redirect answered, 1 = it did not (regression).
"""

import argparse
import socket
import struct
import subprocess
import sys
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def qname(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def query(host, port, name, qtype=1, timeout=4.0):
    pkt = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    pkt += qname(name) + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        return None
    finally:
        s.close()
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--dns-port", type=int, default=15353)
    ap.add_argument("--upstream-port", type=int, default=15354)
    args = ap.parse_args()

    upstream = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "good_upstream.py"),
         "--host", args.host, "--port", str(args.upstream_port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)

    failed = 0
    try:
        # 1) A plain (non-redirected) query must work, proving the upstream
        #    and the forwarding path are alive.
        r = query(args.host, args.dns_port, "plain.test")
        if r is None:
            print("FAIL: plain upstream query timed out (harness problem)")
            return 1
        ancount = struct.unpack("!H", r[6:8])[0]
        if ancount < 1:
            print("FAIL: plain query answered with ANCOUNT=%d" % ancount)
            return 1
        print("OK: plain query answered (ANCOUNT=%d)" % ancount)

        # 2) The CName-redirected query.
        r = query(args.host, args.dns_port, "www.cname.test")
        if r is None:
            print("FAIL: CName-redirected query timed out -- the "
                  "redirection response was dropped (regression)")
            return 1
        if len(r) < 12:
            print("FAIL: CName response shorter than a DNS header")
            return 1
        qid, flags, qd, an = struct.unpack("!HHHH", r[:8])
        if qid != 0xABCD:
            print("FAIL: wrong transaction id 0x%04X" % qid)
            return 1
        if not (flags & 0x8000):
            print("FAIL: QR bit not set (flags 0x%04X)" % flags)
            return 1
        if an < 1:
            print("FAIL: CName response carries no answer (ANCOUNT=%d)" % an)
            return 1
        print("OK: CName redirection answered "
              "(qid=0x%04X, flags=0x%04X, ANCOUNT=%d)" % (qid, flags, an))
    finally:
        upstream.terminate()
        try:
            upstream.wait(timeout=5)
        except subprocess.TimeoutExpired:
            upstream.kill()

    return failed


if __name__ == "__main__":
    sys.exit(main())
