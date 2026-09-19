#!/usr/bin/env python3
"""Regression test for FIX(#003) in ipmisc.c.

The IP policies (`BlockIP` / `IPSubstituting`) are applied to every A/AAAA
record of an upstream response.  Upstream data is attacker controlled and
`DnsSimpleParserIterator` accepts a record whose RDLENGTH is *shorter* than
its type requires, so an `A` record with RDLENGTH = 2 reaches
`IPMiscMapping_Process()`.

Before the fix that function only checked that `RDATA + 4` stays inside the
*message*, which is true because the bytes that follow belong to the next
record.  It therefore read a 4-octet "address" made of this record's 2 octets
plus the first 2 octets of the following record, and a SUBSTITUTE action
wrote 4 octets over a 2-octet RDATA.

The test builds a response whose first A record carries RDLENGTH = 2 and
whose continuation happens to read as 10.0.1.98, which is listed in
`BlockIP`.  With the bug the whole response is discarded; with the fix the
short record is skipped and the legitimate second record is answered.

Usage:
    python3 tests/run_ipmisc_shortrdata.py [--dns-port 15353]
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def qname(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_response(qid, question):
    """question + A(RDLENGTH=2) + A(RDLENGTH=4)"""
    r = struct.pack("!HHHHHH", qid, 0x8180, 1, 2, 0, 0) + question

    # Record 1: only 2 octets of RDATA.  The 4-octet window a buggy reader
    # sees is 0A 00 followed by the first two octets of record 2, which are
    # the length octet (1) and 'b' (0x62) of "b.example": 10.0.1.98.
    r += qname("a.example") + struct.pack("!HHIH", 1, 1, 60, 2) + b"\x0a\x00"

    # Record 2: a perfectly ordinary A record.
    r += qname("b.example") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([198, 51, 100, 7])

    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--dns-port", type=int, default=15353)
    ap.add_argument("--upstream-port", type=int, default=15354)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.upstream_port))
    srv.settimeout(0.5)

    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cli.settimeout(5.0)
        pkt = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        pkt += qname("www.ipmisc.test") + struct.pack("!HH", 1, 1)
        cli.sendto(pkt, (args.host, args.dns_port))

        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                data, addr = srv.recvfrom(4096)
            except socket.timeout:
                continue
            qid = struct.unpack("!H", data[:2])[0]
            i = 12
            while i < len(data):
                l = data[i]
                if l == 0:
                    i += 1
                    break
                if l & 0xC0:
                    i += 2
                    break
                i += 1 + l
            question = data[12:i + 4] if i + 4 <= len(data) else b""
            srv.sendto(build_response(qid, question), addr)
            break
        srv.close()

        try:
            reply, _ = cli.recvfrom(4096)
        except socket.timeout:
            print("FAIL: response was discarded -- the short A record was "
                  "matched against bytes outside its own RDATA (regression)")
            return 1
        finally:
            cli.close()

        ancount = struct.unpack("!H", reply[6:8])[0]
        if ancount < 1:
            print("FAIL: answered with ANCOUNT=%d" % ancount)
            return 1
        print("OK: short A record skipped by the IP policy, "
              "response answered (ANCOUNT=%d)" % ancount)
        return 0
    finally:
        try:
            srv.close()
        except socket.error:
            pass


if __name__ == "__main__":
    sys.exit(main())
