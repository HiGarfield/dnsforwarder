#!/usr/bin/env python3
"""A well-behaved upstream DNS server used by the regression tests.

Answers every query it receives with a single A record, echoing back the
question section and the transaction ID, which is what dnsforwarder's
forwarding path expects.

Usage:
    python3 tests/good_upstream.py [--host 127.0.0.1] [--port 15354]
                                   [--ip 203.0.113.9]
"""

import argparse
import socket
import struct
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15354)
    ap.add_argument("--ip", default="203.0.113.9")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.settimeout(0.5)
    print("good upstream on %s:%d" % (args.host, args.port), flush=True)

    while True:
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except socket.error:
            break
        if len(data) < 12:
            continue
        qid = struct.unpack("!H", data[:2])[0]

        # Locate the end of the first question (or of the header when there
        # is none) so the question section can be echoed back verbatim.
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

        reply = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question
        # answer: owner name = pointer to the question, type A, class IN,
        # TTL 300, RDLENGTH 4
        reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4)
        reply += socket.inet_aton(args.ip)
        try:
            s.sendto(reply, addr)
        except socket.error:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
