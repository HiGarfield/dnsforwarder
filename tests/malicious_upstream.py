#!/usr/bin/env python3
"""A deliberately hostile upstream DNS server.

dnsforwarder forwards client queries to its configured upstream servers and
parses whatever comes back.  That response path (IHeader_Fill ->
IPMiscMapping_Process -> GenAnswerHeaderAndRemove -> DNSCache_AddItemsToCache
-> MsgContext_SendBack, plus the GetAllAnswers() logging path) is reached with
fully attacker-controlled bytes, yet it is invisible to a client-side fuzzer.

This process binds a UDP socket and answers every query with the next entry
of a corpus of malformed responses, keeping the transaction ID (and the
question section when one can be extracted) so the reply is accepted and
handed to the parsing code.

Usage:
    python3 tests/malicious_upstream.py [--host 127.0.0.1] [--port 15354]
                                        [--corpus FILE]
"""

import argparse
import os
import random
import socket
import struct
import sys
import time

# ---------------------------------------------------------------- corpus
# Functions receive (qid, question_bytes) and return a raw response.


def _h(qid, flags=0x8180, qd=1, an=1, ns=0, ar=0):
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def qname(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_corpus():
    c = []

    def fixed(payload_builder):
        c.append(payload_builder)

    # --- header / counts --------------------------------------------------
    fixed(lambda qid, q: b"")
    fixed(lambda qid, q: b"\x00" * 11)
    fixed(lambda qid, q: _h(qid, qd=1, an=0))
    fixed(lambda qid, q: _h(qid, qd=0xFFFF, an=0xFFFF, ns=0xFFFF, ar=0xFFFF))
    fixed(lambda qid, q: _h(qid, qd=1, an=1) + q)  # ANCOUNT=1, no answer

    # --- compression pointer abuse ---------------------------------------
    fixed(lambda qid, q: _h(qid, qd=1, an=1) + q + b"\xc0\x0c" + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04")
    fixed(lambda qid, q: _h(qid, qd=1, an=1) + q + b"\xc0\xff\x00")
    # pointer at offset 12 (start of the question) referencing itself
    fixed(lambda qid, q: _h(qid, qd=1, an=1) + q + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04")
    # two pointers that reference each other
    fixed(lambda qid, q: _h(qid, qd=1, an=1) + q + b"\xc0\x1c\xc0\x1a\x00\x01\x00\x01")
    # pointer chain: a -> b -> a ...
    fixed(lambda qid, q: _h(qid, qd=1, an=1) + q + b"\xc0\x1e\xc0\x1c\xc0\x1e\x00\x01\x00\x01")

    # --- RDLENGTH lies -----------------------------------------------------
    for rrtype, rdlen, tail in (
        (1, 0xFFFF, b""),          # A, RDLENGTH 65535
        (1, 1, b"\x01"),           # A, RDLENGTH 1
        (1, 3, b"\x01\x02\x03"),   # A, RDLENGTH 3
        (28, 4, b"\x01\x02\x03\x04"),  # AAAA, RDLENGTH 4
        (28, 0xFFFF, b""),         # AAAA, RDLENGTH 65535
        (5, 0, b""),               # CNAME, RDLENGTH 0
        (5, 1, b"\x00"),           # CNAME, RDLENGTH 1 (root only)
        (5, 2, b"\xc0\x0c"),       # CNAME target is a self pointer
        (5, 2, b"\x40\x00"),       # CNAME target has a bad label length
        (15, 1, b"\x00"),          # MX without the preference word
        (15, 3, b"\x00\x00\x40"),  # MX: preference + bad label length
        (6, 4, b"\x00\x00\x00\x00"),  # truncated SOA
        (16, 3, b"\x05ab"),        # TXT: length byte runs past RDATA
        (16, 0xFFFF, b""),         # TXT: huge RDLENGTH
        (16, 1, b"\xff"),          # TXT: 255-octet string, 1 byte of RDATA
        (99, 0xFFF0, b""),         # unknown type, huge RDLENGTH
    ):
        fixed(
            lambda qid, q, t=rrtype, l=rdlen, x=tail: _h(qid, qd=1, an=1)
            + q
            + qname("a.example")
            + struct.pack("!HHIH", t, 1, 60, l)
            + x
        )

    # --- many records / oversized -----------------------------------------
    fixed(
        lambda qid, q: _h(qid, qd=1, an=0xFFFF)
        + q
        + (qname("a.example") + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04") * 3
    )
    # an answer whose name expands to more than 255 octets (no cap in
    # DNSCopyLable) - exercises the generator's destination bounds.
    big = b"".join(bytes([63]) + b"a" * 63 for _ in range(8))
    fixed(
        lambda qid, q, big=big: _h(qid, qd=1, an=1)
        + q
        + big
        + b"\x00"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + b"\x01\x02\x03\x04"
    )
    # A record whose owner name is a pointer to the *end* of the message
    fixed(lambda qid, q: _h(qid, qd=1, an=1) + q + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04")

    # --- OPT / EDNS --------------------------------------------------------
    fixed(lambda qid, q: _h(qid, qd=1, an=1, ar=1) + q + qname("a.example") + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04" + b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0xFF00))
    fixed(lambda qid, q: _h(qid, qd=1, an=1, ar=1) + q + qname("a.example") + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04" + b"\xc0\x0c" + struct.pack("!HHIH", 41, 4096, 0, 0))

    # --- random noise ------------------------------------------------------
    rnd = random.Random(0xC0FFEE)
    for i in range(400):
        n = rnd.randrange(0, 400)
        blob = bytes(rnd.randrange(256) for _ in range(n))
        fixed(lambda qid, q, blob=blob: _h(qid, qd=1, an=1) + q + blob)
    for i in range(400):
        n = rnd.randrange(0, 400)
        blob = bytes(rnd.randrange(256) for _ in range(n))
        fixed(
            lambda qid, q, blob=blob: _h(
                qid,
                qd=rnd.randrange(3),
                an=rnd.randrange(3),
                ns=rnd.randrange(3),
                ar=rnd.randrange(3),
            )
            + blob
        )

    return c


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15354)
    ap.add_argument("--stop-after", type=int, default=0, help="exit after N replies")
    args = ap.parse_args()

    corpus = build_corpus()
    idx = 0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.settimeout(0.5)

    print("malicious upstream listening on %s:%d, %d corpus entries"
          % (args.host, args.port, len(corpus)), flush=True)

    served = 0
    while True:
        if args.stop_after and served >= args.stop_after:
            break
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except socket.error:
            break

        if len(data) < 12:
            continue
        qid, _flags, qdcount = struct.unpack("!HHH", data[:6])

        # Extract the first question (name + 4 bytes) so replies look sane.
        q = b""
        if qdcount > 0:
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
            if i + 4 <= len(data):
                q = data[12:i + 4]

        builder = corpus[idx % len(corpus)]
        idx += 1
        try:
            reply = builder(qid, q)
        except Exception as exc:  # pragma: no cover - corpus bug
            print("corpus builder failed: %r" % (exc,), flush=True)
            continue
        try:
            s.sendto(reply, addr)
        except socket.error:
            pass
        served += 1
        print("reply %d: %d bytes (idx %d)" % (served, len(reply), idx - 1), flush=True)

    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
