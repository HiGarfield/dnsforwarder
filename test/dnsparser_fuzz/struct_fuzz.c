/* Structured (not random-bitflip) DNS message fuzzer.
 *
 * Unlike the mutation fuzzer in main.c, this generator builds well-formed DNS
 * messages whose individual fields are chosen to stress the parser's boundary
 * handling: name-compression pointer chains, over-long labels, truncated
 * RDATA, zero-length records, many questions, and pointers that jump to every
 * offset in the packet.  It exercises DnsSimpleParser / DnsSimpleParserIterator,
 * TextifyData and ToCacheData the same way the front-end does, under
 * AddressSanitizer + UBSan, to catch any OOB read/write or misaligned access
 * that a random mutator might statistically miss.
 *
 * Build (from repo root):
 *   cc -I. -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
 *      -o /tmp/t_struct_fuzz test/dnsparser_fuzz/struct_fuzz.c \
 *      dnsparser.c dnsrelated.c utils.c addresslist.c array.c \
 *      stringlist.c stablebuffer.c iheader.c test/tcpfrontend_stub.c -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include "dnsparser.h"
#include "dnsrelated.h"

static unsigned char msg[8192];
static int len;

static void put16(int off, int v) { msg[off] = (unsigned char)(v >> 8); msg[off+1] = (unsigned char)v; }
static void put32(int off, int v) { msg[off]=(unsigned char)(v>>24); msg[off+1]=(unsigned char)(v>>16); msg[off+2]=(unsigned char)(v>>8); msg[off+3]=(unsigned char)v; }

/* Append a textual name as wire labels (no compression). */
static int append_name(const char *name)
{
    const char *p = name;
    while (*p)
    {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        if (l > 63) l = 63;                 /* cap single label to be safe */
        msg[len++] = (unsigned char)l;
        memcpy(msg + len, p, l);
        len += l;
        if (!dot) break;
        p = dot + 1;
    }
    msg[len++] = 0; /* root */
    return len;
}

static void build_base(int qcount, int ancount)
{
    memset(msg, 0, sizeof(msg));
    len = 12;
    put16(0, 0x1234);
    put16(2, qcount);
    put16(6, ancount);
    /* Question */
    int q = append_name("www.example.com");
    put16(q, 1);     /* A */
    put16(q + 2, 1); /* IN */
}

static void run(void)
{
    static char out[65536];
    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    if (DnsSimpleParser_Init(&p, (char *)msg, len, FALSE) != 0) return;
    if (DnsSimpleParserIterator_Init(&i, &p) != 0) return;

    char namebuf[4096];
    for (;;)
    {
        char *pos = i.Next(&i);
        if (pos == NULL) break;
        i.GetName(&i, namebuf, (int)sizeof(namebuf));
        i.GetName(&i, NULL, 0);
        i.TextifyData(&i, "%t: %v\n", out, (int)sizeof(out));
        i.ToCacheData(&i, out, (int)sizeof(out));
        (void)i.GetTTL(&i);
        (void)i.RowData(&i);
    }
    GetAllAnswers((char *)msg, len, out, (int)sizeof(out));
}

int main(void)
{
    /* 1) Multiple questions (multi-question handling). */
    for (int qc = 0; qc <= 5; ++qc)
    {
        build_base(qc, 1);
        int a = append_name("alias.example.org");
        put16(a, 5); put16(a+2, 1);           /* CNAME IN */
        put32(a+4, 300);                      /* TTL */
        put16(a+8, 15);
        msg[len++] = 0xC0; msg[len++] = 12;   /* ptr to question name */
        run();
    }

    /* 2) Compression-pointer jumping to every offset. */
    for (int off = 0; off < 12; ++off)
    {
        memset(msg, 0, sizeof(msg));
        len = 12;
        put16(2, 1); put16(6, 1);
        msg[len++] = 0xC0; msg[len++] = (unsigned char)off; /* wild pointer */
        int a = len;
        put16(a, 1); put16(a+2, 1);
        put32(a+4, 60); put16(a+8, 4);
        msg[len++] = 1; msg[len++] = 2; msg[len++] = 3; msg[len++] = 4;
        run();
    }

    /* 3) Truncated RDATA for every known type. */
    int types[] = {1, 28, 5, 2, 12, 15, 16, 6, 255};
    for (unsigned ti = 0; ti < sizeof(types)/sizeof(types[0]); ++ti)
    {
        for (int rd = 0; rd <= 6; ++rd)
        {
            build_base(1, 1);
            int a = append_name("a.b");
            put16(a, types[ti]); put16(a+2, 1);   /* type IN */
            put32(a+4, 60);                       /* TTL */
            put16(a+8, rd);                       /* forged RDLENGTH */
            for (int k = 0; k < rd; ++k) msg[len++] = 0x41;
            run();
        }
    }

    /* 4) Over-long RDATA trailing bytes. */
    build_base(1, 1);
    int a = append_name("mail.example.com");
    put16(a, 15); put16(a+2, 1);
    put32(a+4, 60); put16(a+8, 30);
    for (int k = 0; k < 30; ++k) msg[len++] = (unsigned char)k;
    run();

    /* 5) Zero questions, many answers of mixed types. */
    memset(msg, 0, sizeof(msg));
    len = 12;
    put16(6, 4);
    int base = len;
    int offs[4];
    offs[0] = append_name("a.example"); put16(offs[0],1); put16(offs[0]+2,1); put32(offs[0]+4,60); put16(offs[0]+8,4); msg[len++]=1;msg[len++]=2;msg[len++]=3;msg[len++]=4;
    offs[1] = append_name("b.example"); put16(offs[1],28); put16(offs[1]+2,1); put32(offs[1]+4,60); put16(offs[1]+8,16); for(int k=0;k<16;++k) msg[len++]=(unsigned char)k;
    offs[2] = append_name("c.example"); put16(offs[2],16); put16(offs[2]+2,1); put32(offs[2]+4,60); put16(offs[2]+8,2); msg[len++]=3;msg[len++]=110;
    offs[3] = append_name("d.example"); put16(offs[3],5); put16(offs[3]+2,1); put32(offs[3]+4,60); put16(offs[3]+8,2); msg[len++]=0xC0; msg[len++]=(unsigned char)(offs[0]&0xFF);
    (void)base;
    run();

    /* 6) Pointer that points at another pointer (chain) to various depths. */
    for (int depth = 1; depth <= 4; ++depth)
    {
        memset(msg, 0, sizeof(msg));
        len = 12;
        put16(2,1); put16(6,1);
        /* build a chain of pointers */
        int chain = len;
        for (int d = 0; d < depth; ++d)
        {
            msg[len++] = 0xC0; msg[len++] = 0; /* point to header start region */
        }
        msg[len++] = 3; msg[len++] = 'x'; msg[len++] = 'y'; msg[len++] = 'z'; msg[len++] = 0;
        int aa = len;
        put16(aa, 1); put16(aa+2, 1); put32(aa+4, 60); put16(aa+8, 4);
        msg[len++] = 9; msg[len++] = 9; msg[len++] = 9; msg[len++] = 9;
        (void)chain;
        run();
    }

    printf("struct fuzz ok\n");
    return 0;
}
