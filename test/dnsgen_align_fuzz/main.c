/* Fuzz the DNS generator path (DNSLabelizedName / DnsGenerator_* / DNSCompress)
 * under AddressSanitizer + UBSan to surface any out-of-bounds write, over-read
 * or misaligned access triggered by crafted domain names, RDATA and answers.
 *
 * Build (from repo root):
 *   cc -I. -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
 *      -o /tmp/t_dnsgen_fuzz test/dnsgen_align_fuzz/main.c \
 *      dnsgenerator.c dnsparser.c dnsrelated.c utils.c addresslist.c \
 *      array.c stringlist.c stablebuffer.c iheader.c -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include "dnsgenerator.h"
#include "dnsparser.h"
#include "dnsrelated.h"

#define SOCKET_CONTEXT_LENGTH 4096

static unsigned long rng_state = 0x9E3779B9UL;
static unsigned long rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void mutate(char *buf, int *len)
{
    int n = *len;
    int ops = (int)(rng() % 6) + 1;
    for (int k = 0; k < ops; ++k)
    {
        unsigned long r = rng();
        int op = (int)(r & 3);
        if (n == 0) op = 1;
        if (op == 0 && n > 0)
        {
            int p = (int)((r >> 2) % n);
            buf[p] ^= (char)(1 + (r >> 10));
        }
        else if (op == 1 && n < 4096)
        {
            int p = (int)((r >> 2) % (n + 1));
            memmove(buf + p + 1, buf + p, (size_t)(n - p));
            buf[p] = (char)(r >> 12);
            ++n;
        }
        else if (op == 2 && n > 0)
        {
            int p = (int)((r >> 2) % n);
            memmove(buf + p, buf + p + 1, (size_t)(n - p - 1));
            --n;
        }
        else
        {
            int p = (int)((r >> 2) % n);
            buf[p] = (char)(r >> 12);
        }
    }
    *len = n;
}

/* Exercise DNSLabelizedName + DnsGenerator copy helpers with a crafted name. */
static void try_name(const char *name)
{
    char buf[600];
    /* The generator writes wire data into a buffer that must hold the
       labelized name; make sure it is big enough and NUL terminated first. */
    memset(buf, 0, sizeof(buf));
    strncpy(buf, name, sizeof(buf) - 2);
    buf[sizeof(buf) - 1] = '\0';

    char *r = DNSLabelizedName(buf, sizeof(buf));
    if (r == NULL)
        return; /* rejected, as expected for oversized input */

    /* Now build a full response message around the name and compress it. */
    char msg[2048];
    DnsGenerator g;
    static const unsigned char hdr[12] = {0};
    memcpy(msg, hdr, sizeof(hdr));
    if (DnsGenerator_Init(&g, msg + sizeof(hdr) - 12, sizeof(msg) - sizeof(hdr) + 12,
                           NULL, 0, FALSE) != 0)
        return;
    /* Re-feed the header bytes properly. */
    if (DnsGenerator_Init(&g, msg, sizeof(msg), NULL, 0, FALSE) != 0)
        return;

    g.Question(&g, name, DNS_TYPE_A, DNS_CLASS_IN);
    g.NextPurpose(&g);
    g.A(&g, name, "1.2.3.4", 300);
    g.NextPurpose(&g);
    g.A(&g, name, "5.6.7.8", 300);

    int len = g.Length(&g);
    if (len > 0 && len < (int)sizeof(msg))
    {
        DNSCompress(msg, len);
    }
}

/* Run the textify/cache consumers over a crafted response packet. */
static void try_packet(const char *raw, int len)
{
    char out[4096];
    GetAllAnswers((char *)raw, len, out, sizeof(out));
}

int main(int argc, char **argv)
{
    char seed[2048];
    int seedlen = 0;

    if (argc > 1)
    {
        FILE *f = fopen(argv[1], "rb");
        if (f)
        {
            seedlen = (int)fread(seed, 1, sizeof(seed), f);
            fclose(f);
        }
    }

    /* Seed 1: a plausible A response with two answers. */
    static const unsigned char base[] = {
        0x00,0x01,0x81,0x80,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00,
        0x03,'w','w','w',0x07,'e','x','a','m','p','l','e',0x00,
        0x00,0x01,0x00,0x01,
        0xC0,0x0C,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2C,0x00,0x04,
        0x01,0x02,0x03,0x04,
        0xC0,0x0C,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2C,0x00,0x04,
        0x05,0x06,0x07,0x08
    };
    if (seedlen == 0)
    {
        memcpy(seed, base, sizeof(base));
        seedlen = (int)sizeof(base);
    }

    /* A pile of candidate domain names (some adversarial). */
    const char *names[] = {
        "www.example.com",
        "",
        ".",
        "a",
        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
        "*",
        "*.example.com",
        "a..b",
        "x.y.z",
        NULL
    };
    for (int i = 0; names[i] != NULL; ++i)
        try_name(names[i]);

    char work[2500];
    long iterations = 800000;
    for (long it = 0; it < iterations; ++it)
    {
        int n = seedlen;
        if (n > (int)sizeof(work)) n = (int)sizeof(work);
        memcpy(work, seed, (size_t)n);
        rng_state = 0x9E3779B9UL ^ (unsigned long)it;
        mutate(work, &n);
        try_name(work);
        try_packet(work, n);
    }

    printf("fuzz ok\n");
    return 0;
}
