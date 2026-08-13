/* A self-contained in-process mutation fuzzer for the DNS parser.
 *
 * It reads a seed packet from a file (argv[1], defaulting to a tiny built-in
 * query), then runs thousands of mutation iterations over that seed, exercising
 * DnsSimpleParser / DnsSimpleParserIterator and the textifying helpers the way
 * the real front-end does.  Build with AddressSanitizer + UndefinedBehaviorSanitizer
 * and let it run; any crash/oob/UB in the parser surface here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include "dnsparser.h"
#include "dnsrelated.h"

static unsigned long rng_state = 0x12345678UL;

static unsigned long rng(void)
{
    /* xorshift */
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
        if (n == 0) op = 1; /* force an insert if empty */
        if (op == 0 && n > 0)
        {
            /* flip a byte */
            int p = (int)((r >> 2) % n);
            buf[p] ^= (char)(1 + (r >> 10));
        }
        else if (op == 1 && n < 4096)
        {
            /* insert a byte */
            int p = (int)((r >> 2) % (n + 1));
            char v = (char)(r >> 12);
            memmove(buf + p + 1, buf + p, (size_t)(n - p));
            buf[p] = v;
            ++n;
        }
        else if (op == 2 && n > 0)
        {
            /* delete a byte */
            int p = (int)((r >> 2) % n);
            memmove(buf + p, buf + p + 1, (size_t)(n - p - 1));
            --n;
        }
        else
        {
            /* overwrite a byte */
            int p = (int)((r >> 2) % n);
            buf[p] = (char)(r >> 12);
        }
    }
    *len = n;
}

static void run_one(char *buf, int len)
{
    static char Out[65536];
    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    /* Try both UDP and TCP framing on the same bytes. */
    for (int tcp = 0; tcp < 2; ++tcp)
    {
        char *body = buf;
        int bodylen = len;
        if (tcp)
        {
            /* Prepend a 2-byte length prefix; if not enough room, skip. */
            if (len < 2) continue;
            body = buf + 2;
            bodylen = len - 2;
            uint16_t l = (uint16_t)bodylen;
            memcpy(buf, &l, 2);
        }

        if (DnsSimpleParser_Init(&p, body, bodylen, tcp ? TRUE : FALSE) != 0)
            continue;

        if (DnsSimpleParserIterator_Init(&i, &p) != 0)
            continue;

        char namebuf[2048];
        for (;;)
        {
            char *pos = i.Next(&i);
            if (pos == NULL) break;

            i.GetName(&i, namebuf, (int)sizeof(namebuf));
            i.GetName(&i, NULL, 0);
            char *row = i.RowData(&i);
            (void)row;
            i.TextifyData(&i, "%t: %v\n", Out, (int)sizeof(Out));
            i.ToCacheData(&i, Out, (int)sizeof(Out));
            (void)i.GetTTL(&i);
        }
    }

    GetAllAnswers(buf, len, Out, (int)sizeof(Out));
}

int main(int argc, char **argv)
{
    char seed[8192];
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
    if (seedlen == 0)
    {
        /* Minimal valid DNS query: header + 1 question "\x03www\x07example"
           null label, type A, class IN. */
        static const unsigned char q[] = {
            0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x03,'w','w','w',0x07,'e','x','a','m','p','l','e',0x00,
            0x00,0x01,0x00,0x01
        };
        memcpy(seed, q, sizeof(q));
        seedlen = (int)sizeof(q);
    }

    char work[9000];
    long iterations = 1500000;
    for (long it = 0; it < iterations; ++it)
    {
        int n = seedlen;
        if (n > (int)sizeof(work)) n = (int)sizeof(work);
        memcpy(work, seed, (size_t)n);
        /* Re-seed RNG per iteration so failures are reproducible from the seed. */
        rng_state = 0x12345678UL ^ (unsigned long)it;
        mutate(work, &n);
        run_one(work, n);
    }

    printf("fuzz ok\n");
    return 0;
}
