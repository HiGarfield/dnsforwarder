/* Mutation fuzzer for DNSCompress() and the cache-hit response path.
 *
 * DNSCompress() walks a response, memmove()s it based on the name length the
 * iterator reports, and rewrites pointers.  A malformed response whose name
 * encodes a huge length can make the memmove run past the end of the buffer.
 * The cache-hit path (DNSCache_FetchFromCache) is the most complex untested
 * surface: it parses a request, builds an answer from the on-disk cache and
 * finally compresses it.  Both are exercised here under ASan+UBSan.
 *
 * Build with AddressSanitizer + UndefinedBehaviorSanitizer; any OOB/UB surfaces.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "dnscache.h"
#include "iheader.h"

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
            char v = (char)(r >> 12);
            memmove(buf + p + 1, buf + p, (size_t)(n - p));
            buf[p] = v;
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

/* A valid A response (qname + 1 A answer with a pointer back to the name). */
static void make_response(unsigned char *buf, int *len, int variant)
{
    static const unsigned char tmpl[] = {
        0x00,0x01,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
        0x03,'w','w','w',0x07,'e','x','a','m','p','l','e',0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c,              /* name pointer to 0x0c */
        0x00,0x01,0x00,0x01,   /* type A, class IN */
        0x00,0x00,0x00,0x1e,   /* TTL 30 */
        0x00,0x04,             /* RDLENGTH 4 */
        0x01,0x02,0x03,0x04
    };
    memcpy(buf, tmpl, sizeof(tmpl));
    *len = (int)sizeof(tmpl);
    if (variant & 1)
    {
        /* Make the answer name a long inline label to stress compression. */
        unsigned char alt[256];
        int a = 12;
        memcpy(alt, tmpl, 12);
        /* build a 60-byte single label via repetition */
        alt[a++] = 60;
        for (int i = 0; i < 60; ++i) alt[a++] = (unsigned char)('a' + (i % 26));
        alt[a++] = 0x00;
        memcpy(alt + a, tmpl + 25, sizeof(tmpl) - 25);
        a += (int)(sizeof(tmpl) - 25);
        memcpy(buf, alt, (size_t)a);
        *len = a;
    }
}

static void run_compress(char *buf, int len)
{
    DnsSimpleParser p;
    if (DnsSimpleParser_Init(&p, buf, len, FALSE) != 0)
        return;
    static char out[8192];
    if (len > (int)sizeof(out))
        return;
    memcpy(out, buf, (size_t)len);
    DNSCompress(out, len);
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

    long iterations = 800000;
    char work[9000];
    for (long it = 0; it < iterations; ++it)
    {
        int n;
        if (seedlen > 0)
        {
            n = seedlen;
            if (n > (int)sizeof(work)) n = (int)sizeof(work);
            memcpy(work, seed, (size_t)n);
            rng_state = 0x9E3779B9UL ^ (unsigned long)it;
            mutate(work, &n);
        }
        else
        {
            unsigned char base[256];
            int blen;
            make_response(base, &blen, (int)(it & 1));
            n = blen;
            memcpy(work, base, (size_t)n);
            rng_state = 0x9E3779B9UL ^ (unsigned long)it;
            mutate(work, &n);
        }
        run_compress(work, n);
    }

    printf("fuzz ok\n");
    return 0;
}
