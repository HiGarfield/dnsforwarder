/* Mutation fuzzer for the IP/CIDR string parsers (IpAddr_Parse / IpSet_Parse /
 * IpChunk_Add).  These parse attacker-influenced strings (hosts files, option
 * lines), so feed them garbage under ASan+UBSan.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include "ipchunk.h"

static unsigned long rng_state = 0x9e3779b9UL;

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
        if (op == 0 && n > 0)      buf[(int)((r >> 2) % n)] ^= (char)(1 + (r >> 10));
        else if (op == 1 && n < 2048) { int p = (int)((r >> 2) % (n + 1)); memmove(buf + p + 1, buf + p, (size_t)(n - p)); buf[p] = (char)(r >> 12); ++n; }
        else if (op == 2 && n > 0) { int p = (int)((r >> 2) % n); memmove(buf + p, buf + p + 1, (size_t)(n - p - 1)); --n; }
        else buf[(int)((r >> 2) % n)] = (char)(r >> 12);
    }
    *len = n;
}

static void run_one(const char *s)
{
    IpAddr a;
    (void)IpAddr_Parse(s, &a);

    IpSet set;
    /* Try to split on '/' for IpSet_Parse. */
    char buf[2048];
    int l = (int)strlen(s);
    if (l >= (int)sizeof(buf)) l = (int)sizeof(buf) - 1;
    memcpy(buf, s, (size_t)l);
    buf[l] = '\0';
    char *slash = strchr(buf, '/');
    char *prefix = NULL;
    if (slash) { *slash = '\0'; prefix = slash + 1; }
    (void)IpSet_Parse(buf, prefix, &set);

    IpChunk ic;
    if (IpChunk_Init(&ic) == 0)
    {
        IpChunk_Add(&ic, s, 0, "data", 4);
        unsigned char v4[4] = {1,2,3,4};
        int type; const char *data;
        (void)IpChunk_Find(&ic, v4, 4, &type, &data);
        IpChunk_Free(&ic);
    }
}

int main(int argc, char **argv)
{
    char seed[2048];
    int seedlen = 0;
    if (argc > 1)
    {
        FILE *f = fopen(argv[1], "rb");
        if (f) { seedlen = (int)fread(seed, 1, sizeof(seed), f); fclose(f); }
    }
    if (seedlen == 0)
    {
        const char *d = "192.168.1.1/24";
        memcpy(seed, d, strlen(d));
        seedlen = (int)strlen(d);
    }

    char work[3000];
    for (long it = 0; it < 1000000; ++it)
    {
        int n = seedlen < (int)sizeof(work) ? seedlen : (int)sizeof(work);
        memcpy(work, seed, (size_t)n);
        rng_state = 0x9e3779b9UL ^ (unsigned long)it;
        mutate(work, &n);
        work[n] = '\0';
        run_one(work);
    }

    printf("ipchunk fuzz ok\n");
    return 0;
}
