/* Regression test: DnsGenerator_A / DnsGenerator_AAAA must reject a
   malformed IP literal instead of emitting it as a record.

   Bug: DnsGenerator_IPv4() / DnsGenerator_IPv6() wrote the bytes returned by
   IPv4AddressToNum() / IPv6AddressToNum() and ignored the return value, so a
   malformed literal (e.g. "1.2.3" or "not-an-ip") was emitted as a bogus
   (or all-zero) A/AAAA record and reported success.

   Fix: both helpers check the parser's return (4 / 16 bytes) and fail the
   record on a mismatch; DnsGenerator_A / DnsGenerator_AAAA then propagate
   the error as -6.

   The static declarations of dnsgenerator.c are exposed (via the #define
   static trick) so the test can call DnsGenerator_A / DnsGenerator_AAAA
   directly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Headers used by dnsgenerator.c -- included BEFORE the static-export trick
   so their own static declarations (e.g. the static inline getters in
   dnsparser.h) are left untouched and do not become undefined externals. */
#include "dnsgenerator.h"
#include "utils.h"
#include "dnsparser.h"

#define static
#include "../../dnsgenerator.c"
#undef static

static int Checks = 0;
static int Failures = 0;

#define CHECK(cond, msg) do { \
    ++Checks; \
    if( !(cond) ) { \
        printf("FAIL: %s\n", msg); \
        ++Failures; \
    } else { \
        printf("PASS: %s\n", msg); \
    } \
} while(0)

/* Fresh generator, advanced to the ANSWER section. */
static int Setup(DnsGenerator *g, char *Buffer, int BufferLength)
{
    if( DnsGenerator_Init(g, Buffer, BufferLength, NULL, 0, FALSE) != 0 )
    {
        return -1;
    }
    g->NextPurpose(g);
    return 0;
}

int main(void)
{
    DnsGenerator g;
    char Buffer[512];

    printf("== DnsGenerator A/AAAA IP-literal validation test ==\n\n");

    /* Valid IPv4 must succeed and land 1.2.3.4 in the payload. */
    memset(Buffer, 0, sizeof(Buffer));
    if( Setup(&g, Buffer, sizeof(Buffer)) != 0 )
    {
        printf("FAIL: DnsGenerator_Init\n");
        return 2;
    }
    CHECK(DnsGenerator_A(&g, "host.example.com", "1.2.3.4", 300) == 0,
          "a valid IPv4 literal is accepted");
    CHECK(g.Itr[-4] == 1 && g.Itr[-3] == 2 && g.Itr[-2] == 3 && g.Itr[-1] == 4,
          "the A payload holds the parsed octets");

    /* Malformed IPv4 must be rejected, not silently truncated. */
    memset(Buffer, 0, sizeof(Buffer));
    if( Setup(&g, Buffer, sizeof(Buffer)) != 0 )
    {
        printf("FAIL: DnsGenerator_Init\n");
        return 2;
    }
    CHECK(DnsGenerator_A(&g, "host.example.com", "1.2.3", 300) == -6,
          "a truncated IPv4 literal is rejected");

    memset(Buffer, 0, sizeof(Buffer));
    if( Setup(&g, Buffer, sizeof(Buffer)) != 0 )
    {
        printf("FAIL: DnsGenerator_Init\n");
        return 2;
    }
    CHECK(DnsGenerator_A(&g, "host.example.com", "999.1.1.1", 300) == -6,
          "an out-of-range IPv4 literal is rejected");

    /* Valid IPv6 must succeed. */
    memset(Buffer, 0, sizeof(Buffer));
    if( Setup(&g, Buffer, sizeof(Buffer)) != 0 )
    {
        printf("FAIL: DnsGenerator_Init\n");
        return 2;
    }
    CHECK(DnsGenerator_AAAA(&g, "host.example.com", "2001:db8::1", 300) == 0,
          "a valid IPv6 literal is accepted");

    /* Malformed IPv6 must be rejected instead of becoming an all-zero AAAA. */
    memset(Buffer, 0, sizeof(Buffer));
    if( Setup(&g, Buffer, sizeof(Buffer)) != 0 )
    {
        printf("FAIL: DnsGenerator_Init\n");
        return 2;
    }
    CHECK(DnsGenerator_AAAA(&g, "host.example.com", "not-an-ip", 300) == -6,
          "a malformed IPv6 literal is rejected");

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
