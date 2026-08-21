/* Regression test: zone-qualified IPv6 entries must match wire queries.
 *
 * IpChunk keys built by IpChunk_Find come from raw DNS answer bytes, which
 * never carry a scope zone (RFC 6874).  IpSet_Parse, however, stripped the
 * zone only for prefixed IPv6 entries ("fe80::1%eth0/64"), leaving a
 * zone-qualified single IP ("fe80::1%eth0") stored WITH its zone.  The
 * Contain() comparator then orders a zone-less query key as unequal to that
 * stored zone'd entry, so the configured rule never matched any query and
 * silently did nothing -- while the prefixed form did match (zone stripped).
 *
 * The fix strips the zone for every IPv6 entry, single-IP and CIDR alike, so
 * zone'd entries behave exactly like their zone-less counterparts.
 *
 * This test locks the contract:
 *   - "fe80::1%eth0" (zone-qualified single IP) matches a query for fe80::1;
 *   - two zone'd entries of the same address match the same query (first
 *     rule wins, no crash);
 *   - zone-qualified CIDRs still match;
 *   - plain IPv4 / IPv6 matching is unaffected.
 *
 * Build (from the project root):
 *   cc -I. -o /tmp/t_ipchunk_zone test/ipchunk_zone/main.c ipchunk.c bst.c \
 *      array.c utils.c stablebuffer.c -lpthread
 */
#include <stdio.h>
#include <string.h>
#include "ipchunk.h"

static int CheckCount = 0;
static int FailCount = 0;

static void Check(int Cond, const char *Msg)
{
    ++CheckCount;
    if( Cond )
    {
        printf("  [ ok ] %s\n", Msg);
    } else {
        printf("  [FAIL] %s\n", Msg);
        ++FailCount;
    }
}

int main(void)
{
    IpChunk ic;
    int type;
    unsigned char fe801[16];    /* fe80::1 */
    unsigned char fe802[16];    /* fe80::2 */

    memset(fe801, 0, sizeof(fe801));
    fe801[0] = 0xfe; fe801[1] = 0x80; fe801[15] = 0x01;
    memset(fe802, 0, sizeof(fe802));
    fe802[0] = 0xfe; fe802[1] = 0x80; fe802[15] = 0x02;

    if( IpChunk_Init(&ic) != 0 )
    {
        fprintf(stderr, "IpChunk_Init failed\n");
        return 1;
    }

    /* --- zone-qualified single IPv6 must be matchable by a zone-less wire
       query.  The old code stored it with its zone and it never matched. --- */
    Check(IpChunk_Add(&ic, "fe80::1%eth0", 1, "zone1", 5) == 0,
          "add fe80::1%eth0 (single IP)");
    type = -1;
    Check(IpChunk_Find(&ic, fe801, 16, &type, NULL) == TRUE,
          "Find fe80::1 matches the zone-qualified single IP");
    Check(type == 1, "zone-qualified single IP match type == 1");

    /* --- a second zone-qualified entry of the same address must coexist
       (no crash) and the first rule wins. --- */
    Check(IpChunk_Add(&ic, "fe80::1%eth1", 2, "zone2", 5) == 0,
          "add fe80::1%eth1 (same address, other zone)");
    type = -1;
    Check(IpChunk_Find(&ic, fe801, 16, &type, NULL) == TRUE,
          "Find fe80::1 still matches after adding the other zone");
    Check(type == 1, "first-added rule wins for equal addresses");

    /* --- zone-qualified CIDR still matches. --- */
    Check(IpChunk_Add(&ic, "fe80::2%eth0/64", 3, "zonecidr", 8) == 0,
          "add fe80::2%eth0/64 (CIDR)");
    type = -1;
    Check(IpChunk_Find(&ic, fe802, 16, &type, NULL) == TRUE,
          "Find fe80::2 matches the zone-qualified CIDR");
    Check(type == 3, "zone-qualified CIDR match type == 3");

    /* --- an unrelated link-local address must NOT match. --- */
    {
        unsigned char fe811[16];
        memset(fe811, 0, sizeof(fe811));
        fe811[0] = 0xfe; fe811[1] = 0x81; fe811[15] = 0x01;   /* fe81::1 */
        Check(IpChunk_Find(&ic, fe811, 16, &type, NULL) == FALSE,
              "Find fe81::1 must NOT match");
    }

    /* --- plain IPv4 / IPv6 behavior unchanged. --- */
    Check(IpChunk_Add(&ic, "192.168.2.1", 4, "v4", 2) == 0,
          "add 192.168.2.1");
    {
        unsigned char v4[4] = { 192, 168, 2, 1 };
        Check(IpChunk_Find(&ic, v4, 4, &type, NULL) == TRUE &&
              type == 4,
              "Find 192.168.2.1 still matches (IPv4 unaffected)");
    }
    Check(IpChunk_Add(&ic, "2001:db8::1", 5, "plain6", 6) == 0,
          "add 2001:db8::1 (plain IPv6)");
    {
        unsigned char v6[16];
        memset(v6, 0, sizeof(v6));
        v6[0] = 0x20; v6[1] = 0x01; v6[2] = 0x0d; v6[3] = 0xb8; v6[15] = 0x01;
        Check(IpChunk_Find(&ic, v6, 16, &type, NULL) == TRUE &&
              type == 5,
              "Find 2001:db8::1 still matches (plain IPv6 unaffected)");
    }

    IpChunk_Free(&ic);

    printf("\n%d checks, %d failure(s)\n", CheckCount, FailCount);
    return FailCount == 0 ? 0 : 1;
}
