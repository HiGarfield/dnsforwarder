/* Regression test for IpChunk overlapping CIDR handling.
 *
 * The old Contain() comparator masked the network to the EXISTING element's
 * prefix only, so a contained range (e.g. 10.1.0.0/16 added after
 * 10.0.0.0/8) compared equal and was silently dropped by Bst_Add, losing the
 * more specific rule.  Find() also relied on that faulty "equal means
 * contained" comparison.
 *
 * This test verifies that:
 *   - both 10.0.0.0/8 and 10.1.0.0/16 coexist,
 *   - a query inside only /8 matches type 8,
 *   - a query inside /16 matches the most specific type 16 (longest prefix),
 *   - single-IP exact matches and non-matches behave.
 *
 * Build (from the project root):
 *   cc -I. -o /tmp/t_ipchunk test/ipchunk/main.c ipchunk.c bst.c array.c \
 *       utils.c addresslist.c stringlist.c stablebuffer.c -lpthread
 */
#include <stdio.h>
#include <string.h>
#include "ipchunk.h"

static int fail(const char *msg)
{
    fprintf(stderr, "IpChunk FAILED: %s\n", msg);
    return 1;
}

int main(void)
{
    IpChunk ic;
    int type;
    unsigned char ip[16];
    int rc = 0;

    if( IpChunk_Init(&ic) != 0 )
    {
        return fail("IpChunk_Init");
    }

    /* Broad range + more specific range that is contained in it. */
    if( IpChunk_Add(&ic, "10.0.0.0/8", 8, "broad", 5) != 0 )
        return fail("add 10.0.0.0/8");
    if( IpChunk_Add(&ic, "10.1.0.0/16", 16, "specific", 8) != 0 )
        return fail("add 10.1.0.0/16");

    /* Query inside the /16 only (not inside /8-exclusive? it is inside /8 too,
       but the most specific match must win). */
    memset(ip, 0, sizeof(ip));
    ip[0] = 10; ip[1] = 1; ip[2] = 2; ip[3] = 3;
    if( IpChunk_Find(&ic, ip, 4, &type, NULL) == FALSE )
        return fail("Find 10.1.2.3 should match");
    if( type != 16 )
        return fail("Find 10.1.2.3 should match most-specific /16 (got type != 16)");

    /* Query inside /8 but outside /16: must match the /8 rule. */
    memset(ip, 0, sizeof(ip));
    ip[0] = 10; ip[1] = 5; ip[2] = 5; ip[3] = 5;
    if( IpChunk_Find(&ic, ip, 4, &type, NULL) == FALSE )
        return fail("Find 10.5.5.5 should match /8");
    if( type != 8 )
        return fail("Find 10.5.5.5 should match /8 (got type != 8)");

    /* Single IP exact match. */
    if( IpChunk_Add(&ic, "192.168.1.1", 99, "host", 4) != 0 )
        return fail("add 192.168.1.1");
    memset(ip, 0, sizeof(ip));
    ip[0] = 192; ip[1] = 168; ip[2] = 1; ip[3] = 1;
    if( IpChunk_Find(&ic, ip, 4, &type, NULL) == FALSE )
        return fail("Find 192.168.1.1 should match");
    if( type != 99 )
        return fail("Find 192.168.1.1 should match single-IP type 99");

    /* Single IP that is not configured must not match. */
    memset(ip, 0, sizeof(ip));
    ip[0] = 192; ip[1] = 168; ip[2] = 1; ip[3] = 2;
    if( IpChunk_Find(&ic, ip, 4, &type, NULL) != FALSE )
        return fail("Find 192.168.1.2 must NOT match");

    /* Unrelated address must not match. */
    memset(ip, 0, sizeof(ip));
    ip[0] = 8; ip[1] = 8; ip[2] = 8; ip[3] = 8;
    if( IpChunk_Find(&ic, ip, 4, &type, NULL) != FALSE )
        return fail("Find 8.8.8.8 must NOT match");

    /* IPv6 nested ranges. */
    if( IpChunk_Add(&ic, "2001:db8::/32", 32, "v6broad", 7) != 0 )
        return fail("add 2001:db8::/32");
    if( IpChunk_Add(&ic, "2001:db8:1::/48", 48, "v6spec", 7) != 0 )
        return fail("add 2001:db8:1::/48");
    memset(ip, 0, sizeof(ip));
    /* 2001:0db8:0001:0000:... */
    ip[0] = 0x20; ip[1] = 0x01; ip[2] = 0x0d; ip[3] = 0xb8;
    ip[4] = 0x00; ip[5] = 0x01;
    if( IpChunk_Find(&ic, ip, 16, &type, NULL) == FALSE )
        return fail("Find 2001:db8:1:: must match");
    if( type != 48 )
        return fail("Find 2001:db8:1:: should match most-specific /48 (got type != 48)");

    IpChunk_Free(&ic);

    printf("IpChunk OK\n");
    return rc;
}
