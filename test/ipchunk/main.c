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

    /* Regression test: IpSet_Parse must reject a negative prefix length instead
     * of storing PrefixBits = -1.  A PrefixBits = -1 entry is accepted by
     * IpChunk_Add yet can never match any query key (IpChunk_Find only builds
     * keys with PrefixBits >= 0), so it would be a silent dead rule that makes
     * a configured block/substitution vanish without any diagnostic.  See the
     * round-review fix in ipchunk.c. */
    {
        IpSet bad;
        if( IpSet_Parse("10.0.0.0", "-5", &bad) == 0 )
            return fail("IpSet_Parse must reject negative prefix '/-5'");
        if( IpSet_Parse("10.0.0.0", "-1", &bad) == 0 )
            return fail("IpSet_Parse must reject negative prefix '/-1'");
        /* Out-of-range but non-negative lengths must still clamp, not fail. */
        {
            IpSet ok;
            if( IpSet_Parse("10.0.0.0", "8", &ok) != 0 || ok.PrefixBits != 8 )
                return fail("IpSet_Parse '/8' should clamp to PrefixBits=8");
            /* atoi("abc") == 0 -> /0, a valid whole-network entry. */
            if( IpSet_Parse("10.0.0.0", "abc", &ok) != 0 || ok.PrefixBits != 0 )
                return fail("IpSet_Parse '/abc' should fall back to /0");
        }
    }

    /* Regression test: IpAddr_From4 must not assume its 4 source octets are
     * 32-bit aligned.  The old code did
     *   *(uint32_t *)(ipAddr->Addr + 12) = *(uint32_t *)Addr;
     * which is a strict-aliasing violation and an unaligned load that SIGBUSes
     * on strict-alignment targets (DNS wire data is often unaligned).  We put
     * the source bytes at an odd offset so a naive uint32_t* read would be
     * misaligned, then verify the copied value is still exact. */
    {
        unsigned char buf[8];
        unsigned char *src = buf + 1;            /* deliberately odd offset */
        IpAddr a;
        int i, ok = 1;

        src[0] = 198; src[1] = 51; src[2] = 100; src[3] = 206;  /* 198.51.100.206 */

        memset(&a, 0xaa, sizeof(a));
        IpAddr_From4(src, &a);

        if( a.Addr[10] != 0xff || a.Addr[11] != 0xff )
            ok = 0;
        for( i = 0; i < 4 && ok; ++i )
            if( a.Addr[12 + i] != src[i] )
                ok = 0;

        if( !ok )
            return fail("IpAddr_From4 misaligned source produced wrong ::ffff address");

        /* Also confirm a normally-aligned source still works (no regression). */
        {
            unsigned char aligned[4] = { 10, 0, 0, 1 };
            IpAddr b;
            memset(&b, 0, sizeof(b));
            IpAddr_From4(aligned, &b);
            if( b.Addr[10] != 0xff || b.Addr[11] != 0xff ||
                b.Addr[12] != 10 || b.Addr[13] != 0 ||
                b.Addr[14] != 0 || b.Addr[15] != 1 )
                return fail("IpAddr_From4 aligned source regressed");
        }
    }

    printf("IpChunk OK\n");
    return rc;
}
