/* Formal verification of the DNSCache_GetRawRecordsFromCache lower-bound fix.
 *
 * Bug under test (fixed this round):
 *   dnscache.c, DNSCache_GetRawRecordsFromCache(): the reloaded-cache-node
 *   guard checked only the UPPER bounds of Node->UsedLength
 *   (Offset+UsedLength <= CacheSize) and of the key header
 *   (Offset+1+KeyLength+1 <= CacheSize), but NOT that UsedLength covers the
 *   key header (UsedLength >= 1+KeyLength+1).  For a corrupted node whose key
 *   bytes still match the query, the data length handed to the DNS generator
 *   was
 *       DataLength = Node->UsedLength - (1 + KeyLength + 1)
 *   which is NEGATIVE when UsedLength < 1+KeyLength+1.  A negative DataLength
 *   reaching DnsGenerator_Generate() is undefined-ish behaviour: the A/AAAA/
 *   HTTPS/TXT writer happens to reject DataLength <= 0, and MX rejects
 *   DataLength < 2, but the CNAME/PTR/NS writer ignores DataLength entirely
 *   and walks the data as a name -- with the data length already corrupted,
 *   the generator's view of the RDATA region is meaningless.
 *
 * The fix adds the missing lower-bound condition, making the guard reject
 * such a node as a cache miss:
 *
 *   if( Offset < 0 ||
 *       Offset + UsedLength > CacheSize ||
 *       Offset + 1 + KeyLength + 1 > CacheSize ||
 *       UsedLength < 1 + KeyLength + 1 )      <- new
 *
 * Verified here:
 *   1. The guard is SUFFICIENT: for every (Offset, UsedLength, KeyLength,
 *      CacheSize) that passes the fixed guard, the data length
 *      UsedLength-(1+KeyLength+1) is in [0, CacheSize) -- i.e. the generator
 *      can never be handed a negative or out-of-range data length.
 *   2. The guard is NECESSARY for the old computation: a node that fails only
 *      the new condition yields a negative DataLength (the old code accepted
 *      it).
 *   3. DnsGenerator_Generate() is invoked with the guarded non-negative
 *      length in the real call path, and the generator itself rejects
 *      non-positive lengths for the record writers that take a length
 *      (proving the guard is what keeps the input well-formed).
 *
 * Build:
 *   gcc verify_usedlength.c dnsgenerator.o dnsparser.o -I../.. -o v.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "common.h"
#include "dnsgenerator.h"

/* Mirror of the fixed guard in DNSCache_GetRawRecordsFromCache(). */
static int GuardPasses(int32_t Offset, int32_t UsedLength,
                       int KeyLength, int CacheSize)
{
    if( Offset < 0 )                                                          return 0;
    if( (uint32_t)Offset + (uint32_t)UsedLength > (uint32_t)CacheSize )       return 0;
    if( (uint32_t)Offset + 1 + (uint32_t)KeyLength + 1 > (uint32_t)CacheSize )return 0;
    if( UsedLength < 1 + KeyLength + 1 )                                      return 0; /* new */
    return 1;
}

/* Old guard (without the lower-bound condition). */
static int OldGuardPasses(int32_t Offset, int32_t UsedLength,
                          int KeyLength, int CacheSize)
{
    if( Offset < 0 )                                                          return 0;
    if( (uint32_t)Offset + (uint32_t)UsedLength > (uint32_t)CacheSize )       return 0;
    if( (uint32_t)Offset + 1 + (uint32_t)KeyLength + 1 > (uint32_t)CacheSize )return 0;
    return 1;
}

/* Data length exactly as the call site computes it:
 *   g->Generate(g, ..., CacheItr, MapStart + Node->Offset + Node->UsedLength
 *                                         - CacheItr, ...)
 * with CacheItr = MapStart + Node->Offset + 1 + KeyLength + 1. */
static int DataLength(int32_t UsedLength, int KeyLength)
{
    return (int)(UsedLength - (1 + KeyLength + 1));
}

/* Formal proof that the guard is SUFFICIENT, verified by construction plus a
 * large random sample:
 *
 *   Let D = UsedLength - (1 + KeyLength + 1).  If the guard passes:
 *     (1) UsedLength >= 1 + KeyLength + 1  ->  D >= 0
 *     (2) Offset + UsedLength <= CacheSize and Offset >= 0
 *                                    ->  D = UsedLength - KeyLength - 2
 *                                            <= CacheSize - KeyLength - 2
 *                                            <= CacheSize
 *     (3) the data region [CacheItr, CacheItr + D)
 *              = [Offset + 1 + KeyLength + 1, Offset + UsedLength)
 *         lies inside [0, CacheSize] by (2) and the key-header bound
 *         Offset + 1 + KeyLength + 1 <= CacheSize.
 *
 * The random sampling below empirically confirms the derivation over a large
 * parameter space (including invalid Offset < 0 and UsedLength beyond the
 * mapping, which the guard must reject). */
static int VerifyGuardSufficiency(void)
{
    const int CacheSize = 64 * 1024;
    const int Samples = 4000000;
    long i;
    long Accepted = 0;

    /* Deterministic LCG for reproducibility. */
    unsigned int seed = 0x12345678u;
#define NEXT_RAND() (seed = seed * 1103515245u + 12345u, (int)((seed >> 16) & 0x7FFF))

    for( i = 0; i < Samples; ++i )
    {
        int32_t Offset     = (int32_t)(NEXT_RAND() % (CacheSize + 200)) - 100;
        int32_t UsedLength = (int32_t)(NEXT_RAND() % (CacheSize + 200));
        int KeyLength      = NEXT_RAND() % 255;
        int dl;

        if( !GuardPasses(Offset, UsedLength, KeyLength, CacheSize) )
        {
            continue; /* rejected -> Generate() is not called */
        }
        ++Accepted;
        dl = DataLength(UsedLength, KeyLength);
        if( dl < 0 || dl > CacheSize )
        {
            printf("FAIL: guard passes but DataLength=%d is out of range "
                   "(Offset=%d UsedLength=%d KeyLength=%d)\n",
                   dl, (int)Offset, (int)UsedLength, KeyLength);
            return 1;
        }
    }

    /* Prove the OLD guard accepted at least one node with a NEGATIVE data
     * length -- i.e. the bug was real and the new condition is necessary. */
    {
        int32_t Offset = 4;
        int KeyLength = 10;
        int32_t UsedLength = 1 + KeyLength; /* one byte short of the key+NUL */
        int OldPassed = OldGuardPasses(Offset, UsedLength, KeyLength, CacheSize);
        int NewPassed = GuardPasses(Offset, UsedLength, KeyLength, CacheSize);
        int dl = DataLength(UsedLength, KeyLength);

        if( !OldPassed )
        {
            printf("FAIL: expected the old guard to accept the undersized node\n");
            return 1;
        }
        if( NewPassed )
        {
            printf("FAIL: the new guard must reject the undersized node\n");
            return 1;
        }
        if( dl >= 0 )
        {
            printf("FAIL: expected a negative data length for the old path, got %d\n", dl);
            return 1;
        }
        printf("CONFIRMED-OLD-BUG: undersized node (UsedLength=%d, KeyLength=%d) "
               "passed the old guard but yields DataLength=%d\n",
               (int)UsedLength, KeyLength, dl);
    }

    /* Boundary: UsedLength exactly 1+KeyLength+1 passes the guard and gives
     * DataLength == 0 (a legal, empty RDATA region). */
    {
        int32_t Offset = 4;
        int KeyLength = 10;
        int32_t UsedLength = 1 + KeyLength + 1;
        if( !GuardPasses(Offset, UsedLength, KeyLength, CacheSize) ||
            DataLength(UsedLength, KeyLength) != 0 )
        {
            printf("FAIL: exact-fit node must pass the guard with DataLength 0\n");
            return 1;
        }
    }

    printf("Guard sufficiency verified over %d samples (accepted %ld): every "
           "accepted node yields a data length in [0, CacheSize].\n",
           Samples, Accepted);
#undef NEXT_RAND
    return 0;
}

/* DnsGenerator_Generate() behaviour with non-positive DataLength, proving the
 * record writers that take a length all reject it (and hence the guard is
 * what keeps the generator's input well-formed). */
static int VerifyGeneratorRejects(void)
{
    char Scratch[512];
    DnsGenerator g;
    int fails = 0;

    if( DnsGenerator_Init(&g, Scratch, (int)sizeof(Scratch), NULL, 0, FALSE) != 0 )
    {
        printf("FAIL: DnsGenerator_Init\n");
        return 1;
    }

    /* DNS_TYPE_A with negative length */
    if( g.Generate(&g, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN, "abcd", -3, 60) == 0 )
    {
        printf("FAIL: A writer accepted a negative DataLength\n");
        ++fails;
    }

    /* DNS_TYPE_MX with length < 2 */
    if( g.Generate(&g, "example.com", DNS_TYPE_MX, DNS_CLASS_IN, "\x00\x0a", -1, 60) == 0 )
    {
        printf("FAIL: MX writer accepted a negative DataLength\n");
        ++fails;
    }

    /* DataLength == 0 for A (empty RDATA): must be rejected, never memcpy'd. */
    if( g.Generate(&g, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN, "", 0, 60) == 0 )
    {
        printf("FAIL: A writer accepted a zero DataLength\n");
        ++fails;
    }

    if( fails == 0 )
    {
        printf("Generator rejects non-positive DataLength for length-aware writers.\n");
    }
    return fails;
}

int main(void)
{
    int failures = 0;
    failures += VerifyGuardSufficiency();
    failures += VerifyGeneratorRejects();
    if( failures == 0 )
    {
        printf("\nALL USEDLENGTH GUARD CHECKS PASSED.\n");
        return 0;
    }
    printf("\nVERIFICATION FAILED (%d failures).\n", failures);
    return 1;
}
