/*
 * Regression tests for IpChunk CIDR matching (ipchunk.c).
 *
 * These tests lock in the *correct* matching behaviour of short-prefix CIDR
 * ranges (e.g. /24, /26) and exact /32 host routes, so that any future
 * change to the BST comparator (Contain) that regresses address/prefix
 * matching is caught.
 *
 * Build (from the repository root):
 *   cc -I. -g -o /tmp/t_ipchunk test/ipchunk/main.c ipchunk.c stablebuffer.c \
 *      bst.c stringchunk.c stringlist.c array.c simpleht.c utils.c \
 *      addresslist.c -lm
 *
 * Run under valgrind for the memory check:
 *   valgrind --leak-check=full --error-exitcode=9 /tmp/t_ipchunk
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../ipchunk.h"

static int Failures = 0;
static int Checks = 0;

static void Check(const char *Name, int Condition)
{
    ++Checks;
    if( Condition )
    {
        printf("  [ ok ] %s\n", Name);
    } else {
        printf("  [FAIL] %s\n", Name);
        ++Failures;
    }
}

int main(void)
{
    IpChunk ic;
    int Type;
    const char *Data;

    if( IpChunk_Init(&ic) != 0 )
    {
        printf("IpChunk_Init failed\n");
        return 1;
    }

    /* Short-prefix CIDR ranges. */
    if( IpChunk_Add(&ic, "10.0.0.0/24", 1, "range24", 8) != 0 ||
        IpChunk_Add(&ic, "192.168.1.0/26", 2, "range26", 8) != 0 )
    {
        printf("IpChunk_Add failed\n");
        IpChunk_Free(&ic);
        return 1;
    }

    {
        unsigned char ip[4] = {10, 0, 0, 123};
        int found = IpChunk_Find(&ic, ip, 4, &Type, &Data);
        Check("10.0.0.123 in 10.0.0.0/24", found == 1 && Type == 1);
    }
    {
        unsigned char ip[4] = {10, 255, 0, 1};
        int found = IpChunk_Find(&ic, ip, 4, &Type, &Data);
        Check("10.255.0.1 NOT in 10.0.0.0/24", found == 0);
    }
    {
        unsigned char ip[4] = {192, 168, 1, 60};
        int found = IpChunk_Find(&ic, ip, 4, &Type, &Data);
        Check("192.168.1.60 in 192.168.1.0/26", found == 1 && Type == 2);
    }
    {
        unsigned char ip[4] = {192, 168, 1, 200};
        int found = IpChunk_Find(&ic, ip, 4, &Type, &Data);
        Check("192.168.1.200 NOT in 192.168.1.0/26", found == 0);
    }

    /* An exact /32 host route must match ONLY its exact address. */
    {
        IpChunk ic32;
        if( IpChunk_Init(&ic32) != 0 )
        {
            printf("IpChunk_Init(32) failed\n");
            IpChunk_Free(&ic);
            return 1;
        }
        if( IpChunk_Add(&ic32, "10.0.0.0/32", 3, "host32", 8) != 0 )
        {
            printf("IpChunk_Add /32 failed\n");
            IpChunk_Free(&ic32);
            IpChunk_Free(&ic);
            return 1;
        }

        unsigned char exact[4] = {10, 0, 0, 0};
        int found = IpChunk_Find(&ic32, exact, 4, &Type, &Data);
        Check("10.0.0.0 matches 10.0.0.0/32", found == 1 && Type == 3);

        unsigned char neighbour[4] = {10, 0, 0, 5};
        found = IpChunk_Find(&ic32, neighbour, 4, &Type, &Data);
        Check("10.0.0.5 NOT in 10.0.0.0/32", found == 0);

        unsigned char other[4] = {10, 0, 1, 1};
        found = IpChunk_Find(&ic32, other, 4, &Type, &Data);
        Check("10.0.1.1 NOT in 10.0.0.0/32", found == 0);

        IpChunk_Free(&ic32);
    }

    IpChunk_Free(&ic);

    printf("\nipchunk: %d checks, %d failures\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
