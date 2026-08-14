/* Regression test for the fix to IpChunk_Add NULL-data bug.
 *
 * Bug: when the SUBSTITUTE additional data could not be stored
 * (StableBuffer.Add returning NULL, e.g. under OOM), IpChunk_Add still
 * registered the rule with New.Data == NULL. IpChunk_Find would then hand
 * NULL back to ipmisc.c, which does memcpy(RowDataPos, NULL, DataLength) on
 * the SUBSTITUTE branch and crash.
 *
 * Fix: IpChunk_Add now returns -1 (rejects the rule) when the data store
 * allocation fails, so a NULL-Data SUBSTITUTE entry can never be created.
 *
 * This test locks the contract ipmisc.c depends on:
 *   - a successfully added SUBSTITUTE rule yields a non-NULL, content-correct
 *     Data on lookup;
 *   - a BLOCK rule (no extra data) still works;
 *   - an unknown IP is cleanly rejected (FALSE) without touching Data;
 *   - CIDR longest-prefix matching keeps working after the change.
 *
 * Note: the IP bytes are passed as raw octets, not as an ASCII string, because
 * IpChunk_Find compares the on-wire address bytes directly.
 */
#include <stdio.h>
#include <string.h>
#include "ipchunk.h"
#include "ipmisc.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if( !(cond) ) { printf("FAIL: %s\n", msg); ++failures; } \
} while(0)

int main(void)
{
    IpChunk ic;
    const char *Data;
    int Type;

    CHECK(IpChunk_Init(&ic) == 0, "IpChunk_Init");

    unsigned char ip1234[4] = {1,2,3,4};
    unsigned char ip5678[4] = {5,6,7,8};
    unsigned char ip8888[4] = {8,8,8,8};
    unsigned char ip1000[4] = {10,0,0,1};

    /* --- Normal SUBSTITUTE entry: data must be stored and retrievable. --- */
    CHECK(IpChunk_Add(&ic, "1.2.3.4", IP_MISC_TYPE_SUBSTITUTE, "9.9.9.9", 8) == 0,
          "IpChunk_Add substitute");
    CHECK(IpChunk_Find(&ic, ip1234, 4, &Type, &Data) == TRUE,
          "IpChunk_Find substitute");
    CHECK(Type == IP_MISC_TYPE_SUBSTITUTE, "type is SUBSTITUTE");
    CHECK(Data != NULL, "Data is non-NULL for a successfully added rule");
    CHECK(Data != NULL && strcmp(Data, "9.9.9.9") == 0, "Data content matches");

    /* --- BLOCK entry without extra data: must still work, no crash. --- */
    CHECK(IpChunk_Add(&ic, "5.6.7.8", IP_MISC_TYPE_BLOCK, NULL, 0) == 0,
          "IpChunk_Add block (no data)");
    CHECK(IpChunk_Find(&ic, ip5678, 4, &Type, &Data) == TRUE,
          "IpChunk_Find block");
    CHECK(Type == IP_MISC_TYPE_BLOCK, "type is BLOCK");

    /* --- Unknown IP: clean rejection, no crash, Data untouched. --- */
    Data = (const char *)0xDEAD;
    CHECK(IpChunk_Find(&ic, ip8888, 4, &Type, &Data) == FALSE,
          "IpChunk_Find unknown returns FALSE");
    CHECK(Data == (const char *)0xDEAD, "Data untouched on miss");

    /* --- CIDR longest-prefix match still works. --- */
    CHECK(IpChunk_Add(&ic, "10.0.0.0/8", IP_MISC_TYPE_SUBSTITUTE, "10.0.0.0", 8) == 0,
          "IpChunk_Add CIDR /8");
    CHECK(IpChunk_Find(&ic, ip1000, 4, &Type, &Data) == TRUE,
          "IpChunk_Find within CIDR");
    CHECK(Type == IP_MISC_TYPE_SUBSTITUTE, "CIDR match type SUBSTITUTE");

    IpChunk_Free(&ic);

    if( failures == 0 )
    {
        printf("t_ipchunk_substitute: PASS\n");
        return 0;
    }
    printf("t_ipchunk_substitute: %d FAILURES\n", failures);
    return 1;
}
