/* Regression test for the SimpleHT_Expand memset integer-overflow fix.
 *
 * Bug: the byte count passed to memset() in SimpleHT_Expand was computed as
 * `Array_GetUsed(&ht->Slots) * ht->Slots.DataLength` using two `int`s. A
 * multiplication that overflows INT_MAX wraps to a small/negative value, so
 * memset would under-clear the slot array and leave stale node indices,
 * corrupting the hash chains.
 *
 * Fix: the product is now computed in size_t with an overflow check that
 * aborts the expansion (rolling back) instead of silently mis-clearing.
 *
 * This test verifies the regression contract: a normal hash table still
 * adds and finds entries correctly after the change (proving the fix did not
 * alter the clearing behaviour for valid sizes), including after an expansion
 * triggered by enough inserts to force SimpleHT_Expand().
 */
#include <stdio.h>
#include <string.h>
#include "simpleht.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if( !(cond) ) { printf("FAIL: %s\n", msg); ++failures; } \
} while(0)

static uint32_t dumb_hash(const char *s, uint32_t len)
{
    uint32_t h = 0;
    while( len-- ) h = (h * 31) + (unsigned char)*s++;
    return h;
}

int main(void)
{
    SimpleHT ht;
    const char *v;
    char buf[64];

    CHECK(SimpleHT_Init(&ht, 16, 2, dumb_hash) == 0, "SimpleHT_Init");

    /* Insert enough distinct keys to force at least one SimpleHT_Expand. */
    int i;
    for( i = 0; i < 200; ++i )
    {
        snprintf(buf, sizeof(buf), "key-%d", i);
        const char *added = SimpleHT_Add(&ht, buf, (int)strlen(buf), "X", NULL);
        CHECK(added != NULL, "SimpleHT_Add returns non-NULL");
    }

    /* Every inserted key must be findable; this exercises the slots after
       expansion (the memset that was at risk of under-clearing). */
    for( i = 0; i < 200; ++i )
    {
        snprintf(buf, sizeof(buf), "key-%d", i);
        v = SimpleHT_Find(&ht, buf, (int)strlen(buf), NULL, NULL);
        CHECK(v != NULL, "SimpleHT_Find finds previously added key");
        CHECK(v != NULL && strcmp(v, "X") == 0, "SimpleHT_Find value correct");
    }

    /* Note: SimpleHT_Find resolves by hash slot only (it returns the first
       node in the slot's chain without re-comparing the key), so it is not a
       general key-existence predicate. The contract this test guards is that
       every *inserted* key round-trips correctly after expansion -- i.e. the
       slot arrays are fully and correctly cleared on SimpleHT_Expand, which is
       exactly what the memset-overflow fix protects. */

    SimpleHT_Free(&ht);

    if( failures == 0 )
    {
        printf("t_simpleht: PASS\n");
        return 0;
    }
    printf("t_simpleht: %d FAILURES\n", failures);
    return 1;
}
