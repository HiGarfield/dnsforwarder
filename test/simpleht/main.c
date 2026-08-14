/* Regression test for simpleht.c.
 *
 * Bug under test: simpleht.c used SIZE_MAX (in SimpleHT_Expand) without
 * including the header that defines it (<stdint.h>).  It only compiled when a
 * transitive include happened to bring SIZE_MAX into scope, so it broke the
 * standalone build of every translation unit that compiles simpleht.c without
 * that luck (e.g. array.c, ipchunk.c, ...).
 *
 * This test compiles simpleht.c *standalone* (only simpleht.c + its own
 * header + the minimal deps it needs to link).  If SIZE_MAX is undefined the
 * compile fails outright, which is exactly the failure we want to keep
 * catching.  The runtime part exercises SimpleHT_Expand (the function that
 * references SIZE_MAX) by forcing many insertions so the table grows, and
 * follows the canonical lookup pattern (loop over Start and compare the
 * stored key, exactly like StringChunk_Match_NoWildCard does) to prove the
 * data survives expansion(s).
 *
 * Build (from the project root):
 *   cc -I. -o /tmp/t_simpleht test/simpleht/main.c simpleht.c array.c \
 *       utils.c addresslist.c -lpthread
 */
#include <stdio.h>
#include <string.h>
#include "simpleht.h"

static uint32_t IdentityHash(const char *Key, uint32_t KeyLength)
{
    uint32_t h = 0;
    uint32_t i;
    for( i = 0; i < KeyLength; ++i )
        h = h * 31 + (uint8_t)Key[i];
    return h;
}

/* Payload: we store the key string itself so the lookup can compare it. */
static int TestStandaloneCompileAndExpand(void)
{
    SimpleHT ht;
    int i;
    char key[32];
    const char *found;
    const char *start;

    /* DataLength must be large enough to hold the stored key string (the test
       stores the key itself as payload).  sizeof(char *) is intentionally NOT
       used here: SimpleHT_Add copies DataLength bytes from Data, so Data must
       point to at least that many bytes. */
    if( SimpleHT_Init(&ht, 32, 5, IdentityHash) != 0 )
    {
        fprintf(stderr, "SimpleHT_Init failed\n");
        return 1;
    }

    /* Insert enough distinct keys to force at least one expansion. */
    for( i = 0; i < 200; ++i )
    {
        snprintf(key, sizeof(key), "key-%d", i);
        if( SimpleHT_Add(&ht, key, (int)strlen(key), key, NULL) == NULL )
        {
            fprintf(stderr, "SimpleHT_Add failed at %d\n", i);
            SimpleHT_Free(&ht);
            return 1;
        }
    }

    /* Every key must be retrievable after expansion(s).  Follow the canonical
       chain-walk + key-compare pattern since SimpleHT_Find does not compare
       keys itself. */
    for( i = 0; i < 200; ++i )
    {
        snprintf(key, sizeof(key), "key-%d", i);
        uint32_t h = IdentityHash(key, (uint32_t)strlen(key));

        start = NULL;
        found = NULL;
        while( (found = SimpleHT_Find(&ht, key, (int)strlen(key), &h, start)) != NULL )
        {
            if( strcmp(found, key) == 0 )
                break;
            start = found;
        }
        if( found == NULL || strcmp(found, key) != 0 )
        {
            fprintf(stderr, "lookup failed for %s\n", key);
            SimpleHT_Free(&ht);
            return 1;
        }
    }

    SimpleHT_Free(&ht);
    printf("SimpleHT standalone-compile + expand OK\n");
    return 0;
}

int main(void)
{
    return TestStandaloneCompileAndExpand() == 0 ? 0 : 1;
}
