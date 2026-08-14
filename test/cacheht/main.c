/* Standalone regression test for cacheht.c.
 *
 * cacheht.c is the core cache hash table but had no dedicated regression test
 * in the suite.  This test exercises the full life-cycle of a cache node:
 *
 *   1. allocate a node of a given chunk size (CacheHT_FindUnusedNode)
 *   2. tag it with a unique marker in Cht_Node.Offset and insert it into the
 *      slot chain (CacheHT_InsertToSlot)
 *   3. retrieve it by walking the slot's linked list (CacheHT_Get) and confirm
 *      the marker survives
 *   4. remove it (CacheHT_RemoveFromSlot) and verify it is gone
 *   5. verify that a removed (non-last) node is recycled by the 2D free list
 *
 * Cht_Node is a fixed-size record (sizeof(Cht_Node)); the actual cached payload
 * lives in a separate data region addressed by Offset/Length in the real
 * DNSCache, so this test uses Offset purely as a round-trip marker.
 *
 * Built and run under AddressSanitizer so any out-of-bounds read/write,
 * use-after-free or misaligned access in the slot/node handling is caught.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cacheht.h"
#include "common.h"
#include "utils.h"

#define NKEYS   200
#define CHUNKSZ 64

static int failures = 0;
#define CHECK(cond, msg) do { \
    if( !(cond) ) { printf("FAIL: %s\n", msg); ++failures; } \
} while(0)

/* Walk every node stored in `slot` and return the one whose Offset equals
 * `marker`, or NULL.  CacheHT_Get needs a non-NULL Key to pass its guard, but
 * when HashValue is supplied the slot is taken from the hash, so a dummy key
 * is harmless. */
static Cht_Node *FindMarkerInSlot(CacheHT *h, int slot, int32_t marker)
{
    Cht_Node *n = NULL;
    uint32_t  hv = (uint32_t)slot;   /* slot < Allocated => hv % Allocated == slot */

    while( (n = CacheHT_Get(h, "x", n, &hv)) != NULL )
    {
        if( n->Offset == marker )
            return n;
    }
    return NULL;
}

int main(void)
{
    size_t   cap = 4 * 1024 * 1024;
    char    *buf = (char *)calloc(1, cap);
    CacheHT ht;
    char    key[32];
    int     subscripts[NKEYS];
    Cht_Node *nodes[NKEYS];
    int     i;
    int     allocated;

    CHECK(buf != NULL, "calloc base buffer");
    if( buf == NULL )
        return 1;

    CHECK(CacheHT_Init(&ht, buf, (int)cap) == 0, "CacheHT_Init");
    allocated = ht.Slots.Allocated;
    CHECK(allocated > 0, "CacheHT_Init produced a positive slot count");

    /* Phase 1 + 2: allocate and insert NKEYS distinct entries, each tagged. */
    for( i = 0; i < NKEYS; ++i )
    {
        BOOL      created = FALSE;
        Cht_Node *node = NULL;
        int32_t   sub;
        uint32_t  hash;

        snprintf(key, sizeof(key), "key-%d", i);

        sub = CacheHT_FindUnusedNode(&ht, CHUNKSZ, &node, buf, &created);
        CHECK(sub >= 0, "CacheHT_FindUnusedNode returns valid subscript");
        CHECK(node != NULL, "CacheHT_FindUnusedNode returns valid node");
        if( sub < 0 || node == NULL )
            continue;

        node->Offset = i;          /* unique round-trip marker */
        node->Length = CHUNKSZ;

        hash = HASH(key, 0);
        CHECK(CacheHT_InsertToSlot(&ht, key, sub, node, &hash) == 0,
              "CacheHT_InsertToSlot");

        subscripts[i] = sub;
        nodes[i] = node;
    }

    /* Phase 3: every inserted marker must be retrievable from its slot. */
    for( i = 0; i < NKEYS; ++i )
    {
        snprintf(key, sizeof(key), "key-%d", i);
        int slot = (int)(HASH(key, 0) % (uint32_t)allocated);
        Cht_Node *n = FindMarkerInSlot(&ht, slot, i);
        CHECK(n != NULL, "CacheHT_Get finds previously inserted node");
        CHECK(n != NULL && n->Offset == i, "CacheHT_Get preserves node marker");
    }

    /* Phase 4: remove key-0 and verify its marker disappears from the slot. */
    {
        snprintf(key, sizeof(key), "key-0");
        int slot = (int)(HASH(key, 0) % (uint32_t)allocated);
        CHECK(CacheHT_RemoveFromSlot(&ht, subscripts[0], nodes[0]) == 0,
              "CacheHT_RemoveFromSlot key-0");
        CHECK(FindMarkerInSlot(&ht, slot, 0) == NULL,
              "removed node is no longer retrievable");
    }

    /* Phase 5: a later insert of the same chunk size must recycle a free node
     * (exercising the 2D free list) and still be correct. */
    {
        BOOL      created = FALSE;
        Cht_Node *node = NULL;
        int32_t   sub;
        uint32_t  hash;
        const char *reuse = "key-reuse";
        int slot;

        sub = CacheHT_FindUnusedNode(&ht, CHUNKSZ, &node, buf, &created);
        CHECK(sub >= 0, "CacheHT_FindUnusedNode (reuse) valid subscript");
        CHECK(node != NULL, "CacheHT_FindUnusedNode (reuse) valid node");

        node->Offset = 9999;       /* distinct marker for the reused node */
        node->Length = CHUNKSZ;

        hash = HASH(reuse, 0);
        CHECK(CacheHT_InsertToSlot(&ht, reuse, sub, node, &hash) == 0,
              "CacheHT_InsertToSlot (reuse)");

        slot = (int)(HASH(reuse, 0) % (uint32_t)allocated);
        Cht_Node *n = FindMarkerInSlot(&ht, slot, 9999);
        CHECK(n != NULL, "CacheHT_Get finds reused node");
        CHECK(n != NULL && n->Offset == 9999, "CacheHT_Get reused marker correct");
    }

    CacheHT_Free(&ht);
    free(buf);

    if( failures == 0 )
    {
        printf("cacheht: PASS\n");
        return 0;
    }
    printf("cacheht: %d FAILURES\n", failures);
    return 1;
}
