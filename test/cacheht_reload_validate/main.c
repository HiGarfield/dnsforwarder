/*
 * Regression test for the unvalidated on-disk cache image.
 *
 * dnscache.c mmaps a plain file and then trusts every field it finds there:
 * the two Array headers of the embedded CacheHT, Free2DList, each slot's chain
 * head, and each Cht_Node's Offset / Length / UsedLength / Slot / Next.
 * IsReloadable() used to check only Ver and CacheSize.
 *
 * The cache READ paths do bound-check Node->Offset, but the WRITE paths do not:
 *
 *   dnscache.c, DNSCacheTTLCountdown_Task:
 *       *(unsigned char *)(MapStart + Node->Offset) = 0xFD;
 *   dnscache.c, DNSCache_GetAvailableChunk:
 *       memset(MapStart + Node->Offset + Length, 0xFE, RoundedLength - Length);
 *
 * So a single corrupted Offset in the file turns into an out-of-bounds WRITE at
 * an attacker-chosen distance from the mapping. Node->Slot and Node->Next are
 * equally dangerous: CacheHT_RemoveFromSlot indexes h->Slots with Node->Slot,
 * and the slot chains are walked through Node->Next.
 *
 * CacheHT_IsStructureSane() is the guard that closes this. This test builds a
 * real, well-formed cache image with CacheHT_Init and asserts it is accepted;
 * then, for every individual field that feeds an unchecked write or an array
 * index, it corrupts THAT FIELD ALONE and asserts the image is rejected.
 *
 * Each rejection case is accompanied by the out-of-bounds access it prevents.
 */

#include "../../cacheht.h"
#include "../../array.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Mirrors dnscache.c's struct _Header layout closely enough for this test:
   what matters is that a fixed-size header precedes the record region and that
   the CacheHT lives inside the mapping. */
#define HEADER_SIZE   128
#define CACHE_SIZE    (256 * 1024)

static int Checks = 0;
static int Failures = 0;

static void expect(const char *what, int cond)
{
    ++Checks;
    if( cond )
    {
        printf("  [ ok ] %s\n", what);
    } else {
        ++Failures;
        printf("  [FAIL] %s\n", what);
    }
}

/* --- access to the private on-image layout -----------------------------

   CacheHT_Init places the slot table at the top of the mapping (aligned down
   to 8 bytes) and grows the node chunk downward from just below it. The test
   needs to reach individual nodes and slots to corrupt them, so it recomputes
   those bases the same way CacheHT_Init / CacheHT_ReInit do.

   Cht_Slot is private to cacheht.c, but it is a single int32_t ("Next"), which
   is all this test needs. */

typedef struct { int32_t Next; } TestSlot;

static char *SlotBase(char *Map, int CacheSize, int SlotsUsed)
{
    return (char *)((uintptr_t)(Map + CacheSize - sizeof(TestSlot) * (size_t)SlotsUsed)
                    & ~(uintptr_t)7);
}

static Cht_Node *NodeAt(char *Map, int CacheSize, int SlotsUsed, int i)
{
    char *nb = SlotBase(Map, CacheSize, SlotsUsed) - sizeof(Cht_Node);
    return (Cht_Node *)(nb - sizeof(Cht_Node) * (size_t)i);
}

static TestSlot *SlotAt(char *Map, int CacheSize, int SlotsUsed, int i)
{
    return (TestSlot *)(SlotBase(Map, CacheSize, SlotsUsed) + sizeof(TestSlot) * (size_t)i);
}

/* --- image construction ------------------------------------------------ */

/* Builds a valid cache image into `Map` and returns the record high-water mark
   through *EndOut. Adds `NodeCount` nodes the way DNSCache does: a chunk of
   record bytes at the current high-water mark plus a node indexed into a slot. */
static void BuildValidImage(char *Map, CacheHT *h, int *EndOut, int NodeCount)
{
    int End = HEADER_SIZE;
    int i;

    memset(Map, 0, CACHE_SIZE);
    CacheHT_Init(h, Map, CACHE_SIZE);

    for( i = 0; i < NodeCount; ++i )
    {
        Cht_Node *Node = NULL;
        BOOL NewCreated = FALSE;
        uint32_t ChunkSize = 64;
        int32_t idx;
        char Key[32];

        idx = CacheHT_FindUnusedNode(h,
                                     ChunkSize,
                                     &Node,
                                     Map + End + ChunkSize,
                                     &NewCreated
                                     );
        if( idx < 0 || Node == NULL )
        {
            break;
        }

        if( NewCreated )
        {
            Node->Offset = End;
            End += (int)ChunkSize;
        }

        Node->UsedLength = 16;
        Node->TTL = 3600;
        Node->TimeAdded = 0;

        sprintf(Key, "k%d.example.com", i);
        memcpy(Map + Node->Offset, Key, strlen(Key) + 1);

        CacheHT_InsertToSlot(h, Key, idx, Node, NULL);
    }

    *EndOut = End;
}

/* Runs the validator against the image currently in Map. */
static BOOL Validate(const CacheHT *h, char *Map, int End)
{
    return CacheHT_IsStructureSane(h, Map, CACHE_SIZE, HEADER_SIZE, End);
}

int main(void)
{
    char *Map;
    CacheHT h;
    int End;
    int SlotsUsed;

    printf("== cache reload validation regression tests ==\n\n");

    Map = malloc(CACHE_SIZE);
    if( Map == NULL )
    {
        printf("out of memory\n");
        return 1;
    }

    /* ---- 1. A genuine, well-formed image must be ACCEPTED ------------- */
    printf("A well-formed cache image\n");
    BuildValidImage(Map, &h, &End, 24);
    SlotsUsed = h.Slots.Used;

    expect("the validator accepts a well-formed image", Validate(&h, Map, End) == TRUE);
    expect("the image really does contain nodes", h.NodeChunk.Used > 0);

    /* ---- 2. Node->Offset past the end of the mapping ------------------
       Prevents: DNSCacheTTLCountdown_Task writing 0xFD at
       MapStart + Offset, i.e. CACHE_SIZE bytes past the mapping. */
    printf("Corrupted Node->Offset (past the end of the mapping)\n");
    {
        CacheHT c = h;
        Cht_Node *n;
        int32_t Saved;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 0);
        Saved = n->Offset;

        n->Offset = CACHE_SIZE + 4096;
        expect("an Offset past the mapping is rejected", Validate(&c, Map, End) == FALSE);

        n->Offset = Saved;
        expect("restoring the Offset makes the image valid again",
               Validate(&c, Map, End) == TRUE);
    }

    /* ---- 2b. Node->Offset exactly at the end of the mapping -----------
       The old check `Offset > CacheSize` accepted Offset == CacheSize, and
       with Length == 0 the Offset+Length bound check cannot catch it either.
       The TTL write path then executed `*(unsigned char *)(MapStart + Offset)
       = 0xFD`, writing one byte past the mapping. Length/UsedLength are zeroed
       so this case isolates the Offset upper bound exclusively. */
    printf("Corrupted Node->Offset (exactly at the end of the mapping)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 8);

        n->Offset = CACHE_SIZE;
        n->Length = 0;
        n->UsedLength = 0;
        expect("an Offset exactly at the end of the mapping is rejected",
               Validate(&c, Map, End) == FALSE);
    }

    /* ---- 3. Negative Node->Offset ------------------------------------
       Prevents an out-of-bounds write BELOW the mapping. */
    printf("Corrupted Node->Offset (negative)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 3);

        n->Offset = -4096;
        expect("a negative Offset is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 4. Offset inside the header --------------------------------
       The record region starts at HEADER_SIZE; an Offset below that would let
       a record write over the header (Ver / CacheSize / End / the CacheHT). */
    printf("Corrupted Node->Offset (inside the file header)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 1);

        n->Offset = HEADER_SIZE - 8;
        expect("an Offset inside the header is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 5. Offset + Length overflowing the mapping ------------------
       Offset alone is in range, but the record runs off the end. Prevents the
       memset in DNSCache_GetAvailableChunk from running past the mapping. */
    printf("Corrupted Node->Length (record runs past the mapping)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 2);

        n->Offset = CACHE_SIZE - 32;
        n->Length = 4096;
        expect("Offset + Length past the mapping is rejected",
               Validate(&c, Map, End) == FALSE);
    }

    /* ---- 6. Length arithmetic must not be allowed to wrap ------------- */
    printf("Corrupted Node->Length (0xFFFFFFFF, would wrap)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 4);

        n->Length = 0xFFFFFFFFU;
        expect("a Length of 0xFFFFFFFF is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 7. UsedLength larger than Length ----------------------------
       DNSCache_GetRawRecordsFromCache derives a read length from
       Offset + UsedLength, so UsedLength must never exceed the chunk. */
    printf("Corrupted Node->UsedLength (larger than Length)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 5);

        n->UsedLength = n->Length + 1024;
        expect("a UsedLength beyond Length is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 8. Node->Slot out of range ---------------------------------
       Prevents CacheHT_RemoveFromSlot from indexing h->Slots out of bounds. */
    printf("Corrupted Node->Slot (out of range)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 6);

        n->Slot = c.Slots.Used + 1000;
        expect("a Slot subscript past the slot table is rejected",
               Validate(&c, Map, End) == FALSE);

        n->Slot = -2;
        expect("a Slot subscript below -1 is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 9. Node->Next out of range ---------------------------------
       Prevents the slot-chain walk in CacheHT_Get / CacheHT_FindPredecessor
       from following a subscript that is not backed by NodeChunk->Used. */
    printf("Corrupted Node->Next (out of range)\n");
    {
        CacheHT c;
        Cht_Node *n;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 7);

        n->Next = c.NodeChunk.Used + 500;
        expect("a Next subscript past the node chunk is rejected",
               Validate(&c, Map, End) == FALSE);

        n->Next = -7;
        expect("a Next subscript below -1 is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 10. A slot chain head out of range -------------------------- */
    printf("Corrupted slot chain head\n");
    {
        CacheHT c;
        TestSlot *s;

        BuildValidImage(Map, &c, &End, 24);
        s = SlotAt(Map, CACHE_SIZE, c.Slots.Used, 0);

        s->Next = c.NodeChunk.Used + 9999;
        expect("a slot head past the node chunk is rejected",
               Validate(&c, Map, End) == FALSE);

        s->Next = -3;
        expect("a slot head below -1 is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 11. Free2DList out of range --------------------------------
       CacheHT_FindUnusedNode walks the free list starting at Free2DList and
       dereferences it without a range check. */
    printf("Corrupted Free2DList\n");
    {
        CacheHT c;

        BuildValidImage(Map, &c, &End, 24);

        c.Free2DList = c.NodeChunk.Used + 1;
        expect("a Free2DList past the node chunk is rejected",
               Validate(&c, Map, End) == FALSE);

        c.Free2DList = -2;
        expect("a Free2DList below -1 is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 12. Corrupted Array bookkeeping ---------------------------- */
    printf("Corrupted Array headers\n");
    {
        CacheHT c;

        BuildValidImage(Map, &c, &End, 24);
        c.NodeChunk.Used = -1;
        expect("a negative NodeChunk.Used is rejected", Validate(&c, Map, End) == FALSE);

        BuildValidImage(Map, &c, &End, 24);
        c.NodeChunk.Allocated = 16;      /* must stay negative (grow-down) */
        expect("a non-negative NodeChunk.Allocated is rejected",
               Validate(&c, Map, End) == FALSE);

        BuildValidImage(Map, &c, &End, 24);
        c.NodeChunk.DataLength = 4;      /* must be sizeof(Cht_Node) */
        expect("a wrong NodeChunk.DataLength is rejected", Validate(&c, Map, End) == FALSE);

        BuildValidImage(Map, &c, &End, 24);
        c.Slots.Used = 0;
        expect("a zero Slots.Used is rejected (modulo by zero downstream)",
               Validate(&c, Map, End) == FALSE);

        BuildValidImage(Map, &c, &End, 24);
        c.Slots.Used = -5;
        expect("a negative Slots.Used is rejected", Validate(&c, Map, End) == FALSE);

        BuildValidImage(Map, &c, &End, 24);
        c.Slots.Allocated = c.Slots.Used + 7;
        expect("Slots.Allocated != Slots.Used is rejected", Validate(&c, Map, End) == FALSE);

        BuildValidImage(Map, &c, &End, 24);
        c.NodeChunk.Used = CACHE_SIZE;   /* nodes would swallow the whole map */
        expect("an absurd NodeChunk.Used is rejected", Validate(&c, Map, End) == FALSE);
    }

    /* ---- 13. Corrupted record high-water mark ------------------------ */
    printf("Corrupted record high-water mark (Header->End)\n");
    {
        CacheHT c;

        BuildValidImage(Map, &c, &End, 24);

        expect("End past the end of the mapping is rejected",
               Validate(&c, Map, CACHE_SIZE + 1) == FALSE);
        expect("End below the header is rejected",
               Validate(&c, Map, HEADER_SIZE - 1) == FALSE);
        expect("a negative End is rejected", Validate(&c, Map, -1) == FALSE);
        expect("End colliding with the node region is rejected",
               Validate(&c, Map, CACHE_SIZE - 8) == FALSE);
    }

    /* ---- 14. Degenerate arguments ------------------------------------ */
    printf("Degenerate arguments\n");
    {
        CacheHT c;

        BuildValidImage(Map, &c, &End, 24);

        expect("a NULL base address is rejected",
               CacheHT_IsStructureSane(&c, NULL, CACHE_SIZE, HEADER_SIZE, End) == FALSE);
        expect("a zero cache size is rejected",
               CacheHT_IsStructureSane(&c, Map, 0, HEADER_SIZE, End) == FALSE);
        expect("a negative cache size is rejected",
               CacheHT_IsStructureSane(&c, Map, -1, HEADER_SIZE, End) == FALSE);
    }

    /* ---- 15. An empty but valid table is still accepted -------------- */
    printf("An empty (freshly created) cache image\n");
    {
        CacheHT c;

        memset(Map, 0, CACHE_SIZE);
        CacheHT_Init(&c, Map, CACHE_SIZE);
        expect("a freshly initialised empty table is accepted",
               Validate(&c, Map, HEADER_SIZE) == TRUE);
    }

    /* ---- 16. A fully populated image is still accepted --------------- */
    printf("A densely populated cache image\n");
    {
        CacheHT c;

        BuildValidImage(Map, &c, &End, 500);
        expect("a densely populated image is accepted", Validate(&c, Map, End) == TRUE);
        expect("the dense image really is dense", c.NodeChunk.Used > 100);
    }

    /* ---- 17. Free-2D-list KeyNext in [NodeChunk.Used, Slots.Used) -----
       A node on the free 2D list stores its chain successor in the field that
       Cht_Node.Slot overlays (offset 0 = Cht_2DList.KeyNext), but the per-node
       check bounds that field by Slots->Used -- correct for a slot-chain node,
       wrong for a free-list node, whose KeyNext is a NodeChunk subscript.  A
       corrupted KeyNext in [NodeChunk.Used, Slots.Used) therefore slips past
       the validator; when the cache is next used, CacheHT_FindUnusedNode() /
       CacheHT_AddTo2DList() walk the free list through that KeyNext, call
       Array_GetBySubscript() with it, get NULL back and dereference it,
       crashing on a merely-corrupted cache file. */
    printf("Corrupted free-2D-list KeyNext (in [NodeChunk.Used, Slots.Used))\n");
    {
        CacheHT c;
        Cht_Node *n;
        int bogus;

        BuildValidImage(Map, &c, &End, 24);
        if( c.Slots.Used > c.NodeChunk.Used )
        {
            /* A NodeChunk subscript that is legal for the generic Slot check
               (below Slots->Used) but not backed by the node chunk. */
            bogus = (c.NodeChunk.Used + c.Slots.Used) / 2;
            n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, c.NodeChunk.Used - 1);
            n->Slot = bogus;          /* becomes KeyNext when the node is freed */
            c.Free2DList = c.NodeChunk.Used - 1;
            expect("a free-list KeyNext past the node chunk is rejected",
                   Validate(&c, Map, End) == FALSE);
        }
        else
        {
            expect("(skip: node chunk at least as large as the slot table)",
                   TRUE);
        }
    }

    /* ---- 18. A cyclic slot chain (0 -> 1 -> 0) ------------------------
       The per-node Next checks bound every subscript but do not detect a
       cycle.  With a cyclic chain, CacheHT_Get()'s walkers and
       CacheHT_FindPredecessor() (CacheHT_RemoveFromSlot) loop forever,
       hanging the daemon on a merely corrupted cache file. */
    printf("Corrupted slot chain (cycle 0 -> 1 -> 0)\n");
    {
        CacheHT c;
        Cht_Node *n0;
        Cht_Node *n1;
        TestSlot *s0;

        BuildValidImage(Map, &c, &End, 24);
        if( c.NodeChunk.Used >= 2 )
        {
            n0 = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 0);
            n1 = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 1);
            s0 = SlotAt(Map, CACHE_SIZE, c.Slots.Used, 0);

            s0->Next = 0;
            n0->Next = 1;
            n1->Next = 0;
            expect("a two-node cyclic slot chain is rejected",
                   Validate(&c, Map, End) == FALSE);

            n1->Next = -1;
            expect("breaking the cycle makes the image valid again",
                   Validate(&c, Map, End) == TRUE);
        }
        else
        {
            expect("(skip: fewer than 2 nodes in the image)", TRUE);
        }
    }

    /* ---- 19. A self-referential node ----------------------------------
       The shortest possible cycle: a node whose Next points at itself. */
    printf("Corrupted slot chain (self-cycle)\n");
    {
        CacheHT c;
        Cht_Node *n;
        TestSlot *s;

        BuildValidImage(Map, &c, &End, 24);
        n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, 0);
        s = SlotAt(Map, CACHE_SIZE, c.Slots.Used, 0);

        s->Next = 0;
        n->Next = 0;               /* node 0 points at itself */
        expect("a node that points at itself is rejected",
               Validate(&c, Map, End) == FALSE);
    }

    /* ---- 20. A long but acyclic chain must still be accepted ----------
       The cycle detector must not false-positive: a chain that visits every
       node exactly once (hops == NodeChunk.Used, then -1) is legal. */
    printf("A long acyclic slot chain\n");
    {
        CacheHT c;
        int i;

        BuildValidImage(Map, &c, &End, 24);
        if( c.NodeChunk.Used >= 3 )
        {
            TestSlot *s = SlotAt(Map, CACHE_SIZE, c.Slots.Used, 0);
            s->Next = 0;
            for( i = 0; i < c.NodeChunk.Used - 1; ++i )
            {
                Cht_Node *n = NodeAt(Map, CACHE_SIZE, c.Slots.Used, i);
                n->Next = i + 1;
            }
            NodeAt(Map, CACHE_SIZE, c.Slots.Used,
                   c.NodeChunk.Used - 1)->Next = -1;
            expect("an acyclic chain of every node is accepted",
                   Validate(&c, Map, End) == TRUE);
        }
        else
        {
            expect("(skip: fewer than 3 nodes in the image)", TRUE);
        }
    }

    (void)SlotsUsed;
    free(Map);

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
