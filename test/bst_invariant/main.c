/*
 * Rigorous structural verification of bst.c.
 *
 * The pre-existing test/bst only prints and always exits 0, so structural
 * corruption in Bst_Delete goes unnoticed. This test verifies, after every
 * single mutation, that:
 *
 *   1. The BST ordering property holds for every node.
 *   2. Every child's Parent pointer points back at its actual parent.
 *   3. The root has a NULL Parent.
 *   4. No node is reachable twice (no cycles / no shared subtrees).
 *   5. The set of live keys matches exactly what was inserted/deleted.
 *   6. Bst_Search finds every live key and no deleted key.
 *   7. Bst_Minimum returns the smallest live key.
 *   8. Bst_Successor walks all live keys in ascending order exactly once.
 *
 * It does so for hand-picked shapes that exercise each Bst_Delete branch and
 * then for a long pseudo-random add/delete soak, which is what actually
 * catches parent-pointer corruption in the two-child replacement path.
 */

#include "../../bst.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYS 512

static int Checks = 0;
static int Failures = 0;

static void ok(const char *what, int cond)
{
    ++Checks;
    if( cond )
    {
        return;
    }
    ++Failures;
    printf("  [FAIL] %s\n", what);
}

static int CompareInt(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    if( x < y ) return -1;
    if( x > y ) return 1;
    return 0;
}

/* ---- structural walker ------------------------------------------------- */

typedef struct {
    const Bst_NodeHead *Seen[MAX_KEYS * 4];
    int                 SeenCount;

    int                 Keys[MAX_KEYS * 4];
    int                 KeyCount;

    int                 Ok;         /* structure is sane so far */
} Walk;

static int AlreadySeen(Walk *w, const Bst_NodeHead *n)
{
    int i;
    for( i = 0; i < w->SeenCount; ++i )
    {
        if( w->Seen[i] == n )
        {
            return 1;
        }
    }
    return 0;
}

/* In-order walk collecting keys, validating parent links and node bounds. */
static void WalkNode(Walk *w,
                     const Bst_NodeHead *n,
                     const Bst_NodeHead *ExpectedParent,
                     int HasLow, int Low,
                     int HasHigh, int High
                     )
{
    int key;

    if( n == NULL )
    {
        return;
    }

    if( AlreadySeen(w, n) )
    {
        w->Ok = 0;                      /* cycle or shared subtree */
        return;
    }

    if( w->SeenCount >= (int)(sizeof(w->Seen) / sizeof(w->Seen[0])) )
    {
        w->Ok = 0;
        return;
    }
    w->Seen[w->SeenCount++] = n;

    if( n->Parent != ExpectedParent )
    {
        w->Ok = 0;                      /* parent back-pointer corrupted */
    }

    key = *(const int *)(n + 1);

    /* bst.c inserts equal keys to the left, so duplicates would make the
       bounds non-strict.  This test never inserts duplicates, so strict
       bounds are the right assertion. */
    if( HasLow && !(key > Low) )
    {
        w->Ok = 0;
    }
    if( HasHigh && !(key < High) )
    {
        w->Ok = 0;
    }

    WalkNode(w, n->Left, n, HasLow, Low, 1, key);

    if( w->KeyCount < (int)(sizeof(w->Keys) / sizeof(w->Keys[0])) )
    {
        w->Keys[w->KeyCount++] = key;
    } else {
        w->Ok = 0;
    }

    WalkNode(w, n->Right, n, 1, key, HasHigh, High);
}

/* `Live` is a sorted array of the keys that must be present. */
static void VerifyTree(Bst *t, const int *Live, int LiveCount, const char *Where)
{
    static Walk w;                      /* static: keeps stack usage tiny */
    char msg[256];
    int i;

    memset(&w, 0, sizeof(w));
    w.Ok = 1;

    if( t->Root != NULL && t->Root->Parent != NULL )
    {
        w.Ok = 0;
    }

    WalkNode(&w, t->Root, NULL, 0, 0, 0, 0);

    sprintf(msg, "%s: tree structure (order + parent links + acyclic)", Where);
    ok(msg, w.Ok);

    sprintf(msg, "%s: node count is %d", Where, LiveCount);
    ok(msg, w.KeyCount == LiveCount);

    if( w.KeyCount == LiveCount )
    {
        int same = 1;
        for( i = 0; i < LiveCount; ++i )
        {
            if( w.Keys[i] != Live[i] )
            {
                same = 0;
                break;
            }
        }
        sprintf(msg, "%s: in-order traversal equals the sorted live set", Where);
        ok(msg, same);
    }

    /* Search must find every live key. */
    {
        int allFound = 1;
        for( i = 0; i < LiveCount; ++i )
        {
            int k = Live[i];
            const void *f = t->Search(t, &k, NULL);
            if( f == NULL || *(const int *)f != k )
            {
                allFound = 0;
                break;
            }
        }
        sprintf(msg, "%s: Search finds every live key", Where);
        ok(msg, allFound);
    }

    /* Minimum must be the smallest live key. */
    if( LiveCount > 0 )
    {
        const void *m = t->Minimum(t, NULL);
        sprintf(msg, "%s: Minimum is the smallest live key", Where);
        ok(msg, m != NULL && *(const int *)m == Live[0]);
    } else {
        sprintf(msg, "%s: empty tree has a NULL root", Where);
        ok(msg, t->Root == NULL);
    }

    /* Successor must enumerate every live key in ascending order, once. */
    if( LiveCount > 0 )
    {
        const void *cur = t->Minimum(t, NULL);
        int n = 0;
        int good = 1;

        while( cur != NULL )
        {
            if( n >= LiveCount || *(const int *)cur != Live[n] )
            {
                good = 0;
                break;
            }
            ++n;
            cur = t->Successor(t, cur);
        }

        if( n != LiveCount )
        {
            good = 0;
        }

        sprintf(msg, "%s: Successor walks all %d keys in order", Where, LiveCount);
        ok(msg, good);
    }
}

/* ---- live-key bookkeeping --------------------------------------------- */

static int Live[MAX_KEYS];
static int LiveCount = 0;

static int LiveIndexOf(int k)
{
    int i;
    for( i = 0; i < LiveCount; ++i )
    {
        if( Live[i] == k ) return i;
        if( Live[i] > k )  return -1;
    }
    return -1;
}

static void LiveInsert(int k)
{
    int i, j;
    for( i = 0; i < LiveCount && Live[i] < k; ++i ) {}
    for( j = LiveCount; j > i; --j )
    {
        Live[j] = Live[j - 1];
    }
    Live[i] = k;
    ++LiveCount;
}

static void LiveRemove(int idx)
{
    int j;
    for( j = idx; j + 1 < LiveCount; ++j )
    {
        Live[j] = Live[j + 1];
    }
    --LiveCount;
}

static void DoAdd(Bst *t, int k)
{
    if( LiveIndexOf(k) >= 0 )
    {
        return;                         /* keep the key set duplicate-free */
    }
    if( t->Add(t, &k) == NULL )
    {
        ok("Bst_Add did not run out of memory", 0);
        return;
    }
    LiveInsert(k);
}

static void DoDel(Bst *t, int k)
{
    const void *n;
    int idx = LiveIndexOf(k);

    n = t->Search(t, &k, NULL);

    if( idx < 0 )
    {
        ok("Search does not find a deleted key", n == NULL);
        return;
    }

    if( n == NULL )
    {
        ok("Search finds a key that is supposed to be live", 0);
        return;
    }

    t->Delete(t, n);
    LiveRemove(idx);
}

static void ResetAll(Bst *t)
{
    t->Reset(t);
    LiveCount = 0;
}

/* ---- deterministic PRNG (so failures are reproducible) ---------------- */

static unsigned long RngState = 20240601UL;

static unsigned long Rng(void)
{
    RngState = RngState * 1103515245UL + 12345UL;
    return (RngState >> 8) & 0x7fffffffUL;
}

int main(void)
{
    Bst t;
    int i, round;

    printf("== bst structural invariant regression tests ==\n\n");

    if( Bst_Init(&t, sizeof(int), CompareInt) != 0 )
    {
        printf("Bst_Init failed\n");
        return 1;
    }

    /* --- Shape 1: delete a leaf --------------------------------------- */
    printf("Delete a leaf\n");
    DoAdd(&t, 50); DoAdd(&t, 30); DoAdd(&t, 70); DoAdd(&t, 20); DoAdd(&t, 40);
    DoDel(&t, 20);
    VerifyTree(&t, Live, LiveCount, "leaf delete");
    ResetAll(&t);

    /* --- Shape 2: delete a node with only a left child ---------------- */
    printf("Delete a node with only a left child\n");
    DoAdd(&t, 50); DoAdd(&t, 30); DoAdd(&t, 20);
    DoDel(&t, 30);
    VerifyTree(&t, Live, LiveCount, "left-only delete");
    ResetAll(&t);

    /* --- Shape 3: delete a node with only a right child --------------- */
    printf("Delete a node with only a right child\n");
    DoAdd(&t, 50); DoAdd(&t, 30); DoAdd(&t, 40);
    DoDel(&t, 30);
    VerifyTree(&t, Live, LiveCount, "right-only delete");
    ResetAll(&t);

    /* --- Shape 4: two children, successor is the right child itself ---
       This is the branch where ActuallyRemoved == Current->Right, i.e. the
       replacement node's own parent is the node being unlinked. */
    printf("Delete a node whose successor is its right child\n");
    DoAdd(&t, 50); DoAdd(&t, 30); DoAdd(&t, 70); DoAdd(&t, 80);
    DoDel(&t, 50);
    VerifyTree(&t, Live, LiveCount, "successor-is-right-child delete");
    ResetAll(&t);

    /* --- Shape 5: two children, successor is deeper ------------------- */
    printf("Delete a node whose successor is deeper in the right subtree\n");
    DoAdd(&t, 50); DoAdd(&t, 30); DoAdd(&t, 80); DoAdd(&t, 60); DoAdd(&t, 90);
    DoAdd(&t, 70);
    DoDel(&t, 50);
    VerifyTree(&t, Live, LiveCount, "deep-successor delete");
    ResetAll(&t);

    /* --- Shape 6: delete the root repeatedly until empty -------------- */
    printf("Delete the root repeatedly until the tree is empty\n");
    for( i = 0; i < 16; ++i )
    {
        DoAdd(&t, (int)(Rng() % 1000));
    }
    while( LiveCount > 0 )
    {
        int rootKey = *(const int *)(t.Root + 1);
        DoDel(&t, rootKey);
        VerifyTree(&t, Live, LiveCount, "root delete chain");
    }
    ResetAll(&t);

    /* --- Shape 7: descending inserts (pure left chain) ---------------- */
    printf("Delete from a pure left chain\n");
    for( i = 20; i > 0; --i )
    {
        DoAdd(&t, i);
    }
    for( i = 1; i <= 20; i += 2 )
    {
        DoDel(&t, i);
        VerifyTree(&t, Live, LiveCount, "left-chain delete");
    }
    ResetAll(&t);

    /* --- Shape 8: ascending inserts (pure right chain) --------------- */
    printf("Delete from a pure right chain\n");
    for( i = 1; i <= 20; ++i )
    {
        DoAdd(&t, i);
    }
    for( i = 20; i >= 1; i -= 2 )
    {
        DoDel(&t, i);
        VerifyTree(&t, Live, LiveCount, "right-chain delete");
    }
    ResetAll(&t);

    /* --- Soak: randomized add/delete, verified after every step ------- */
    printf("Randomized add/delete soak\n");
    for( round = 0; round < 4; ++round )
    {
        int step;

        ResetAll(&t);

        for( step = 0; step < 400; ++step )
        {
            int k = (int)(Rng() % 200);

            if( LiveCount > 0 && (Rng() & 1) )
            {
                /* Delete an existing key more often than a missing one, so
                   the two-child replacement path is hit frequently. */
                if( Rng() & 1 )
                {
                    k = Live[(int)(Rng() % (unsigned long)LiveCount)];
                }
                DoDel(&t, k);
            } else {
                DoAdd(&t, k);
            }

            /* Verifying every step is what makes this test able to localise
               corruption to the exact mutation that caused it. */
            VerifyTree(&t, Live, LiveCount, "soak");

            if( Failures > 0 )
            {
                printf("  (stopping soak at round %d step %d)\n", round, step);
                round = 1000;
                break;
            }
        }
    }

    /* --- Free-list reuse: delete everything, then refill -------------- */
    printf("Free-list reuse after deleting every node\n");
    ResetAll(&t);
    for( i = 0; i < 40; ++i )
    {
        DoAdd(&t, i);
    }
    while( LiveCount > 0 )
    {
        DoDel(&t, Live[0]);
    }
    VerifyTree(&t, Live, LiveCount, "emptied tree");
    for( i = 100; i < 140; ++i )
    {
        DoAdd(&t, i);
    }
    VerifyTree(&t, Live, LiveCount, "refilled from free list");

    t.Free(&t);

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
