/* Regression test for the CacheHT free-list / NodeChunk consistency bug.
 *
 * Bug: CacheHT_RemoveFromSlot used to drop the *last* node of the NodeChunk
 * with `--(NodeChunk->Used)'.  A node that had already been freed earlier
 * (and was therefore still referenced by another node's KeyNext/ValNext
 * inside the free 2D list) could become that last node, get its subscript
 * truncated away, and then be dereferenced as a NULL pointer the next time
 * the free list was walked (CacheHT_FindUnusedNode -> HeirHead->KeyNext).
 *
 * The fix returns every removed node to the free list unconditionally, so no
 * live link ever points at a subscript outside `Used'.
 *
 * Build (from the repository root):
 *   cc -I. -g -fsanitize=address,undefined -o /tmp/t_cacheht \
 *      test/cacheht/main.c cacheht.c array.c utils.c -lpthread
 * (logs.c/addresslist.c are stubbed for the standalone build; see run.sh.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cacheht.h"
#include "common.h"

static int Failures = 0;

static void Check(const char *Name, int Condition)
{
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
    enum { CAP = 1 << 20 };
    char *buf = malloc(CAP);
    CacheHT ht;
    BOOL created;
    Cht_Node *a = NULL, *b = NULL, *c = NULL, *reuse = NULL;
    int32_t sa, sb, sc, sr;
    uint32_t hk = 12345;

    if( buf == NULL )
    {
        fprintf(stderr, "malloc failed\n");
        return 2;
    }
    memset(buf, 0, CAP);

    Check("CacheHT_Init", CacheHT_Init(&ht, buf, CAP) == 0);

    /* Two nodes with the SAME Length so they share a 2D-list chain, with A
       preceding B in the NodeChunk. */
    sa = CacheHT_FindUnusedNode(&ht, 64, &a, buf, &created);
    sb = CacheHT_FindUnusedNode(&ht, 64, &b, buf, &created);
    Check("alloc A/B", sa >= 0 && sb >= 0 && a != NULL && b != NULL);

    CacheHT_InsertToSlot(&ht, "keyA", sa, a, &hk);
    CacheHT_InsertToSlot(&ht, "keyB", sb, b, &hk);

    /* Free both so they live in the free 2D list (A.ValNext -> B). */
    CacheHT_RemoveFromSlot(&ht, sa, a);
    CacheHT_RemoveFromSlot(&ht, sb, b);

    /* Allocate a different-sized node C and remove it: C becomes the last node
       and gets truncated. Then remove B (which is now the last node) -> another
       `--Used', invalidating B's subscript while A.ValNext still points at B. */
    sc = CacheHT_FindUnusedNode(&ht, 128, &c, buf, &created);
    Check("alloc C", sc >= 0 && c != NULL);
    CacheHT_InsertToSlot(&ht, "keyC", sc, c, &hk);
    CacheHT_RemoveFromSlot(&ht, sc, c);
    CacheHT_RemoveFromSlot(&ht, sb, b);

    /* Reusing A must not crash: the stale ValNext/KeyNext into B's now-invalid
       subscript used to yield a NULL HeirHead / CurNode and segfault here. */
    sr = CacheHT_FindUnusedNode(&ht, 64, &reuse, buf, &created);
    Check("reuse A without crash", sr >= 0 && reuse != NULL);

    CacheHT_Free(&ht);
    free(buf);

    printf("\n%s\n", Failures == 0 ? "cacheht: all checks passed" : "cacheht: FAILURES");
    return Failures == 0 ? 0 : 1;
}
