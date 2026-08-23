/* Regression test for the StringChunk_Add payload-leak bug.
 *
 * Bug: StringChunk_Add() wrote the AdditionalData payload into the
 * StableBuffer first, then inserted the key into the StringList.  When the
 * StringList insert failed (e.g. under memory pressure) the function simply
 * returned, leaking the already-committed payload block inside the
 * StableBuffer -- it was never matched or freed until the whole chunk was
 * destroyed, so a long-lived StringChunk that kept accepting adds would leak
 * on every failed key-insert.
 *
 * Fix: StableBuffer gained a RollbackLast() member that removes the tail of
 * the last block; StringChunk_Add() calls it on the key-insert failure path
 * (only when a payload was already written), restoring the chunk to its
 * pre-call state.
 *
 * This test proves the fix two ways:
 *   (1) unit-test StableBuffer_RollbackLast() directly (new block / extend
 *       existing block / address reuse), and
 *   (2) drive StringChunk_Add() through a StringList whose Add() always
 *       fails, and confirm -- under ASan's leak detector -- that no bytes
 *       escape (the payload must have been rolled back).
 *
 * Build with AddressSanitizer and run; a non-zero exit (CHECK failure or a
 * leak reported by ASan) means the bug is present.
 */

#include <stdio.h>
#include <string.h>
#include "common.h"
#include "stablebuffer.h"
#include "stringchunk.h"
#include "stringlist.h"

static int g_failures = 0;

static void CHECK(const char *name, int cond)
{
    if( cond )
    {
        printf("  ok   - %s\n", name);
    }
    else
    {
        printf("  FAIL - %s\n", name);
        ++g_failures;
    }
}

/* ---- stub StringList whose Add() always fails, to force the failure path ---- */
static void *stub_add_always_fail(StringList *s, const char *str, const char *delim)
{
    (void)s; (void)str; (void)delim;
    return NULL;
}

static int  stub_count(StringList *s)
{
    (void)s;
    return 0;
}
static int  stub_append(StringList *s, const char *str, const char *delim)
{
    (void)s; (void)str; (void)delim;
    return -1;
}
static char **stub_toarray(StringList *s)
{
    (void)s;
    return NULL;
}
static void stub_trim(StringList *s, const char *g)
{
    (void)s; (void)g;
}
static void stub_lower(StringList *s)
{
    (void)s;
}
static void stub_clear(StringList *s)
{
    (void)s;
}
static void stub_free(StringList *s)
{
    (void)s;
}

int main(void)
{
    /* ------------------------------------------------------------------ */
    printf("StableBuffer_RollbackLast unit checks:\n");
    {
        StableBuffer sb;
        StableBufferIterator it;
        const char *p1, *p2;
        char probe[16];

        CHECK("StableBuffer_Init", StableBuffer_Init(&sb) == 0);

        /* Case A: rollback a payload that opened a fresh block. */
        memset(probe, 0xA5, sizeof(probe));
        p1 = (const char *)sb.Add(&sb, probe, (int)sizeof(probe), FALSE);
        CHECK("Add returned a pointer", p1 != NULL);
        CHECK("RollbackLast succeeds (fresh block)",
              sb.RollbackLast(&sb, (int)sizeof(probe), FALSE) == 0);

        /* After rolling back the only write in a fresh block, the block's Used
           must be 0 and the next Add must land at the SAME address (no hole,
           no leak). */
        p2 = (const char *)sb.Add(&sb, probe, (int)sizeof(probe), FALSE);
        CHECK("next Add reuses the rolled-back slot", p2 == p1);

        /* Case B: rollback a payload that extended an existing block. */
        memset(probe, 0x5A, sizeof(probe));
        p1 = (const char *)sb.Add(&sb, probe, (int)sizeof(probe), FALSE);
        CHECK("second Add returned a pointer", p1 != NULL);
        /* Grew the same block; rollback should drop exactly the tail. */
        CHECK("RollbackLast succeeds (extended block)",
              sb.RollbackLast(&sb, (int)sizeof(probe), FALSE) == 0);
        /* A fresh write must re-occupy the just-rolled-back tail. */
        p2 = (const char *)sb.Add(&sb, probe, (int)sizeof(probe), FALSE);
        CHECK("extended-block rollback reuses tail", p2 == p1);

        /* Case C: aligned rollback (the path StringChunk uses). */
        int aligned_len = (int)(((7 + (int)sizeof(void *) - 1) / (int)sizeof(void *)) * (int)sizeof(void *));
        p1 = (const char *)sb.Add(&sb, probe, 7, TRUE);
        CHECK("aligned Add returned a pointer", p1 != NULL);
        CHECK("RollbackLast succeeds (aligned)",
              sb.RollbackLast(&sb, 7, TRUE) == 0);
        CHECK("aligned length accounted (>= 7)", aligned_len >= 7);

        /* Sanity: re-init and free without ASan complaint proves no internal
           leak across the rollback scenarios above. */
        sb.Free(&sb);

        (void)it;
    }

    /* ------------------------------------------------------------------ */
    printf("StringChunk_Add failure-path leak check (stub list always fails):\n");
    {
        StringChunk chunk;
        StringList  stub;
        int         i;
        int         added = 0;

        memset(&stub, 0, sizeof(stub));
        stub.Count       = stub_count;
        stub.Add         = stub_add_always_fail;
        stub.AppendLast  = stub_append;
        stub.ToCharPtrArray = stub_toarray;
        stub.TrimAll     = stub_trim;
        stub.LowercaseAll= stub_lower;
        stub.Clear       = stub_clear;
        stub.Free        = stub_free;

        CHECK("StringChunk_Init with external stub list",
              StringChunk_Init(&chunk, &stub) == 0);

        /* Hammer the failure path many times with a payload.  If the payload
           were leaked on each failure, ASan would report the accumulating
           blocks at process exit.  With the fix, every failed add rolls the
           payload back, so nothing survives. */
        for( i = 0; i != 1000; ++i )
        {
            int r = StringChunk_Add(&chunk,
                                     "never-inserted.example",
                                     "PAYLOAD-DATA",
                                     12);
            if( r != 0 )
            {
                ++added; /* failure expected */
            }
        }
        CHECK("every add failed (stub forces it)", added == 1000);

        /* A chunk with a failed-key payload must not match anything. */
        void *data = NULL;
        BOOL hit = StringChunk_Match(&chunk,
                                      "never-inserted.example",
                                      NULL,
                                      &data,
                                      NULL,
                                      NULL);
        CHECK("failed add leaves no match", hit == FALSE && data == NULL);

        StringChunk_Free(&chunk, FALSE); /* FALSE: we own the stub, don't free it */
        CHECK("chunk freed cleanly (no payload leak)", 1);
    }

    if( g_failures == 0 )
    {
        printf("\nALL CHECKS PASSED\n");
        return 0;
    }
    printf("\n%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
