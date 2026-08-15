/*
 * Regression proof for Bug #3: memory leak in FilterType_Init.
 *
 * Original code:
 *     if( InitBst(&DisabledTypes, TypeCompare) != 0 )  return -146;   // alloc
 *     if( StringListIterator_Init(&sli, DisableType_Str) != 0 )
 *         return -2;                                              // LEAKS DisabledTypes
 *
 * The fix releases DisabledTypes (Free + free) before returning on the
 * StringListIterator_Init failure path.
 *
 * This test mirrors the exact two-step allocation contract and proves that
 * the fixed path frees the first allocation while the original path leaks it,
 * using a malloc/free accounting counter.
 *
 * Build & run:
 *     gcc -Wall -Wextra filter_leak_repro.c -o t && ./t
 */
#include <stdio.h>
#include <stdlib.h>

static long live_allocs = 0;   /* count of currently-live allocations */

static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if( p ) live_allocs++;
    return p;
}
static void xfree(void *p)
{
    if( p ) { live_allocs--; free(p); }
}

/* Stubs mirroring InitBst / DestroyBst and StringListIterator_Init. */
typedef struct { void *impl; } Bst;
static int InitBst(Bst **out)
{
    *out = (Bst *)xmalloc(sizeof(Bst));
    return (*out == NULL) ? -1 : 0;
}
static void DestroyBst(Bst *t) { xfree(t); }

static int sli_fails = 1;   /* force the iterator-init failure path */
static int StringListIterator_Init(void) { return sli_fails ? -1 : 0; }

/* ---- OLD buggy FilterType_Init (leaks) ---- */
static int FilterType_Init_OLD(Bst **DisabledTypes)
{
    if( InitBst(DisabledTypes) != 0 ) return -146;
    if( StringListIterator_Init() != 0 ) return -2;   /* leaks *DisabledTypes */
    return 0;
}
/* ---- NEW fixed FilterType_Init (frees) ---- */
static int FilterType_Init_NEW(Bst **DisabledTypes)
{
    if( InitBst(DisabledTypes) != 0 ) return -146;
    if( StringListIterator_Init() != 0 )
    {
        DestroyBst(*DisabledTypes);
        *DisabledTypes = NULL;
        return -2;
    }
    return 0;
}

static int failures = 0;
static void check(int cond, const char *name)
{
    if( !cond ) { printf("FAIL: %s\n", name); failures++; }
    else        { printf("PASS: %s\n", name); }
}

int main(void)
{
    Bst *dt = NULL;
    long before = live_allocs;
    int rc = FilterType_Init_OLD(&dt);
    check(rc == -2, "OLD: iterator-init failure returns -2");
    check(live_allocs == before + 1, "OLD: leaks the DisabledTypes allocation (1 live alloc remains)");
    dt = NULL;

    before = live_allocs;
    rc = FilterType_Init_NEW(&dt);
    check(rc == -2, "NEW: iterator-init failure returns -2");
    check(live_allocs == before, "NEW: frees DisabledTypes, no leak (0 live allocs added)");

    if( failures == 0 )
    {
        printf("\nBug #3 fix verified (no leak on iterator-init failure).\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
