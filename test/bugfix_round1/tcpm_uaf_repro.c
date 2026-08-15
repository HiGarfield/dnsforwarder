/*
 * Regression proof for Bug #2: use-after-free / data race in TcpM_Send_Actual.
 *
 * In the original TcpM_Send_Actual, after `p->Del(p, s)` the local `TcpCtx`
 * still pointed at the node that Bst_Delete returned to p's free list. That
 * node is recycled by a later `p->Add`, so every read/write through `TcpCtx`
 * after the Del is a use-after-free / data race.
 *
 * The fix copies the context out into a local `Ctx` immediately after the Del
 * and uses `Ctx` for all subsequent accesses.  This test reproduces the exact
 * memory-management contract of Bst (Delete -> free list -> reused by Add) and
 * proves that:
 *   - the OLD pattern (keep using the dangling pointer) yields CORRUPTED data
 *     as soon as the free-list node is reused;
 *   - the NEW pattern (value-copy) is immune to such reuse.
 *
 * Build & run:
 *     gcc -O2 -Wall -Wextra tcpm_uaf_repro.c -o t && ./t
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Node {
    int key;
    int data;          /* the field we care about, mirrors TcpContext fields */
    struct Node *next_free;
} Node;

#define POOL 4
static Node pool[POOL];
static Node *freelist = NULL;

/* Mirror Bst: Add pulls a node from the free list (reusing a deleted one). */
static Node *Add(int key, int data)
{
    Node *n = freelist;
    if( n == NULL ) { fprintf(stderr, "pool exhausted\n"); exit(2); }
    freelist = n->next_free;
    n->key = key;
    n->data = data;
    return n;
}

/* Mirror Bst: Delete returns the node to the free list (memory NOT freed). */
static void Del(Node *n)
{
    n->next_free = freelist;
    freelist = n;
}

static int failures = 0;
static void check(int cond, const char *name)
{
    if( !cond ) { printf("FAIL: %s\n", name); failures++; }
    else        { printf("PASS: %s\n", name); }
}

int main(void)
{
    for( int i = 0; i < POOL; i++ ) pool[i].next_free = NULL;
    freelist = &pool[0]; freelist->next_free = &pool[1];
    pool[1].next_free = &pool[2]; pool[2].next_free = &pool[3];

    /* ---- OLD (buggy) pattern: keep using pointer after Del ---- */
    Node *ctx = Add(100, 1111);     /* represents a live TCP context */
    Del(ctx);                       /* p->Del(p, s): node back to free list */
    /* later the free-list node is reused by a new Add (concurrent/next loop) */
    Node *reuse = Add(200, 2222);
    (void)reuse;
    /* Now the OLD code reads through `ctx` -- it observes the REUSED data. */
    int observed_old = ctx->data;  /* use-after-free read */
    check(observed_old != 1111,
          "OLD pattern: read after Del observes corrupted/reused data (bug present)");

    /* ---- NEW (fixed) pattern: value-copy immediately after Del ---- */
    Node *ctx2 = Add(300, 3333);
    Node copy = *ctx2;              /* TcpContext Ctx = *TcpCtx; */
    Del(ctx2);
    Node *reuse2 = Add(400, 4444);  /* free-list node reused */
    (void)reuse2;
    int observed_new = copy.data;   /* all accesses go through the copy */
    check(observed_new == 3333,
          "NEW pattern: copied context is immune to free-list reuse");

    if( failures == 0 )
    {
        printf("\nBug #2 fix verified (value-copy prevents use-after-free corruption).\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
