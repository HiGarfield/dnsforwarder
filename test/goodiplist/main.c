/*
 * Regression test for the goodiplist "fastest-IP swap" overlap bug.
 *
 * Bug: In GoodIpList's measurement task (ThreadJod), the fastest IP is moved
 * to the front of the list with a three-step swap using memcpy():
 *
 *     memcpy(&t, Fastest, sizeof(...));
 *     memcpy(Fastest, First,  sizeof(...));
 *     memcpy(First, &t,  sizeof(...));
 *
 * When the fastest IP is the one already at index 0, `Fastest` and `First`
 * alias the SAME element, so memcpy() is invoked with a source that overlaps
 * its destination -- undefined behaviour. Even though a self-swap happens to
 * be a no-op for many memcpy implementations, the standard does not guarantee
 * it, and any future change that makes the two regions only *partially*
 * overlap would silently corrupt the list under a plain memcpy while memmove()
 * would stay correct.
 *
 * The real fix swaps memcpy for memmove (see goodiplist.c). This test proves
 * both:
 *   (a) the exact self-swap from ThreadJod() leaves the list intact (the
 *       contract the fix must preserve -- no regression), and
 *   (b) a PARTIALLY-overlapping copy (the latent form of the same defect)
 *       is corrupted by memcpy() but preserved by memmove(), showing why
 *       memmove() is the correct primitive.
 *
 * Built twice by run.sh:
 *   - -DGI_USE_MEMCPY : old path, expected to FAIL the partial-overlap check
 *     (proves the defect is real).
 *   - default         : fixed memmove() path, expected to pass everything.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "array.h"

static int failures = 0;
#define CHECK(c, m) do { if(!(c)) { printf("FAIL: %s\n", m); ++failures; } } while(0)

static uint32_t addr(int x) { return htonl((uint32_t)(0x0A000000u + x)); }

/* Reproduces the ThreadJod self-swap: Fastest == First (index 0). */
static void self_swap(struct sockaddr_in *buf)
{
    struct sockaddr_in *First  = &buf[0];
    struct sockaddr_in *Fastest = &buf[0];   /* fastest is index 0 */
    struct sockaddr_in t;

#ifdef GI_USE_MEMCPY
    memcpy(&t, Fastest, sizeof(t));
    memcpy(Fastest, First, sizeof(t));
    memcpy(First, &t, sizeof(t));
#else
    memmove(&t, Fastest, sizeof(t));
    memmove(Fastest, First, sizeof(t));
    memmove(First, &t, sizeof(t));
#endif
}

/* Partially-overlapping regions: dst starts one element before src, so the
 * copy window overlaps by (N-1) elements. A rotate-left by one slot. memcpy
 * is UB here and typically corrupts the tail; memmove must preserve it. */
static void rotate_one_slot(struct sockaddr_in *buf, int n)
{
    struct sockaddr_in *src = &buf[1];
    struct sockaddr_in *dst = &buf[0];
    size_t len = (size_t)(n - 1) * sizeof(struct sockaddr_in);

#ifdef GI_USE_MEMCPY
    memcpy(dst, src, len);
#else
    memmove(dst, src, len);
#endif
}

int main(void)
{
    struct sockaddr_in buf[3];
    int i;

    memset(buf, 0, sizeof(buf));
    for( i = 0; i < 3; ++i ) {
        buf[i].sin_family = 2;
        buf[i].sin_port   = htons(53);
        buf[i].sin_addr.s_addr = addr(i + 10);
    }

    /* (a) self-swap contract: index 0 unchanged, whole list intact. */
    self_swap(buf);
    CHECK(buf[0].sin_addr.s_addr == addr(10), "self-swap: index0 preserved");
    CHECK(buf[1].sin_addr.s_addr == addr(11), "self-swap: index1 preserved");
    CHECK(buf[2].sin_addr.s_addr == addr(12), "self-swap: index2 preserved");

    /* (b) partial overlap: rotate-left by one slot must keep every element.
     * Correct result: buf[0]=old buf[1], buf[1]=old buf[2], buf[2]=old buf[2]
     * (the last element is copied onto itself by the rotate). */
    buf[0].sin_addr.s_addr = addr(20);
    buf[1].sin_addr.s_addr = addr(21);
    buf[2].sin_addr.s_addr = addr(22);

    rotate_one_slot(buf, 3);
    CHECK(buf[0].sin_addr.s_addr == addr(21), "rotate: new index0 == old index1");
    CHECK(buf[1].sin_addr.s_addr == addr(22), "rotate: new index1 == old index2");
    CHECK(buf[2].sin_addr.s_addr == addr(22), "rotate: index2 unchanged");

    if( failures == 0 )
        printf("GOODIPLIST_OVERLAP_OK\n");
    return failures == 0 ? 0 : 1;
}
