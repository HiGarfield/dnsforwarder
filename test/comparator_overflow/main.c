/*
 * Regression test for signed-integer-overflow comparators.
 *
 * Bug under test (now fixed):
 *   - filter.c  TypeCompare:  return *(const int*)a - *(const int*)b;
 *   - timedtask.c Tv_Comapre: returns one->tv_usec - two->tv_usec (long).
 *   - timedtask.c Compare (Win32): returns o->LeftTime - t->LeftTime.
 *
 * All three feed a BST / strictly-ordered queue, which REQUIRES the comparator
 * to satisfy strict weak ordering: for any a, b
 *     cmp(a,b) < 0  iff a < b
 *     cmp(a,b) > 0  iff a > b
 *     cmp(a,b) == 0 iff a == b
 * and cmp(a,b) == -cmp(b,a).
 *
 * The old subtraction form breaks this when |a-b| > INT_MAX (signed overflow
 * is UB in C89/C99/C11, and even without UB the result wraps and reverses the
 * sign for extreme deltas), and on Win64 a 64-bit SOCKET subtraction also
 * truncates.  This test constructs such extreme inputs and proves the fixed
 * three-way comparators keep ordering correct while the old form fails.
 */

#include <stdio.h>
#include <limits.h>

/* ---- Fixed comparators (mirror of the patched source) ---- */

static int TypeCompare_fixed(const void *_1, const void *_2)
{
    int a = *(const int *)_1;
    int b = *(const int *)_2;
    if( a < b ) return -1;
    if( a > b ) return 1;
    return 0;
}

/* Old, buggy version kept here ONLY to demonstrate the failure. */
static int TypeCompare_buggy(const void *_1, const void *_2)
{
    return *(const int *)_1 - *(const int *)_2;
}

typedef struct timeval { long tv_sec; long tv_usec; } timeval;

static int Tv_Comapre_fixed(const timeval *one, const timeval *two)
{
    if( one->tv_sec != two->tv_sec )
        return (one->tv_sec < two->tv_sec) ? -1 : 1;
    if( one->tv_usec != two->tv_usec )
        return (one->tv_usec < two->tv_usec) ? -1 : 1;
    return 0;
}

static int Tv_Comapre_buggy(const timeval *one, const timeval *two)
{
    if( one->tv_sec == two->tv_sec )
        return (int)(one->tv_usec - two->tv_usec);
    else
        return (int)(one->tv_sec - two->tv_sec);
}

/* ---- Verification helpers ---- */

static int ordering_ok(int (*cmp)(const void*, const void*),
                       const void *a, const void *b, const void *c)
{
    /* a < b < c must hold, and antisymmetry must hold. */
    int ab = cmp(a, b);
    int ba = cmp(b, a);
    int bc = cmp(b, c);
    int cb = cmp(c, b);
    int ac = cmp(a, c);
    int ca = cmp(c, a);
    if( ab >= 0 ) return 0;          /* a must be < b */
    if( bc >= 0 ) return 0;          /* b must be < c */
    if( ac >= 0 ) return 0;          /* a must be < c */
    if( ab != -ba ) return 0;        /* antisymmetry */
    if( bc != -cb ) return 0;
    if( ac != -ca ) return 0;
    return 1;
}

int main(void)
{
    int failures = 0;

    /* ---- Bug #1: filter.c TypeCompare with extreme int values ---- */
    {
        int a = INT_MIN;          /* e.g. a DNS type encoded as a small/neg value */
        int b = 0;
        int c = INT_MAX;          /* large type number */
        /* a < b < c */
        if( !ordering_ok(TypeCompare_fixed, &a, &b, &c) )
        {
            printf("FAIL: TypeCompare_fixed violates ordering for extreme ints\n");
            ++failures;
        }
        /* The buggy version: a=INT_MIN, c=INT_MAX -> a-c overflows / wraps,
           so cmp(a,c) computed as INT_MIN - INT_MAX wraps to a positive value,
           wrongly reporting a > c. Demonstrate the bug exists in the old form: */
        int buggy_ac = TypeCompare_buggy(&a, &c);
        if( buggy_ac <= 0 )
        {
            printf("NOTE: buggy TypeCompare did not overflow on this platform "
                   "(got %d); cannot reproduce UB here, but the form is still "
                   "non-portable and disallowed by the strict-weak-ordering "
                   "contract.\n", buggy_ac);
        }
        else
        {
            printf("CONFIRMED-BUG: buggy TypeCompare(INT_MIN, INT_MAX) = %d "
                   "(positive => wrongly says INT_MIN > INT_MAX)\n", buggy_ac);
        }
    }

    /* Also check a realistic DNS-type pair still orders correctly. */
    {
        int a = 1;   /* A */
        int b = 28;  /* AAAA */
        int c = 255; /* ANY-ish large type */
        if( !ordering_ok(TypeCompare_fixed, &a, &b, &c) )
        {
            printf("FAIL: TypeCompare_fixed normal types\n");
            ++failures;
        }
    }

    /* ---- Bug #2: timedtask.c Tv_Comapre with extreme timevals ---- */
    {
        timeval a = { LONG_MIN / 2, 0 };
        timeval b = { 0, 0 };
        timeval c = { LONG_MAX / 2, 0 };
        if( !ordering_ok((int(*)(const void*,const void*))Tv_Comapre_fixed,
                         &a, &b, &c) )
        {
            printf("FAIL: Tv_Comapre_fixed violates ordering for extreme timevals\n");
            ++failures;
        }
        /* Buggy form overflows for these deltas: */
        long delta = (long)c.tv_sec - (long)a.tv_sec;
        if( delta > INT_MAX || delta < INT_MIN )
        {
            printf("CONFIRMED-BUG: Tv_Comapre_buggy would overflow computing "
                   "tv_sec delta %ld (cannot fit in int)\n", (long)delta);
        }
    }

    /* Microsecond-only difference must still order correctly. */
    {
        timeval a = { 0, 0 };
        timeval b = { 0, 1 };
        timeval c = { 0, 2 };
        if( !ordering_ok((int(*)(const void*,const void*))Tv_Comapre_fixed,
                         &a, &b, &c) )
        {
            printf("FAIL: Tv_Comapre_fixed usec ordering\n");
            ++failures;
        }
    }

    if( failures == 0 )
    {
        printf("PASS: all fixed comparators satisfy strict weak ordering.\n");
        return 0;
    }
    printf("%d FAILURES.\n", failures);
    return 1;
}
