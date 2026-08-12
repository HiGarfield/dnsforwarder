/* Regression tests for the Array helpers on grow-down (stack-like) arrays.
 *
 * 1) Array_Sort
 *    For a grow-down array, subscript 0 lives at the highest address (a->Data)
 *    and subscript (Used - 1) at the lowest.  Array_Sort must therefore pass
 *    qsort a base of (a->Data - (Used - 1) * DataLength).  The old code passed
 *    (a->Data - Used * DataLength), which reads one element below the allocated
 *    region (buffer underflow) and silently drops the element stored at a->Data,
 *    producing a corrupted sort.
 *
 * 2) Array_GetThis / Array_GetNext
 *    Both derived the subscript as (Position - a->Data) / DataLength, which is
 *    negative for a grow-down array.  Array_GetNext therefore stepped
 *    *backwards*: from subscript 0 it returned a->Data + DataLength, one element
 *    past the top of the array (out-of-bounds), and the "n >= Used" end check
 *    never triggered, so a walk over a grow-down array never terminated at the
 *    right element.
 *
 * Build (from the project root):
 *   cc -I. -o /tmp/t_array test/array/main.c array.c utils.c -lpthread
 */
#include <stdio.h>
#include <string.h>
#include "array.h"

static int IntCompare(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

static int TestSortGrowDown(void)
{
    enum { CAP = 8 };
    int buffer[CAP];
    Array a;
    int input[] = {5, 3, 8, 1, 9, 2};
    int n = (int)(sizeof(input) / sizeof(input[0]));
    int i;
    int expected[] = {9, 8, 5, 3, 2, 1};

    /* Grow-down array: TheFirstAddress is the highest element address. */
    if( Array_Init(&a, (int)sizeof(int), 0, TRUE, buffer + CAP - 1) != 0 )
    {
        fprintf(stderr, "Array_Init failed\n");
        return 1;
    }

    for( i = 0; i < n; ++i )
    {
        if( Array_PushBack(&a, &input[i], buffer) < 0 )
        {
            fprintf(stderr, "Array_PushBack failed at %d\n", i);
            return 1;
        }
    }

    Array_Sort(&a, IntCompare);

    /* After an ascending sort, subscript 0 (highest address) holds the largest
       value and the values must be non-increasing across subscripts. */
    for( i = 0; i < n - 1; ++i )
    {
        int cur = *(int *)Array_GetBySubscript(&a, i);
        int nxt = *(int *)Array_GetBySubscript(&a, i + 1);
        if( cur < nxt )
        {
            fprintf(stderr,
                    "Array_Sort grow-down FAILED: a[%d]=%d > a[%d]=%d (expected decreasing)\n",
                    i, cur, i + 1, nxt);
            return 1;
        }
    }

    for( i = 0; i < n; ++i )
    {
        int v = *(int *)Array_GetBySubscript(&a, i);
        if( v != expected[i] )
        {
            fprintf(stderr, "Array_Sort grow-down FAILED: a[%d]=%d expected %d\n",
                    i, v, expected[i]);
            return 1;
        }
    }

    printf("Array_Sort grow-down OK\n");
    return 0;
}

/* Walk the whole array with Array_GetNext and check every step lands on the
   element Array_GetBySubscript reports, then stops exactly at the end.
   Pointers are compared before being dereferenced so that a broken
   implementation cannot turn the test itself into an out-of-bounds read. */
static int TestWalk(Array *a, int Count, const char *What)
{
    void *pos = NULL;
    int i;

    for( i = 0; i < Count; ++i )
    {
        void *expected = Array_GetBySubscript(a, i);

        pos = Array_GetNext(a, pos);
        if( pos != expected )
        {
            fprintf(stderr,
                    "Array_GetNext %s FAILED: step %d returned %p, expected %p\n",
                    What, i, pos, expected);
            return 1;
        }

        if( Array_GetThis(a, pos) != expected )
        {
            fprintf(stderr,
                    "Array_GetThis %s FAILED: subscript %d not resolved to %p\n",
                    What, i, expected);
            return 1;
        }

        if( *(int *)pos != i )
        {
            fprintf(stderr, "Array_GetNext %s FAILED: a[%d]=%d expected %d\n",
                    What, i, *(int *)pos, i);
            return 1;
        }
    }

    pos = Array_GetNext(a, pos);
    if( pos != NULL )
    {
        fprintf(stderr,
                "Array_GetNext %s FAILED: walked past the last element (%p)\n",
                What, pos);
        return 1;
    }

    printf("Array_GetNext/Array_GetThis %s OK\n", What);
    return 0;
}

static int TestWalkGrowDown(void)
{
    enum { CAP = 8, N = 5 };
    int buffer[CAP];
    Array a;
    int i;

    if( Array_Init(&a, (int)sizeof(int), 0, TRUE, buffer + CAP - 1) != 0 )
    {
        fprintf(stderr, "Array_Init failed\n");
        return 1;
    }

    for( i = 0; i < N; ++i )
    {
        if( Array_PushBack(&a, &i, buffer) < 0 )
        {
            fprintf(stderr, "Array_PushBack failed at %d\n", i);
            return 1;
        }
    }

    return TestWalk(&a, N, "grow-down");
}

static int TestWalkGrowUp(void)
{
    enum { N = 5 };
    Array a;
    int i;
    int ret;

    if( Array_Init(&a, (int)sizeof(int), 2, FALSE, NULL) != 0 )
    {
        fprintf(stderr, "Array_Init failed\n");
        return 1;
    }

    for( i = 0; i < N; ++i )
    {
        if( Array_PushBack(&a, &i, NULL) < 0 )
        {
            fprintf(stderr, "Array_PushBack failed at %d\n", i);
            Array_Free(&a);
            return 1;
        }
    }

    ret = TestWalk(&a, N, "grow-up");
    Array_Free(&a);
    return ret;
}

int main(void)
{
    int Failures = 0;

    Failures += TestSortGrowDown();
    Failures += TestWalkGrowDown();
    Failures += TestWalkGrowUp();

    return Failures == 0 ? 0 : 1;
}
