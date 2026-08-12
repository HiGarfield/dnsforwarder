/* Regression test for Array_Sort on grow-down (stack-like) arrays.
 *
 * For a grow-down array, subscript 0 lives at the highest address (a->Data)
 * and subscript (Used - 1) at the lowest.  Array_Sort must therefore pass
 * qsort a base of (a->Data - (Used - 1) * DataLength).  The old code passed
 * (a->Data - Used * DataLength), which reads one element below the allocated
 * region (buffer underflow) and silently drops the element stored at a->Data,
 * producing a corrupted sort.
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

int main(void)
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
