#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "array.h"
#include "utils.h"

#define CHECK(cond) do { if( !(cond) ) { fprintf(stderr, "FAIL: %s (line %d)\n", #cond, __LINE__); return 1; } } while(0)

/* Regression test for the integer-overflow fix in Array_Init / Array_PushBack /
   Array_SetToSubscript. The capacity size used to be `int * int` widened to
   size_t, so a product above INT_MAX wrapped to a tiny value, handing
   malloc/realloc a far-too-small buffer and overflowing the heap on the
   following memcpy/memset. */

static int compare_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(void)
{
    int      i;
    int      v;
    Array    a;

    /* --- normal grow-up usage, including reallocation + sort + walk --- */
    CHECK(Array_Init(&a, sizeof(int), 4, FALSE, NULL) == 0);

    for( i = 0; i < 1000; ++i )
    {
        v = 1000 - i;                      /* reverse order on purpose */
        CHECK(Array_PushBack(&a, &v, NULL) == i);
    }

    CHECK(Array_GetUsed(&a) == 1000);

    Array_Sort(&a, compare_int);

    for( i = 0; i < 1000; ++i )
    {
        int *p = (int *)Array_GetBySubscript(&a, i);
        CHECK(p != NULL);
        CHECK(*p == i + 1);                /* 1..1000 ascending after sort */
    }

    /* grow-down array: basic push + read back */
    {
        int         buf[64];
        Array       g;
        int         j;
        int         value = 7;

        memset(buf, 0, sizeof(buf));
        CHECK(Array_Init(&g, sizeof(int), 0, TRUE, buf + 63) == 0);
        for( j = 0; j < 10; ++j )
        {
            value = j * 3;
            CHECK(Array_PushBack(&g, &value, buf) == j);
        }
        for( j = 0; j < 10; ++j )
        {
            int *p = (int *)Array_GetBySubscript(&g, j);
            CHECK(p != NULL);
            CHECK(*p == j * 3);
        }
        Array_Free(&g);
    }

    Array_Free(&a);

    /* --- overflow guard: a huge subscript must fail gracefully (NULL),
           not hand malloc/realloc a tiny buffer and corrupt the heap. --- */
    {
        Array   o;
        int     dummy = 0;

        CHECK(Array_Init(&o, sizeof(int), 1, FALSE, NULL) == 0);

        /* Product (0x40000000 + 1) * sizeof(int) overflows a 32-bit int but
           must be rejected instead of producing a tiny allocation. */
        CHECK(Array_SetToSubscript(&o, 0x40000000, &dummy) == NULL);

        /* (0x3FFFFFFF + 1) * 4 == 0x100000000 wraps to 0, so the buggy code
           would hand realloc() a zero-sized buffer and then write at a negative
           offset (heap underflow). Must be rejected. */
        CHECK(Array_SetToSubscript(&o, 0x3FFFFFFF, &dummy) == NULL);

        /* Negative subscripts must be rejected instead of writing before the
           buffer. */
        CHECK(Array_SetToSubscript(&o, -1, &dummy) == NULL);

        Array_Free(&o);
    }

    printf("array_overflow: all tests passed\n");
    return 0;
}
