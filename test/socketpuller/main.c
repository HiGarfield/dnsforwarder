/*
 * Regression test for the SocketPullers_* memory leak (socketpuller.c).
 *
 * SocketPullers_Init() allocates one contiguous array of SocketPuller objects
 * (Buffer) and a parallel array of pointers (Pullers). The Free / FreeWithoutClose
 * paths used to release only the pointer array, leaking the whole Buffer of
 * SocketPuller objects. This test allocates and frees several times so valgrind
 * can confirm the Buffer array is released.
 *
 * Build (from the repository root):
 *   cc -I. -g -o /tmp/t_socketpuller test/socketpuller/main.c socketpuller.c \
 *      socketpool.c -lpthread
 *
 * Run under valgrind:
 *   valgrind --leak-check=full --error-exitcode=9 /tmp/t_socketpuller
 */
#include <stdio.h>
#include <stdlib.h>

#include "../../socketpuller.h"

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
    int i;
    /* Repeat allocations so a leak is clearly visible under valgrind. */
    for( i = 0; i < 5; ++i )
    {
        SocketPuller **pp = SocketPullers_Init(8, 64);
        Check("SocketPullers_Init returns non-NULL", pp != NULL);
        if( pp == NULL )
        {
            continue;
        }
        SocketPullers_Free(pp);
    }

    for( i = 0; i < 5; ++i )
    {
        SocketPuller **pp = SocketPullers_Init(4, 32);
        if( pp == NULL )
        {
            continue;
        }
        SocketPullers_FreeWithoutClose(pp);
    }

    printf("\nsocketpuller: %d failures\n", Failures);
    return Failures == 0 ? 0 : 1;
}
