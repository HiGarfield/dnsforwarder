/* Regression test for the shutdown race in filter.c's atexit cleanups.

   Bug: atexit LIFO order runs FilterType_Cleanup() / DisabledDomain_Cleanup()
   BEFORE Modules_Cleanup() stops the module worker threads.  Every request
   path calls IsDisabledType() (a lock-free read of the DisabledTypes BST)
   and IsDisabledDomain() (a read lock followed by a dereference of
   DisabledDomain).  The old cleanups did:
     - DisabledDomain_Cleanup: freed DisabledDomain WITHOUT taking the lock
       and WITHOUT NULLing the pointer, so a module worker that acquired the
       read lock right after could dereference a freed StringChunk
       (use-after-free at exit);
     - FilterType_Cleanup: freed DisabledTypes (read lock-free) and destroyed
       DisabledDomainLock while workers could still lock it (use-after-free +
       locking a destroyed rwlock).

   Fix: DisabledDomain_Cleanup takes the write lock, frees the container and
   NULLs the pointer (any reader that follows sees NULL and returns FALSE);
   FilterType_Cleanup deliberately leaves the lock and the BST to the OS --
   the same convention as dnscache.c / dynamichosts.c.

   Part 1 (runtime): a worker thread keeps running the IsDisabledDomain()
   access pattern (read lock + dereference) while DisabledDomain_Cleanup()
   is called; the worker then performs one more access.  With the old
   cleanup that final access dereferences freed memory (ASan:
   heap-use-after-free) or locks a destroyed rwlock; with the fix the worker
   sees NULL.

   Part 2 (structural, in run.sh): scan FilterType_Cleanup /
   DisabledDomain_Cleanup for the absence of RWLock_Destroy / lock-free
   frees / BST free and the presence of the shutdown-race rationale comment.
*/
#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* filter.c's headers -- included BEFORE the static-export trick so their
   own static declarations are left untouched. */
#include "common.h"
#include "filter.h"
#include "stringchunk.h"
#include "bst.h"
#include "logs.h"
#include "readline.h"
#include "domainstatistic.h"
#include "rwlock.h"
#include "readconfig.h"
#include "stringlist.h"
#include "mcontext.h"
#include "iheader.h"

/* Stubs for ConfigGet* / Log_* live in run.sh-generated conf_stub.c and
   logs_stub.c. */

/* ---- expose filter.c statics ---- */
#define static
#include "filter.c"
#undef static

/* ---- test harness ---- */

static volatile int Stage = 0; /* 0 = starting, 1 = pre-cleanup done,
                                  2 = cleanup ran, 3 = post-cleanup done */
static volatile int CleanupSawNull = 0;

static void Msleep(int ms)
{
    struct timespec Ts;

    Ts.tv_sec = ms / 1000;
    Ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while( nanosleep(&Ts, &Ts) != 0 )
    {
    }
}

static void *DomainUser(void *Unused)
{
    uint32_t Hash = 0;
    int i;

    (void)Unused;

    /* Hammer the exact access pattern of IsDisabledDomain(): read lock,
       dereference the container, unlock. */
    for( i = 0; i < 50; ++i )
    {
        RWLock_RdLock(DisabledDomainLock);
        if( DisabledDomain != NULL )
        {
            StringChunk_Domain_Match(DisabledDomain,
                                     "example.com",
                                     &Hash,
                                     NULL,
                                     NULL,
                                     NULL);
        }
        RWLock_UnRLock(DisabledDomainLock);
    }
    Stage = 1;

    /* Wait for the main thread to run DisabledDomain_Cleanup(). */
    while( Stage != 2 )
    {
        Msleep(1);
    }

    /* One more locked access after cleanup: with the old cleanup this
       dereferences a freed StringChunk (DisabledDomain was freed without
       the lock and without NULLing); with the fix it observes NULL. */
    RWLock_RdLock(DisabledDomainLock);
    if( DisabledDomain == NULL )
    {
        CleanupSawNull = 1;
    }
    RWLock_UnRLock(DisabledDomainLock);
    Stage = 3;
    return NULL;
}

int main(void)
{
    pthread_t Tid;
    int i;

    printf("== filter shutdown cleanup race test ==\n\n");

    RWLock_Init(DisabledDomainLock);

    /* Simulate a loaded DisabledDomain list. */
    if( InitChunk(&DisabledDomain) != 0 )
    {
        printf("FAIL: InitChunk\n");
        return 2;
    }
    if( StringChunk_Add_Domain(DisabledDomain, "example.com", NULL, 0) != 0 )
    {
        printf("FAIL: StringChunk_Add_Domain\n");
        return 2;
    }

    if( pthread_create(&Tid, NULL, DomainUser, NULL) != 0 )
    {
        printf("FAIL: pthread_create\n");
        return 2;
    }

    for( i = 0; i < 5000 && Stage != 1; ++i )
    {
        Msleep(1);
    }
    if( Stage != 1 )
    {
        printf("FAIL: worker never reached the pre-cleanup phase\n");
        return 1;
    }
    printf("PASS: worker hammering DisabledDomain before cleanup\n");

    /* Run the atexit body while the worker thread is still live. */
    DisabledDomain_Cleanup();

    Stage = 2;
    for( i = 0; i < 5000 && Stage != 3; ++i )
    {
        Msleep(1);
    }
    if( Stage != 3 )
    {
        printf("FAIL: worker never finished the post-cleanup access\n");
        return 1;
    }
    pthread_join(Tid, NULL);

    /* The worker must have observed the NULLed pointer. */
    if( !CleanupSawNull )
    {
        printf("FAIL: worker did not observe DisabledDomain == NULL after cleanup\n");
        return 1;
    }
    printf("PASS: worker observed DisabledDomain == NULL after cleanup\n");

    /* The lock must still be usable (a destroyed rwlock would corrupt it). */
    RWLock_RdLock(DisabledDomainLock);
    RWLock_UnRLock(DisabledDomainLock);
    printf("PASS: DisabledDomainLock is still usable after cleanup\n");

    printf("\nAll checks passed.\n");
    return 0;
}
#else /* _WIN32 */
int main(void)
{
    printf("POSIX-only test, skipped.\n");
    return 0;
}
#endif /* _WIN32 */
