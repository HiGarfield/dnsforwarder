/* Regression test for the shutdown race in dnscache.c's atexit cleanup.

   Bug: DNSCache_Cleanup() (registered with atexit inside DNSCache_Init,
   which is called late in the init sequence) destroyed CacheLock and freed
   the cache storage (MapStart) / unmapped the cache file.  atexit handlers
   run in LIFO order, so this handler fires BEFORE TimedTask_Cleanup()
   (registered earlier) and BEFORE Modules_Cleanup().  At that moment the
   TimedTask worker thread can still be executing
   DNSCacheTTLCountdown_Task(), and the module worker threads
   (UdpM_Works / TcpM_Works) can still be inside DNSCache_AddItemsToCache().
   Both take CacheLock and touch MapStart, so destroying the lock / freeing
   the mapping is locking-a-destroyed-rwlock and use-after-free during
   shutdown.

   Fix: the cleanup handler is a documented no-op; the OS reclaims the lock,
   mapping, file descriptor and heap blocks at process exit (same convention
   as dynamichosts.c, domainstatistic.c and timedtask.c).

   Part 1 (runtime): a worker thread keeps locking CacheLock and writing to
   MapStart; DNSCache_Cleanup() is called while the thread is live, and the
   thread then performs one more locked write.  With the old cleanup that
   final write dereferences freed/NULL memory (ASan: heap-use-after-free) or
   locks a destroyed rwlock; with the fix everything still works.

   Part 2 (structural, in run.sh): scan DNSCache_Cleanup for the absence of
   RWLock_Destroy / SafeFree(MapStart) / CacheTtlCrtl_Free / UNMAP_FILE and
   the presence of the shutdown-race rationale comment.

   The dnscache.c statics are exposed via the #define static trick, so the
   test drives the real cleanup handler directly.
*/
#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* dnscache.c's headers -- included BEFORE the static-export trick so their
   own static declarations are left untouched. */
#include "common.h"
#include "dnscache.h"
#include "cacheht.h"
#include "array.h"
#include "rwlock.h"
#include "utils.h"
#include "logs.h"
#include "readconfig.h"
#include "timedtask.h"
#include "cachettlcrtl.h"
#include "stringchunk.h"
#include "stringlist.h"

/* Stubs for ConfigGet* / TimedTask_Add / FileIsReadable / GetErrorMsg /
   Log_* live in run.sh-generated conf_stub.c and logs_stub.c (they are also
   needed by the linked dependency chain, e.g. utils.c), so this test defines
   none of them itself. */

/* ---- expose dnscache.c statics ---- */
#define static
#include "dnscache.c"
#undef static

/* ---- test harness ---- */

static int32_t         FakeCount = 0;
static volatile int32_t FakeEnd = 0;

static volatile int Stage = 0; /* 0 = starting, 1 = pre-cleanup done,
                                  2 = cleanup ran, 3 = post-cleanup done */

static void Msleep(int ms)
{
    struct timespec Ts;

    Ts.tv_sec = ms / 1000;
    Ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while( nanosleep(&Ts, &Ts) != 0 )
    {
    }
}

static void *CacheUser(void *Unused)
{
    int i;

    (void)Unused;

    /* Hammer the cache exactly like the TTL countdown task / a module
       worker: lock, touch MapStart, unlock. */
    for( i = 0; i < 50; ++i )
    {
        RWLock_WrLock(CacheLock);
        MapStart[0] = (char)i;
        RWLock_UnWLock(CacheLock);
    }
    Stage = 1;

    /* Wait for the main thread to run DNSCache_Cleanup(). */
    while( Stage != 2 )
    {
        Msleep(1);
    }

    /* One more locked access after cleanup: with the old cleanup this is a
       heap-use-after-free / NULL deref (SafeFree(MapStart) sets it NULL) or
       a lock on a destroyed rwlock; with the fix it is perfectly fine. */
    RWLock_WrLock(CacheLock);
    MapStart[0] = (char)0xAA;
    RWLock_UnWLock(CacheLock);
    Stage = 3;
    return NULL;
}

int main(void)
{
    pthread_t Tid;
    int i;

    printf("== dnscache shutdown cleanup race test ==\n\n");

    MemoryCache = TRUE;
    MapStart = (char *)malloc(4096);
    if( MapStart == NULL )
    {
        printf("FAIL: malloc\n");
        return 2;
    }
    memset(MapStart, 0, 4096);
    CacheInfo = (CacheHT *)MapStart;
    CacheFileHandle = INVALID_FILE;
    CacheMappingHandle = INVALID_MAP;
    TtlCtrl = NULL;
    CacheSize = 4096;
    CacheCount = &FakeCount;
    CacheEnd = &FakeEnd;
    RWLock_Init(CacheLock);

    if( pthread_create(&Tid, NULL, CacheUser, NULL) != 0 )
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
        printf("FAIL: worker thread never reached the pre-cleanup phase\n");
        return 1;
    }
    printf("PASS: worker thread hammering the cache before cleanup\n");

    /* Run the atexit body while the "background" thread is still live. */
    DNSCache_Cleanup();

    Stage = 2;
    for( i = 0; i < 5000 && Stage != 3; ++i )
    {
        Msleep(1);
    }
    if( Stage != 3 )
    {
        printf("FAIL: worker thread never finished the post-cleanup access\n");
        return 1;
    }
    pthread_join(Tid, NULL);

    /* Reaching this point proves there was no use-after-free (ASan builds). */
    if( MapStart[0] == (char)0xAA )
    {
        printf("PASS: cache storage is still accessible after cleanup\n");
    } else {
        printf("FAIL: cache storage content lost\n");
        return 1;
    }

    /* The lock must still be usable (a destroyed rwlock would corrupt it). */
    RWLock_WrLock(CacheLock);
    RWLock_UnWLock(CacheLock);
    printf("PASS: cache lock is still usable after cleanup\n");

    free(MapStart);

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
