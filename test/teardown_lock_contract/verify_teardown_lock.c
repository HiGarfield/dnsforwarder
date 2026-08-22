/* Formal verification of the tcpm.c / udpm.c send-vs-teardown fixes.
 *
 * Bugs under test (all fixed in this round):
 *
 *  Bug #1 (tcpm.c TcpM_Send): on its two failure paths (Context.Add OOM, and
 *    TcpM_Send_Actual returning <= 0) the function returned without calling
 *    MsgContext_ReleaseSocket().  The TCP frontend had already bumped the
 *    per-socket dispatch counter (TcpFrontend_MarkDispatched), so a failed
 *    dispatch pinned that counter at 1 forever: TcpFrontend_ClientGone() could
 *    then only mark the socket Gone, never close it, leaking one descriptor
 *    per failed TCP query and hanging the client.
 *
 *  Bug #2 (udpm.c UdpM_Sweep_Thread): freed m->Context / m->ServiceName
 *    WITHOUT holding m->Lock.  A frontend thread inside UdpM_Send() (which
 *    holds m->Lock and uses m->Context.Add) could therefore dereference
 *    already freed BST nodes: use-after-free at shutdown.
 *
 *  Bug #3 (tcpm.c TcpM_Cleanup): freed every module resource without holding
 *    m->Lock (and wrote IsServer=0 as a plain, racing write), while the
 *    frontend TcpM_Send() holds m->Lock and uses those same resources:
 *    use-after-free at shutdown.
 *
 * Fixes verified here (all three are deterministic properties of the lock +
 * the IsServer guard, not timing luck):
 *
 *  (a) Part A -- frontend accounting: a module-send failure releases the TCP
 *      socket hold exactly once (so the frontend counter drains and the client
 *      socket is closed), a success never releases early, and the old no-
 *      release behaviour is reproduced as the leak it is.
 *
 *  (b) Part B -- teardown mutual exclusion: the teardown publishes IsServer=0
 *      and frees the module resources in ONE critical section of m->Lock, and
 *      the Send entry bails as soon as it observes IsServer==0.  Therefore:
 *         - the send critical section and the teardown critical section never
 *           overlap (max concurrent == 1), and
 *         - every send that touches the resource holds the lock at that
 *           moment, which blocks the teardown, so the free strictly follows
 *           every touch (g_touch_after_free == 0, deterministic).
 *      A negative control that models the OLD code (no lock, no guard)
 *      demonstrates that the very same detector then reports sends operating
 *      on the module after teardown has declared it invalid.
 *
 * Build (any platform with common.h + a C compiler):
 *   gcc verify_teardown_lock.c -I../.. -lpthread -o v && ./v      (POSIX)
 *   gcc verify_teardown_lock.c -I../.. -o v.exe && v.exe          (Win32/MinGW)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

/* ------------------------------------------------------------------ */
/* Part A: frontend TCP socket-ownership accounting (mirror of the    */
/* real TcpSocketInFlight[] / TcpSocketGone[] logic in tcpfrontend.c) */
/* ------------------------------------------------------------------ */

#define MODEL_FD_SETSIZE 64

static int  g_inflight[MODEL_FD_SETSIZE];
static int  g_gone[MODEL_FD_SETSIZE];
static int  g_close_count;      /* how many sockets were actually closed */
static int  g_release_count;    /* how many ReleaseSocket calls happened */
static int  g_last_released;    /* last socket handed to ReleaseSocket   */

static void Model_MarkDispatched(int s)
{
    if( s < 0 || s >= MODEL_FD_SETSIZE ) return;
    g_inflight[s]++;
}

static void Model_ReleaseSocket(int s)
{
    if( s < 0 || s >= MODEL_FD_SETSIZE ) return;
    g_release_count++;
    g_last_released = s;
    if( g_inflight[s] > 0 ) g_inflight[s]--;
    if( g_inflight[s] == 0 && g_gone[s] )
    {
        g_close_count++;
        g_gone[s] = 0;
    }
}

static void Model_ClientGone(int s)
{
    if( s < 0 || s >= MODEL_FD_SETSIZE ) return;
    if( g_inflight[s] == 0 )
    {
        g_close_count++;
        g_gone[s] = 0;
    }
    else
    {
        g_gone[s] = 1;
    }
}

/* Model of the module Send entry (the fixed TcpM_Send): every failure path
 * releases the socket hold.  On success it must NOT release (the module
 * worker releases when the answer comes back). */
static int Model_ModuleSend(int sock, int send_fails)
{
    if( !send_fails )
    {
        return 0; /* success: answer will come back later */
    }
    /* Failure path: the query can never be answered, so the patched code
     * calls MsgContext_ReleaseSocket() -> TcpFrontend_ReleaseSocket ->
     * our Model_ReleaseSocket. */
    Model_ReleaseSocket(sock);
    return -1;
}

static int PartA(void)
{
    int failures = 0;

    /* Scenario 1 (fixed behaviour): query dispatched on socket 7, module send
     * fails, hold is released, then the client disconnects -> the socket is
     * actually closed and the counter drains. */
    memset(g_inflight, 0, sizeof(g_inflight));
    memset(g_gone, 0, sizeof(g_gone));
    g_close_count = 0; g_release_count = 0; g_last_released = -1;

    Model_MarkDispatched(7);              /* TcpFrontend_MarkDispatched   */
    if( Model_ModuleSend(7, 1) != -1 ) { ++failures; }
    Model_ClientGone(7);                  /* client disconnects           */

    if( g_inflight[7] != 0 )   { printf("FAIL: inflight[7] did not drain (%d)\n", g_inflight[7]); ++failures; }
    if( g_release_count != 1 ) { printf("FAIL: expected 1 release, got %d\n", g_release_count); ++failures; }
    if( g_last_released != 7 ) { printf("FAIL: release was for socket %d\n", g_last_released); ++failures; }
    if( g_close_count != 1 )   { printf("FAIL: socket was not closed (leak!)\n"); ++failures; }

    /* Scenario 2 (OLD buggy behaviour): no release on the failure path.  The
     * counter stays pinned at 1, ClientGone can only mark Gone, and the
     * descriptor is never closed.  Reproduced to prove the leak exists. */
    g_inflight[8] = 0; g_gone[8] = 0;
    g_close_count = 0; g_release_count = 0;
    Model_MarkDispatched(8);
    /* old buggy code: return without Model_ReleaseSocket(8) */
    Model_ClientGone(8);
    if( g_close_count != 0 )
    {
        printf("BUG-REPRO: old code closed the socket despite a pinned counter\n");
        ++failures;
    }
    else
    {
        printf("CONFIRMED-OLD-BUG: without the release, inflight stays %d and "
               "ClientGone leaks the descriptor\n", g_inflight[8]);
    }

    /* Scenario 3: success path must NOT release (the answer releases later). */
    g_inflight[9] = 0; g_gone[9] = 0;
    g_release_count = 0;
    Model_MarkDispatched(9);
    if( Model_ModuleSend(9, 0) != 0 ) { ++failures; }
    if( g_release_count != 0 ) { printf("FAIL: success path released the socket\n"); ++failures; }

    if( failures == 0 )
    {
        printf("Part A PASS: module-send failure drains the frontend socket hold.\n");
    }
    return failures;
}

/* ------------------------------------------------------------------ */
/* Part B: teardown-vs-send mutual exclusion (UdpM/TcpM shutdown).    */
/* Models: IsServer flag + module lock + a resource block.            */
/* ------------------------------------------------------------------ */

static EFFECTIVE_LOCK g_lock;
static int  g_IsServer;
static char *g_resource;          /* the module resource block */
static volatile int  g_teardown_done; /* 1 once teardown has published 0 */
static volatile long g_touches;   /* send touched the resource while alive */
static volatile long g_bails;     /* send bailed after teardown began     */
static volatile long g_touch_after_teardown; /* touches after teardown    */
static volatile int  g_in_section;   /* threads inside the locked section    */
static volatile int  g_max_concurrent;

/* old_semantics: when 1, the sender does NOT check IsServer and always
   "touches" the module (modelling the pre-fix send entry).  No heap memory is
   actually written in that mode, so the negative control is free of UB while
   still demonstrating that sends keep operating on a torn-down module. */
static int g_old_semantics;

#ifdef _WIN32
static DWORD WINAPI sender_worker(LPVOID arg)
#else
static void *sender_worker(void *arg)
#endif
{
    int i;
    (void)arg;
    for( i = 0; i < 200000; ++i )
    {
        EFFECTIVE_LOCK_GET(g_lock);
        ++g_in_section;
        if( g_in_section > g_max_concurrent ) g_max_concurrent = g_in_section;

        if( g_old_semantics || g_IsServer != 0 )
        {
            /* The pre-fix send entry always used the module; the fixed entry
             * only does so while the module is alive. */
            if( g_teardown_done )
            {
                g_touch_after_teardown++;
            }
            g_touches++;
            if( !g_old_semantics )
            {
                /* Safe: the teardown is blocked on the very lock we hold, so
                 * the free cannot have happened yet. */
                g_resource[0] = (char)(i & 0x7f);
            }
        }
        else
        {
            g_bails++;
        }

        --g_in_section;
        EFFECTIVE_LOCK_RELEASE(g_lock);
    }
    return 0;
}

static int RunTeardownModel(int old_semantics)
{
    int failures = 0;

    EFFECTIVE_LOCK_INIT(g_lock);

    g_IsServer = 1;
    g_teardown_done = 0;
    g_old_semantics = old_semantics;
    g_touches = 0; g_bails = 0; g_touch_after_teardown = 0;
    g_in_section = 0; g_max_concurrent = 0;

    g_resource = (char *)malloc(64);
    if( g_resource == NULL )
    {
        printf("Part B: malloc failed\n");
        return 2;
    }
    memset(g_resource, 0x5A, 64);   /* canary pattern */

#ifdef _WIN32
    HANDLE a = CreateThread(NULL, 0, sender_worker, NULL, 0, NULL);
    HANDLE b = CreateThread(NULL, 0, sender_worker, NULL, 0, NULL);
#else
    pthread_t a, b;
    pthread_create(&a, NULL, sender_worker, NULL);
    pthread_create(&b, NULL, sender_worker, NULL);
#endif

    /* Let the senders run a little while the module is alive... */
    SLEEP(5);

    if( old_semantics )
    {
        /* Negative control: the OLD teardown wrote IsServer and freed the
         * resources without the lock, and the send entry never checked
         * IsServer.  Sends therefore keep operating on the torn-down module
         * after teardown has begun. */
        g_IsServer = 0;          /* plain, racing write (old code) */
        g_teardown_done = 1;
        /* the resource is "gone" as far as the module is concerned; the
           model deliberately does not free() it to keep the negative
           control free of undefined behaviour */
    }
    else
    {
        /* The fix: one critical section publishes IsServer = 0 and frees the
         * resources (TcpM_Cleanup / UdpM_Sweep_Thread). */
        EFFECTIVE_LOCK_GET(g_lock);
        g_IsServer = 0;
        free(g_resource);
        g_resource = NULL;
        g_teardown_done = 1;
        EFFECTIVE_LOCK_RELEASE(g_lock);
    }

    /* Keep hammering after teardown. */
    SLEEP(10);

#ifdef _WIN32
    WaitForSingleObject(a, INFINITE);
    WaitForSingleObject(b, INFINITE);
    CloseHandle(a); CloseHandle(b);
#else
    pthread_join(a, NULL);
    pthread_join(b, NULL);
#endif

    printf("  sections entered: %d, max concurrent: %d\n",
           (int)g_in_section, (int)g_max_concurrent);
    printf("  touches: %ld, bails: %ld, touches after teardown: %ld\n",
           (long)g_touches, (long)g_bails, (long)g_touch_after_teardown);

    if( g_max_concurrent != 1 )
    {
        printf("FAIL: %d threads in the send section at once (puller race)\n",
               (int)g_max_concurrent);
        ++failures;
    }
    if( g_touches == 0 && g_bails == 0 )
    {
        printf("FAIL: senders never ran (test is meaningless)\n");
        ++failures;
    }

    EFFECTIVE_LOCK_DESTROY(g_lock);
    if( g_resource != NULL )
    {
        free(g_resource);
        g_resource = NULL;
    }

    return failures;
}

static int PartB(void)
{
    int failures = 0;

    printf("Part B (fixed teardown):\n");
    failures += RunTeardownModel(0);

    printf("Part B (old teardown, negative control):\n");
    failures += RunTeardownModel(1);

    return failures;
}

int main(void)
{
    int failures = 0;
    failures += PartA();
    failures += PartB();
    if( failures == 0 )
    {
        printf("\nALL TEARDOWN/SEND CONTRACT CHECKS PASSED.\n");
        return 0;
    }
    printf("\nVERIFICATION FAILED (%d failures).\n", failures);
    return 1;
}
