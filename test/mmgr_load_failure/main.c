/* Regression test for the mmgr.c partial group-file reload bug found in the
   Round-2 review:

   Bug: Modules_Load()'s failure path (the ModulesFree label) freed the new
   ModuleMap with Modules_Free() unconditionally.  When a group-file reload
   failed after one or more groups had already been created, those groups'
   worker threads (UdpM_Works / UdpM_Sweep_Thread / TcpM_Works) were still
   running while their module instances -- including the EFFECTIVE_LOCK every
   worker acquires on each loop iteration -- were freed underneath them: a
   use-after-free on the module lock / context / pullers.

   Fix: (1) the ModulesFree path now runs Modules_SafeCleanup(), which clears
   IsServer so every started worker exits, waits for the thread handles to be
   nulled, drains in-flight MMgr_Send readers via the ModulesLock barrier, and
   only then frees the map; (2) Modules_SafeCleanup() skips entries whose Send
   is NULL -- such entries exist only when a constructor failed, in which case
   no thread was ever started and the lock was never initialized, so touching
   them would be undefined behaviour.

   The static declarations of mmgr.c are exposed (via the #define static
   trick) so the test can drive Modules_Load() end-to-end and call
   Modules_SafeCleanup() directly.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

/* Headers used by mmgr.c -- included BEFORE the static-export trick so their
   own static declarations are left untouched. */
#include "common.h"
#include "mmgr.h"
#include "iheader.h"
#include "stringchunk.h"
#include "utils.h"
#include "filter.h"
#include "hosts.h"
#include "dnscache.h"
#include "logs.h"
#include "ipmisc.h"
#include "readline.h"
#include "rwlock.h"
#include "stringlist.h"

/* ---- stubs (real production symbol names, see test/mmgr_storeamodule) -- */

static int FakeSend(void *Module, const char *Buffer, int BufferLength)
{
    (void)Module; (void)Buffer; (void)BufferLength;
    return 0;
}

/* ---- simulation of a fully-started UDP module ---------------------------
   UdpM_Init succeeds: the lock is initialized, IsServer is on, a worker
   thread is spawned (mimicking UdpM_Works' IsServer polling), and Send is
   set -- exactly the state the production constructor leaves behind.  The
   worker nulls its handle before it stops touching module memory, so
   Modules_SafeCleanup can observe a clean exit. */

static UdpM *StartedModule = NULL;
static ThreadHandle WorkerHandle;
static volatile int WorkerExited = 0;

static int
#ifdef WIN32
WINAPI
#endif
UdpWorker(void *arg)
{
    UdpM *m = (UdpM *)arg;

    for(;;)
    {
        EFFECTIVE_LOCK_GET(m->Lock);
        BOOL KeepServing = m->IsServer;
        EFFECTIVE_LOCK_RELEASE(m->Lock);

        if( !KeepServing )
        {
            break;
        }

        usleep(1000);
    }

    /* Mimic UdpM_Cleanup: null the thread handle under the lock.  After the
       release the worker never touches module memory again -- Modules_SafeCleanup
       frees the instance as soon as it observes the nulled handle. */
    EFFECTIVE_LOCK_GET(m->Lock);
    m->WorkThread = NULL_THREAD;
    EFFECTIVE_LOCK_RELEASE(m->Lock);

    WorkerExited = 1;
    EXIT_THREAD(0);
}

int UdpM_Init(UdpM *m, const char *Services, BOOL Parallel)
{
    (void)Services; (void)Parallel;

    EFFECTIVE_LOCK_INIT(m->Lock);
    m->IsServer = 1;
    m->SweepThread = NULL_THREAD;
    m->Send = FakeSend;

    WorkerExited = 0;
#ifdef _WIN32
    CREATE_THREAD(UdpWorker, m, WorkerHandle);
    if( WorkerHandle == NULL_THREAD )
    {
        return -1;
    }
#else
    if( CREATE_THREAD(UdpWorker, m, WorkerHandle) != 0 )
    {
        return -1;
    }
#endif
    m->WorkThread = WorkerHandle;
    StartedModule = m;

    return 0;
}

int TcpM_Init(TcpM *m, const char *Services, BOOL Parallel, const char *Proxies)
{
    (void)m; (void)Services; (void)Parallel; (void)Proxies;
    return -1;                 /* simulate an init failure of a later group */
}

int Filter_Init(ConfigFileInfo *ConfigInfo) { (void)ConfigInfo; return 0; }
int Filter_Update(void) { return 0; }
BOOL Filter_Out(MsgContext *MsgCtx) { (void)MsgCtx; return FALSE; }

int Hosts_Init(ConfigFileInfo *ConfigInfo) { (void)ConfigInfo; return 0; }
int Hosts_Get(MsgContext *MsgCtx, int BufferLength)
{
    (void)MsgCtx; (void)BufferLength;
    return -1;                 /* no hosts hit: continue to module dispatch */
}

int DNSCache_Init(ConfigFileInfo *ConfigInfo) { (void)ConfigInfo; return 0; }
int DNSCache_FetchFromCache(MsgContext *MsgCtx, int BufferLength)
{
    (void)MsgCtx; (void)BufferLength;
    return -1;                 /* no cache hit: continue to module dispatch */
}

int IpMiscMapping_Init(ConfigFileInfo *ConfigInfo) { (void)ConfigInfo; return 0; }
void IpMiscMapping_Update(void) {}

int32_t ConfigGetInt32(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return 0;
}

BOOL ConfigGetBoolean(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return FALSE;
}

static StringList TheGroups;

StringList *ConfigGetStringList(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return &TheGroups;
}

BOOL MsgContext_IsFromTCP(const MsgContext *MsgCtx)
{
    (void)MsgCtx;
    return FALSE;
}

void MsgContext_ReleaseSocket(MsgContext *MsgCtx)
{
    (void)MsgCtx;
}

/* ---- expose the private declarations of mmgr.c ------------------------ */
#define static
#include "mmgr.c"
#undef static

static int Checks = 0;
static int Failures = 0;

static void expect(const char *what, int cond)
{
    ++Checks;
    if( cond )
    {
        printf("  [ ok ] %s\n", what);
    } else {
        ++Failures;
        printf("  [FAIL] %s\n", what);
    }
}

static int wait_for_worker_exit(int timeout_ms)
{
    int waited = 0;

    while( !WorkerExited && waited < timeout_ms )
    {
        usleep(1000);
        waited += 1;
    }

    return WorkerExited != 0;
}

int main(void)
{
    ConfigFileInfo ConfigInfo;
    int ret;

    /* Flush immediately so a CI timeout shows which assertion hung. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("== mmgr partial group-file reload failure tests ==\n\n");

    memset(&ConfigInfo, 0, sizeof(ConfigInfo));

    /* Group 1 (UDP) succeeds and starts a worker thread; group 2 (TCP) fails
       -- the exact shape of a partial reload. */
    StringList_Init(&TheGroups,
                    "UDP 1.2.3.4:53 example.com on "
                    "TCP 1.2.3.4:53 example.com on no",
                    " ");

    RWLock_Init(ModulesLock);

    /* ---- 1. end-to-end: a failed reload must stop the started module ---- */
    printf("Modules_Load with a succeeded UDP group followed by a failing TCP group\n");

    ret = Modules_Load(&ConfigInfo);
    expect("Modules_Load reports the TCP-group failure (-226)", ret == -226);

    /* Modules_SafeCleanup must have stopped the UDP worker instead of freeing
       its instance out from under the thread. */
    expect("the first (UDP) group was actually created", StartedModule != NULL);
    if( StartedModule != NULL )
    {
        expect("its worker thread stopped within the timeout (was not leaked "
               "onto freed memory)", wait_for_worker_exit(5000));
        JOIN_THREAD(WorkerHandle);
        expect("the worker exited cleanly", WorkerExited == 1);
    }

    /* ---- 2. Modules_SafeCleanup must skip failed (Send==NULL) entries ---- */
    printf("Modules_SafeCleanup on a half-built map with a failed module\n");
    {
        ModuleMap mm;
        ModuleInterface *M;

        memset(&mm, 0, sizeof(mm));
        InitChunk(&(mm.Distributor));

        mm.Modules = (StableBuffer *)malloc(sizeof(StableBuffer));
        expect("StableBuffer_Init succeeds", mm.Modules != NULL &&
               StableBuffer_Init(mm.Modules) == 0);

        mm.ModuleArray = (Array *)malloc(sizeof(Array));
        expect("Array_Init succeeds", mm.ModuleArray != NULL &&
               Array_Init(mm.ModuleArray, sizeof(ModuleInterface *), 0, FALSE, NULL) == 0);

        if( mm.Distributor == NULL || mm.Modules == NULL || mm.ModuleArray == NULL )
        {
            printf("  setup failed\n");
            return 1;
        }

        /* A "failed constructor" entry exactly as Udp_Init_Core would leave
           one: ModuleName set, Send NULL, and a lock region that was never
           initialized (filled with a poison pattern).  Before the fix
           Modules_SafeCleanup would spin on that garbage lock (undefined
           behaviour / hang); with the fix it must skip the entry and still
           free the map cleanly. */
        M = mm.Modules->Add(mm.Modules, NULL, sizeof(ModuleInterface), TRUE);
        expect("module slot allocated", M != NULL);
        if( M != NULL )
        {
            memset(M, 0xCD, sizeof(ModuleInterface));   /* poison everything */
            M->ModuleName = "UDP";
            M->Send = NULL;                            /* constructor failed */
            M->ModuleUnion.Udp.IsServer = 1;
            M->ModuleUnion.Udp.WorkThread = NULL_THREAD;
            M->ModuleUnion.Udp.SweepThread = NULL_THREAD;
            /* M->ModuleUnion.Udp.Lock intentionally left poisoned */

            ret = Modules_SafeCleanup(&mm);
            expect("Modules_SafeCleanup skips the Send==NULL entry and "
                   "returns 0 (never touches the uninitialized lock)",
                   ret == 0);
        }
    }

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
