/* Regression test for the mmgr.c uninitialized-module bug found in the
   Round-3 review:

   Bug: StoreAModule() allocated a ModuleInterface through StableBuffer_Add
   (which does NOT zero the new slot) and pushed it into ModuleArray.  The
   constructor then called UdpM_Init / TcpM_Init; when that failed the module
   was left in ModuleArray with a GARBAGE Send pointer, and MMgr_Send()'s
   fallback routing (module selected by query-id modulo) would call through
   it -- a crash.

   Fix: StoreAModule() defaults Send to NULL and MMgr_Send() skips modules
   whose Send is NULL (releasing the client socket and failing the query).

   The static declarations of mmgr.c are exposed (via the #define static
   trick) so the test can drive Udp_Init_Core / MMgr_Send directly and inspect
   CurModuleMap / ModuleArray state.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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

/* ---- stubs --------------------------------------------------------------
   These use the real production symbol names (deliberately NOT static,
   matching the declarations in the headers) because mmgr.c is compiled into
   this test binary. */

static int ReleaseCount = 0;

int UdpM_Init(UdpM *m, const char *Services, BOOL Parallel)
{
    (void)m; (void)Services; (void)Parallel;
    return -1;                 /* simulate an init failure */
}

int TcpM_Init(TcpM *m, const char *Services, BOOL Parallel, const char *Proxies)
{
    (void)m; (void)Services; (void)Parallel; (void)Proxies;
    return -1;                 /* simulate an init failure */
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

StringList *ConfigGetStringList(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return NULL;
}

BOOL MsgContext_IsFromTCP(const MsgContext *MsgCtx)
{
    (void)MsgCtx;
    return FALSE;
}

void MsgContext_ReleaseSocket(MsgContext *MsgCtx)
{
    (void)MsgCtx;
    ++ReleaseCount;
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

int main(void)
{
    ModuleMap mm;
    StringList dl;
    ModuleInterface *m0;
    char MsgBuf[sizeof(IHeader) + 8];
    int ret;

    printf("== mmgr StoreAModule / Send==NULL regression tests ==\n\n");

    /* MMgr_Send() takes ModulesLock; in production MMgr_Init() initializes it.
       Without this the read lock hits an uninitialized CRITICAL_SECTION on
       Win32 (crash) -- a zeroed pthread rwlock merely happens to work on
       Linux. */
    RWLock_Init(ModulesLock);

    memset(&mm, 0, sizeof(mm));

    expect("InitChunk allocates the Distributor",
           InitChunk(&(mm.Distributor)) == 0);

    mm.Modules = (StableBuffer *)malloc(sizeof(StableBuffer));
    expect("StableBuffer_Init succeeds", mm.Modules != NULL &&
           StableBuffer_Init(mm.Modules) == 0);

    mm.ModuleArray = (Array *)malloc(sizeof(Array));
    expect("Array_Init succeeds", mm.ModuleArray != NULL &&
           Array_Init(mm.ModuleArray, sizeof(ModuleInterface *), 0, FALSE, NULL) == 0);

    if( mm.Distributor == NULL || mm.Modules == NULL || mm.ModuleArray == NULL )
    {
        printf("setup failed\n");
        return 1;
    }

    StringList_Init(&dl, "example.com", ",");

    /* ---- 1. A failed module constructor must leave Send == NULL ------- */
    printf("Udp_Init_Core with a failing UdpM_Init\n");
    ret = Udp_Init_Core(&mm, "1.2.3.4:53", &dl, "on");
    expect("Udp_Init_Core reports the init failure (-128)", ret == -128);

    expect("the failed module is still registered in ModuleArray",
           Array_GetUsed(mm.ModuleArray) == 1);

    m0 = *(ModuleInterface **)Array_GetBySubscript(mm.ModuleArray, 0);
    expect("the module pointer is non-NULL", m0 != NULL);
    if( m0 != NULL )
    {
        expect("its name is \"UDP\"", strcmp(m0->ModuleName, "UDP") == 0);
        expect("its Send pointer is NULL (was garbage)", m0->Send == NULL);

        /* BUG FIX (Round-3): the lifecycle lock must be initialized even when
           the constructor fails, because Modules_SafeCleanup still matches this
           module by its "UDP" name and takes the lock.  An uninitialized lock
           is undefined behaviour (pthread_spin_lock on a garbage spinlock), so
           we exercise the exact GET/RELEASE that Modules_SafeCleanup performs.
           Under ASan/TSan this traps on the previously-uninitialized lock. */
        EFFECTIVE_LOCK_GET(m0->ModuleUnion.Udp.Lock);
        EFFECTIVE_LOCK_RELEASE(m0->ModuleUnion.Udp.Lock);
        expect("failed-UDP module lock is safely lockable", 1);
    }

    /* ---- 2. MMgr_Send must not call a NULL Send ----------------------- */
    printf("MMgr_Send with a Send==NULL module\n");
    CurModuleMap = &mm;

    memset(MsgBuf, 0, sizeof(MsgBuf));
    ReleaseCount = 0;

    ret = MMgr_Send(MsgBuf, sizeof(MsgBuf));
    expect("MMgr_Send fails the query instead of crashing (-190)", ret == -190);
    expect("the client socket is released once", ReleaseCount == 1);

    /* ---- 3. A Tcp_Init failure behaves identically -------------------- */
    printf("Tcp_Init with a failing TcpM_Init\n");
    {
        StringList sl;
        StringListIterator it;

        StringList_Init(&sl, "1.2.3.4:53 example.com on no", " ");
        StringListIterator_Init(&it, &sl);

        ret = Tcp_Init(&mm, &it);
        expect("Tcp_Init reports the init failure", ret != 0);

        expect("both failed modules are now in ModuleArray",
               Array_GetUsed(mm.ModuleArray) == 2);
        m0 = *(ModuleInterface **)Array_GetBySubscript(mm.ModuleArray, 1);
        expect("the TCP module Send is NULL too",
               m0 != NULL && m0->Send == NULL);

        /* Same lock-initialization guarantee for the failed TCP module. */
        if( m0 != NULL )
        {
            EFFECTIVE_LOCK_GET(m0->ModuleUnion.Tcp.Lock);
            EFFECTIVE_LOCK_RELEASE(m0->ModuleUnion.Tcp.Lock);
            expect("failed-TCP module lock is safely lockable", 1);
        }
    }

    /* ---- 4. MMgr_Send still skips NULL-Send modules with both broken ---- */
    printf("MMgr_Send with two Send==NULL modules\n");
    {
        memset(MsgBuf, 0, sizeof(MsgBuf));
        ReleaseCount = 0;

        ret = MMgr_Send(MsgBuf, sizeof(MsgBuf));
        expect("MMgr_Send still fails cleanly (-190)", ret == -190);
        expect("the client socket is released once", ReleaseCount == 1);
    }

    /* cleanup: same order as Modules_Free() */
    mm.Modules->Free(mm.Modules);
    free(mm.Modules);
    Array_Free(mm.ModuleArray);
    free(mm.ModuleArray);
    StringChunk_Free(mm.Distributor, TRUE);
    free(mm.Distributor);

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
