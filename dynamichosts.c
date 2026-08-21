#include <string.h>
#include "dynamichosts.h"
#include "common.h"
#include "downloader.h"
#include "readline.h"
#include "goodiplist.h"
#include "timedtask.h"
#include "rwlock.h"
#include "logs.h"
#include "filter.h"
#include "ipmisc.h"
#include "mmgr.h"

#define SIZE_OF_PATH_BUFFER 384

static const char   *File = NULL;
static RWLock       HostsLock = NULL_RWLOCK;
static volatile HostsContainer  *MainDynamicContainer = NULL;

/* Set by DynamicHosts_Cleanup() (atexit) so the detached reload thread
   (GetHostsFromInternet_Thread) stops touching HostsLock / the container
   while cleanup is tearing them down. */
static volatile BOOL    ToExit = FALSE;

/* TRUE while a reload thread is running.  It is set BEFORE the thread
   touches any shared resource and cleared on every exit path, so
   DynamicHosts_Cleanup() can wait on it: once it reads FALSE it knows no
   reload thread can still be inside Filter_Update() / IpMiscMapping_Update()
   / Modules_Update() against modules whose locks and lists have already been
   torn down by other atexit handlers.  A thread spawned after the wait has
   started will see ToExit first and return without touching anything. */
static volatile BOOL    Reloading = FALSE;

/* Arguments for updating  */
static int          HostsRetryInterval;
static char         Script[SIZE_OF_PATH_BUFFER] = "";
static char         **HostsURLs = NULL; /* malloced */

static void DynamicHosts_ContainerCleanup(HostsContainer *DynamicContainer)
{
    if( DynamicContainer != NULL )
    {
        DynamicContainer->Free(DynamicContainer);
        SafeFree(DynamicContainer);
    }
}

static void DynamicHosts_Cleanup(void)
{
    ToExit = TRUE;

    /* Wait until no reload thread is inside the download/update path.  A
       reload thread that already passed its ToExit checks could otherwise
       keep running Filter_Update() / IpMiscMapping_Update() / Modules_Update()
       while their locks and lists are torn down by other atexit handlers
       (use-after-free / locking destroyed locks during shutdown).  The
       Reloading flag is set by the thread before it touches any shared
       resource and cleared on every exit path, so once it reads FALSE no
       such thread can still be active; any thread spawned later sees ToExit
       first and returns immediately. */
    while( Reloading )
    {
        SLEEP(10);
    }

    /* Do NOT destroy HostsLock here. The detached reload thread
       (GetHostsFromInternet_Thread) may still be running when atexit fires;
       it checks ToExit before use but there is a narrow window between that
       check and its RWLock_WrLock inside DynamicHosts_Load(). Destroying the
       lock here would let the thread lock a freed lock (undefined behaviour).
       The OS reclaims the lock's resources when the process exits, so simply
       leaving it untouched is both safe and sufficient. */
    /* Free the container under the write lock. The read path
       (DynamicHosts_Try/GetCName/TypeExisting) takes RWLock_RdLock(HostsLock)
       before dereferencing MainDynamicContainer, so doing the free without the
       lock would let a reader still inside its critical section dereference a
       freed container (use-after-free) if atexit fires while a request thread
       is mid-lookup. HostsLock itself is intentionally left intact (see above). */
    RWLock_WrLock(HostsLock);
    DynamicHosts_ContainerCleanup((HostsContainer *)MainDynamicContainer);
    MainDynamicContainer = NULL;
    RWLock_UnWLock(HostsLock);

    /* Intentionally do NOT free HostsURLs here.  The detached reload thread
       (GetHostsFromInternet_Thread) reads HostsURLs at the start of every run
       and passes it to GetFromInternet_MultiFiles(), which iterates it for the
       whole duration of a download.  ToExit is only checked before and after
       that call, so freeing HostsURLs while a download is in progress would
       hand the thread a dangling pointer (use-after-free).  Like HostsLock
       above, the memory is reclaimed by the OS when the process exits, so
       leaving it untouched is both safe and sufficient. */
}

static int DynamicHosts_Load(void)
{
    FILE            *fp;
    char            Buffer[320];
    ReadLineStatus  Status;

    HostsContainer *TempContainer;

    fp = fopen(File, "r");
    if( fp == NULL )
    {
        goto EXIT_1;
    }

    TempContainer = (HostsContainer *)SafeMalloc(sizeof(HostsContainer));
    if( TempContainer == NULL )
    {
        goto EXIT_2;
    }

    if( HostsContainer_Init(TempContainer) != 0 )
    {
        SafeFree(TempContainer);
        goto EXIT_2;
    }

    while( TRUE )
    {
        Status = ReadLine(fp, Buffer, sizeof(Buffer));
        if( Status == READ_FAILED_OR_END )
        {
            break;
        }

        if( Status == READ_TRUNCATED )
        {
            ERRORMSG("Hosts is too long : %s\n", Buffer);
            ReadLine_GoToNextLine(fp);
            continue;
        }

        TempContainer->Load(TempContainer, Buffer);
    }

    fclose(fp);

    RWLock_WrLock(HostsLock);

    DynamicHosts_ContainerCleanup((HostsContainer *)MainDynamicContainer);
    MainDynamicContainer = TempContainer;

    RWLock_UnWLock(HostsLock);

    INFO("Loading hosts completed.\n");

    return 0;

EXIT_2:
    fclose(fp);
EXIT_1:
    INFO("Loading hosts failed.\n");
    return -1;
}

static void GetHostsFromInternet_Failed(int ErrorCode, const char *URL, const char *File1)
{
    ERRORMSG("Getting Hosts %s failed. Waiting %d second(s) to try again.\n",
             URL,
             HostsRetryInterval
             );
}

static void GetHostsFromInternet_Succeed(const char *URL, const char *File1)
{
    INFO("Hosts %s saved.\n", URL);
}

static void GetHostsFromInternet_Thread(void *Unused1, void *Unused2)
{
#if !defined(TEST_RELOADING)
    int         DownloadState;
#endif /* !defined(TEST_RELOADING) */

    /* Announce the reload before touching any shared resource, so
       DynamicHosts_Cleanup()'s wait loop cannot miss this thread. */
    Reloading = TRUE;

#if !defined(TEST_RELOADING)
    /* Bail out if atexit cleanup is tearing down HostsLock / the container. */
    if( ToExit )
    {
        Reloading = FALSE;
        return;
    }

    if( HostsURLs == NULL || HostsURLs[0] == NULL )
    {
        ERRORMSG("Hosts URLs list is not available.\n");
        Reloading = FALSE;
        return;
    }

    if( HostsURLs[1] == NULL )
    {
        INFO("Getting hosts from %s ...\n", HostsURLs[0]);
    } else {
        INFO("Getting hosts from various places ...\n");
    }

    DownloadState = GetFromInternet_MultiFiles((const char **)HostsURLs,
                                               File,
                                               HostsRetryInterval,
                                               -1,
                                               GetHostsFromInternet_Failed,
                                               GetHostsFromInternet_Succeed
                                               );

    if( DownloadState == 0 )
    {
        INFO("Hosts saved at %s.\n", File);

        if( *Script != 0 )
        {
            INFO("Running hosts script \"%s\"...\n", Script);

            if( Execute(Script) < 0 )
            {
                ERRORMSG("Hosts script running failed.\n");
            }
        }
#endif

        /* Re-check here: atexit may have set ToExit (and begun tearing down
           the container) while we were blocked inside the download above.
           Bailing out avoids loading into a container that cleanup is freeing
           and avoids touching HostsLock during shutdown. */
        if( ToExit )
        {
            Reloading = FALSE;
            return;
        }

        DynamicHosts_Load();
        Filter_Update();
        IpMiscMapping_Update();
        Modules_Update();

        INFO("Reloading Modules completed.\n");

        Reloading = FALSE;
#if !defined(TEST_RELOADING)
    } else {
        ERRORMSG("Getting hosts file(s) failed.\n");
    }
#endif
}

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo)
{
    StringList  *Hosts;
    int          UpdateInterval;
    const char  *RawScript;

    Hosts = ConfigGetStringList(ConfigInfo, "Hosts");
    if( Hosts == NULL )
    {
        return -151;
    }

    Hosts->TrimAll(Hosts, "\"\t ");

    HostsURLs = Hosts->ToCharPtrArray(Hosts);
    if( HostsURLs == NULL )
    {
        ERRORMSG("Failed to build Hosts URLs list.\n");
        return -152;
    }

    UpdateInterval = ConfigGetInt32(ConfigInfo, "ModulesUpdateInterval");
    HostsRetryInterval = ConfigGetInt32(ConfigInfo, "HostsRetryInterval");

    RawScript = ConfigGetRawString(ConfigInfo, "HostsScript");
    if( RawScript != NULL )
    {
        if( ExpandPathTo(Script, SIZE_OF_PATH_BUFFER, RawScript) != 0 )
        {
            ERRORMSG("Failed to expand path: %s.\n", RawScript);
            FreeCharPtrArray(HostsURLs);
            HostsURLs = NULL;
            return -170;
        }
    } else {
        *Script = 0;
    }

    RWLock_Init(HostsLock);

    /* Register cleanup only after every resource has been successfully
       initialised, so the atexit handler never touches a half-initialised
       or NULL state. */
    atexit(DynamicHosts_Cleanup);

    File = ConfigGetRawString(ConfigInfo, "HostsDownloadPath");

    if( HostsRetryInterval < 0 )
    {
        ERRORMSG("`HostsRetryInterval' is too small (< 0).\n");
        File = NULL;
        return -167;
    }

    INFO("Local hosts file : \"%s\"\n", File);

    if( FileIsReadable(File) )
    {
        INFO("Loading the existing hosts file ...\n");
        DynamicHosts_Load();
    } else {
        INFO("Hosts file is unreadable, this may cause some failures.\n");
    }

    if( UpdateInterval <= 0 )
    {
        TimedTask_Add(FALSE,
                      TRUE,
                      0,
                      (TaskFunc)GetHostsFromInternet_Thread,
                      NULL,
                      NULL,
                      TRUE);
    } else {
        TimedTask_Add(TRUE,
                      TRUE,
                      UpdateInterval * 1000,
                      (TaskFunc)GetHostsFromInternet_Thread,
                      NULL,
                      NULL,
                      TRUE);
    }

    return 0;
}

int DynamicHosts_GetCName(const char *Domain, char *Buffer)
{
    int ret;

    if( MainDynamicContainer == NULL )
    {
        return -198;
    }

    RWLock_RdLock(HostsLock);

    ret = HostsUtils_GetCName(Domain,
                              Buffer,
                              (HostsContainer *)MainDynamicContainer
                              );

    RWLock_UnRLock(HostsLock);

    return ret;
}

BOOL DynamicHosts_TypeExisting(const char *Domain, HostsRecordType Type)
{
    BOOL ret;

    if( MainDynamicContainer == NULL )
    {
        return FALSE;
    }

    RWLock_RdLock(HostsLock);

    ret = HostsUtils_TypeExisting((HostsContainer *)MainDynamicContainer,
                                  Domain,
                                  Type
                                  );

    RWLock_UnRLock(HostsLock);

    return ret;
}

HostsUtilsTryResult DynamicHosts_Try(MsgContext *MsgCtx, int BufferLength)
{
    HostsUtilsTryResult ret;

    if( MainDynamicContainer == NULL )
    {
        return HOSTSUTILS_TRY_NONE;
    }

    RWLock_RdLock(HostsLock);

    ret = HostsUtils_Try(MsgCtx,
                         BufferLength,
                         (HostsContainer *)MainDynamicContainer
                         );

    RWLock_UnRLock(HostsLock);

    return ret;
}
