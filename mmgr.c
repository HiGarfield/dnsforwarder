#include <string.h>
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

typedef int (*SendFunc)(void *Module,
                        const char *Buffer,
                        int BufferLength
                        );

typedef struct _ModuleInterface {
    union {
        UdpM    Udp;
        TcpM    Tcp;
    } ModuleUnion;

    SendFunc    Send;

    const char *ModuleName;

} ModuleInterface;

typedef struct _ModuleMap {
    StableBuffer *Modules;      /* Storing ModuleInterfaces */
    Array        *ModuleArray;  /* ModuleInterfaces' references */
    StringChunk  *Distributor;  /* Domain-to-ModuleInterface mapping */
} ModuleMap;

static ModuleMap    *CurModuleMap = NULL;
static RWLock       ModulesLock = NULL_RWLOCK;
static ConfigFileInfo *CurrConfigInfo = NULL;

static BOOL EnableUDPtoTCP;
static BOOL EnableTCPtoUDP;

int TCPM_Keep_Alive = 2;

static void DomainList_Tidy(StringList *DomainList)
{
    DomainList->TrimAll(DomainList, "\t .");
    DomainList->LowercaseAll(DomainList);
}

static int MappingAModule(ModuleMap *ModuleMap,
                          ModuleInterface *Stored,
                          StringList *DomainList
                          )
{
    StringListIterator  i;
    const char *OneDomain;

    if( StringListIterator_Init(&i, DomainList) != 0 )
    {
        return -46;
    }

    while( (OneDomain = i.Next(&i)) != NULL )
    {
        StringChunk_Add_Domain(ModuleMap->Distributor,
                               OneDomain,
                               &Stored,
                               sizeof(ModuleInterface *)
                               );
    }

    return 0;
}

static ModuleInterface *StoreAModule(ModuleMap *ModuleMap)
{
    ModuleInterface *Added;

    Added = ModuleMap->Modules->Add(ModuleMap->Modules, NULL, sizeof(ModuleInterface), TRUE);
    if( Added == NULL )
    {
        return NULL;
    }

    if( Array_PushBack(ModuleMap->ModuleArray, &Added, NULL) < 0 )
    {
        return NULL;
    }

    Added->ModuleName = "Unknown";

    /* The constructor (Udp_Init_Core / Tcp_Init) fills Send only after its
       module init succeeds; when UdpM_Init / TcpM_Init fails the module is
       left in ModuleArray with a garbage Send pointer, and MMgr_Send() would
       call through it (crash).  Default it to NULL here and have MMgr_Send()
       skip modules without a Send routine. */
    Added->Send = NULL;

    return Added;
}

static int Udp_Init_Core(ModuleMap *ModuleMap,
                         const char *Services,
                         StringList *DomainList,
                         const char *Parallel
                         )
{
    ModuleInterface *NewM;

    char ParallelOnOff[8];
    BOOL ParallelQuery;

    if( Services == NULL || DomainList == NULL || Parallel == NULL )
    {
        return -99;
    }

    NewM = StoreAModule(ModuleMap);
    if( NewM == NULL )
    {
        return -101;
    }

    NewM->ModuleName = "UDP";

    strncpy(ParallelOnOff, Parallel, sizeof(ParallelOnOff));
    ParallelOnOff[sizeof(ParallelOnOff) - 1] = '\0';
    StrToLower(ParallelOnOff);

    if( strcmp(ParallelOnOff, "on") == 0 )
    {
        ParallelQuery = TRUE;
    } else {
        ParallelQuery = FALSE;
    }

    /* Initialize the module's lifecycle lock BEFORE the constructor runs.  The
       constructor (UdpM_Init) may fail partway (bind error, OOM) and return
       without initializing m->Lock, but Modules_SafeCleanup still matches this
       module by its "UDP"/"TCP" name and takes m->Lock.  A lock that was never
       initialized is undefined behaviour on Linux, so initialize it up front
       and destroy it on the failure path below.  UdpM_Init must therefore NOT
       re-initialize the same lock (double init is also UB). */
    EFFECTIVE_LOCK_INIT(NewM->ModuleUnion.Udp.Lock);

    /* Initializing module */
    if( UdpM_Init(&(NewM->ModuleUnion.Udp), Services, ParallelQuery) != 0 )
    {
        /* Leave Udp.Lock initialized: Modules_SafeCleanup still matches this
           failed module by its "UDP" name and takes Udp.Lock, so destroying it
           here would make that GET a use-after-destroy.  The lock dies with the
           ModuleMap's memory (Modules_Free), which never destroys it explicitly,
           exactly like a successfully-initialized module. */
        return -128;
    }

    NewM->Send = NewM->ModuleUnion.Udp.Send;

    if( MappingAModule(ModuleMap, NewM, DomainList) != 0 )
    {
        ERRORMSG("Mapping UDP module of %s failed.\n", Services);
    }

    return 0;
}

static int Udp_Init(ModuleMap *ModuleMap, StringListIterator *i)
{
    const char *Services;
    const char *Domains;
    const char *Parallel;

    StringList DomainList;
    int ret = 0;

    /* Initializing parameters */
    Services = i->Next(i);
    Domains = i->Next(i);
    Parallel = i->Next(i);

    if( Domains == NULL )
    {
        return -143;
    }

    if( StringList_Init(&DomainList, Domains, ",") != 0 )
    {
        return -148;
    }

    DomainList_Tidy(&DomainList);

    if( Udp_Init_Core(ModuleMap, Services, &DomainList, Parallel) != 0 )
    {
        ret = -153;
    }

    DomainList.Free(&DomainList);

    return ret;
}

static int Tcp_Init_Core(ModuleMap *ModuleMap,
                         const char *Services,
                         StringList *DomainList,
                         const char *Parallel,
                         const char *Proxies
                         )
{
    ModuleInterface *NewM;

    char OptionString[8];
    BOOL ParallelQuery;

    if( Services == NULL || DomainList == NULL || Parallel == NULL || Proxies == NULL )
    {
        return -157;
    }

    NewM = StoreAModule(ModuleMap);
    if( NewM == NULL )
    {
        return -192;
    }

    NewM->ModuleName = "TCP";

    strncpy(OptionString, Parallel, sizeof(OptionString));
    OptionString[sizeof(OptionString) - 1] = '\0';
    StrToLower(OptionString);

    if( strcmp(OptionString, "on") == 0 )
    {
        ParallelQuery = TRUE;
    } else {
        ParallelQuery = FALSE;
    }

    strncpy(OptionString, Proxies, sizeof(OptionString));
    OptionString[sizeof(OptionString) - 1] = '\0';
    StrToLower(OptionString);

    if( strcmp(OptionString, "no") == 0 )
    {
        Proxies = NULL;
    }

    /* Initialize the module's lifecycle lock BEFORE the constructor runs.
       TcpM_Init may fail partway (bind error, OOM) and return without
       initializing m->Lock, yet Modules_SafeCleanup matches this module by its
       "TCP" name and takes m->Lock; an uninitialized lock is UB on Linux.  Init
       it up front and destroy on the failure path.  TcpM_Init must NOT
       re-initialize the same lock (double init is UB). */
    EFFECTIVE_LOCK_INIT(NewM->ModuleUnion.Tcp.Lock);

    /* Initializing module */
    if( TcpM_Init(&(NewM->ModuleUnion.Tcp), Services, ParallelQuery, Proxies) != 0 )
    {
        /* Leave Tcp.Lock initialized for the same reason as the UDP branch:
           Modules_SafeCleanup matches this failed module by "TCP" and takes
           Tcp.Lock, so destroying it here would be a use-after-destroy. */
        return -180;
    }

    NewM->Send = NewM->ModuleUnion.Tcp.Send;

    if( MappingAModule(ModuleMap, NewM, DomainList) != 0 )
    {
        ERRORMSG("Mapping TCP module of %s failed.\n", Services);
    }

    return 0;
}

static int Tcp_Init(ModuleMap *ModuleMap, StringListIterator *i)
{
    const char *Services;
    const char *Domains;
    const char *Parallel;
    const char *Proxies;

    StringList DomainList;
    int ret = 0;

    /* Initializing parameters */
    Services = i->Next(i);
    Domains = i->Next(i);
    Parallel = i->Next(i);
    Proxies = i->Next(i);

    if( Domains == NULL )
    {
        return -143;
    }

    if( StringList_Init(&DomainList, Domains, ",") != 0 )
    {
        return -148;
    }

    DomainList_Tidy(&DomainList);

    if( Tcp_Init_Core(ModuleMap, Services, &DomainList, Parallel, Proxies) != 0 )
    {
        ret = -233;
    }

    DomainList.Free(&DomainList);

    return ret;
}

/*
#############################
# UDP
PROTOCOL UDP
SERVER 1.2.4.8,127.0.0.1
PARALLEL ON

LIST domainlist.txt

example.com

#############################
# TCP
PROTOCOL TCP
SERVER 1.2.4.8,127.0.0.1
PARALLEL ON
PROXY NO

LIST domainlist.txt

example.com

#############################
# TCP
PROTOCOL TCP
SERVER 1.2.4.8,127.0.0.1
PARALLEL OFF
PROXY 192.168.1.1:8080,192.168.1.1:8081

example.com

#############################
# UDP and TCP use the same servers
PROTOCOL *
SERVER 1.2.4.8,127.0.0.1
*/
static int Modules_InitFromFile(ModuleMap *ModuleMap, StringListIterator *i)
{
    #define MAX_PATH_BUFFER     384

    StringChunk Args;
    StringList  Domains;

    const char *FileOri;
    char File[MAX_PATH_BUFFER];
    FILE *fp;

    ReadLineStatus  Status;

    const char *Protocol = NULL;
    const char *List = NULL;

    BOOL UseUDP = FALSE;
    BOOL UseTCP = FALSE;
    BOOL UseANY = FALSE;

    int ret = 0;

    FileOri = i->Next(i);

    if( FileOri == NULL )
    {
        return -201;
    }

    if( ExpandPathTo(File, MAX_PATH_BUFFER, FileOri) != 0 )
    {
        ERRORMSG("Failed to expand path: %s.\n", FileOri);
        return -202;
    }

    fp = fopen(File, "r");
    if( fp == NULL )
    {
        WARNING("Cannot open group file \"%s\".\n", File);
        return 0;
    }

    if( StringChunk_Init(&Args, NULL) != 0 )
    {
        fclose(fp);
        return -230;
    }

    if( StringList_Init(&Domains, NULL, NULL) != 0 )
    {
        fclose(fp);
        ret = -235;
        goto EXIT_1;
    }

    do {
        char Buffer[MAX_PATH_BUFFER];
        const char *Value;

        Status = ReadLine(fp, Buffer, sizeof(Buffer));

        if( Status == READ_TRUNCATED )
        {
            WARNING("Line is too long %s, file \"%s\".\n", Buffer, File);
            ReadLine_GoToNextLine(fp);
            continue;
        }

        if( Status == READ_FAILED_OR_END )
        {
            break;
        }

        StrToLower(Buffer);

        Value = SplitNameAndValue(Buffer, " \t=");
        if( Value != NULL )
        {
            StringChunk_Add(&Args, Buffer, Value, strlen(Value) + 1);
        } else {
            Domains.Add(&Domains, Buffer, NULL);
        }

    } while( TRUE );

    fclose(fp);

    if( !StringChunk_Match_NoWildCard(&Args,
                                      "protocol",
                                      NULL,
                                      (void **)&Protocol,
                                      NULL,
                                      NULL
                                      ) ||
        Protocol == NULL
        )
    {
        ERRORMSG("No protocol specified, file \"%s\".\n", File);
        ret = -270;
        goto EXIT_2;
    }

    if( StringChunk_Match_NoWildCard(&Args, "list", NULL, (void **)&List, NULL, NULL) && List != NULL )
    {
        char ListFile[MAX_PATH_BUFFER];

        if( ExpandPathTo(ListFile, MAX_PATH_BUFFER, List) != 0 )
        {
            ERRORMSG("Failed to expand path: %s.\n", List);
            ret = -202;
            goto EXIT_2;
        }

        fp = fopen(ListFile, "r");
        if( fp == NULL )
        {
            WARNING("Cannot open group domain list file \"%s\".\n", ListFile);
        } else {
            do {
                char Buffer[MAX_PATH_BUFFER];

                Status = ReadLine(fp, Buffer, sizeof(Buffer));

                if( Status == READ_TRUNCATED )
                {
                    WARNING("Line is too long %s, file \"%s\".\n", Buffer, ListFile);
                    ReadLine_GoToNextLine(fp);
                    continue;
                }

                if( Status == READ_FAILED_OR_END )
                {
                    break;
                }

                StrToLower(Buffer);

                Domains.Add(&Domains, Buffer, NULL);
            } while( TRUE );

            fclose(fp);
        }
    }

    DomainList_Tidy(&Domains);

    if( Domains.Count(&Domains) == 0 )
    {
        ret = 0;
        goto EXIT_2;
    }

    UseANY = strcmp(Protocol, "*") == 0;
    if( UseANY )
    {
        UseUDP = TRUE;
        UseTCP = TRUE;
    } else {
        UseUDP = strcmp(Protocol, "udp") == 0;
    }

    if( UseUDP )
    {
        const char *Services = NULL;
        const char *Parallel = "on";

        StringChunk_Match_NoWildCard(&Args, "server", NULL, (void **)&Services, NULL, NULL);
        StringChunk_Match_NoWildCard(&Args, "parallel", NULL, (void **)&Parallel, NULL, NULL);

        if( Udp_Init_Core(ModuleMap, Services, &Domains, Parallel) != 0 )
        {
            ERRORMSG("Loading group file \"%s\" failed.\n", File);
            ret = -337;
        }

    } else {
        UseTCP = strcmp(Protocol, "tcp") == 0;
    }

    if( UseTCP )
    {
        const char *Services = NULL;
        const char *Parallel = "on";
        const char *Proxies = "no";

        StringChunk_Match_NoWildCard(&Args, "server", NULL, (void **)&Services, NULL, NULL);
        StringChunk_Match_NoWildCard(&Args, "parallel", NULL, (void **)&Parallel, NULL, NULL);
        StringChunk_Match_NoWildCard(&Args, "proxy", NULL, (void **)&Proxies, NULL, NULL);

        if( Tcp_Init_Core(ModuleMap, Services, &Domains, Parallel, Proxies) != 0 )
        {
            ERRORMSG("Loading group file \"%s\" failed.\n", File);
            ret = -233;
        }

    } else if( !UseUDP ) {
        ERRORMSG("Unknown protocol %s, file \"%s\".\n", Protocol, File);
        ret = -281;
    }

EXIT_2:
    Domains.Free(&Domains);
EXIT_1:
    StringChunk_Free(&Args, TRUE);

    return ret;
}

static int Modules_Init(ModuleMap *ModuleMap, ConfigFileInfo *ConfigInfo)
{
    StringList  *ServerGroups;
    StringListIterator  i;

    const char *Type;

    ServerGroups = ConfigGetStringList(ConfigInfo, "ServerGroup");
    if( ServerGroups == NULL )
    {
        ERRORMSG("Please set at least one server group.\n");
        return -202;
    }

    if( StringListIterator_Init(&i, ServerGroups) != 0 )
    {
        return -207;
    }

    while( (Type = i.Next(&i)) != NULL )
    {
        if( strcmp(Type, "UDP") == 0 )
        {
            if( Udp_Init(ModuleMap, &i) != 0 )
            {
                ERRORMSG("Initializing UDPGroups failed.\n");
                return -218;
            }
        } else if( strcmp(Type, "TCP") == 0 )
        {
            if( Tcp_Init(ModuleMap, &i) != 0 )
            {
                ERRORMSG("Initializing TCPGroups failed.\n");
                return -226;
            }
        } else if( strcmp(Type, "FILE") == 0 )
        {
            if( Modules_InitFromFile(ModuleMap, &i) != 0 )
            {
                ERRORMSG("Initializing group files failed.\n");
                return -318;
            }
        } else {
            ERRORMSG("Initializing server groups failed, near %s.\n", Type);
            return -230;
        }
    }

    INFO("Loading Server Groups completed.\n", Type);
    return 0;
}

static void Modules_Free(ModuleMap *ModuleMap)
{
    if( ModuleMap == NULL )
    {
        return;
    }
    if( ModuleMap->Modules != NULL )
    {
        ModuleMap->Modules->Free(ModuleMap->Modules);
        SafeFree(ModuleMap->Modules);
    }
    if( ModuleMap->ModuleArray != NULL )
    {
        Array_Free(ModuleMap->ModuleArray);
        SafeFree(ModuleMap->ModuleArray);
    }
    if( ModuleMap->Distributor != NULL )
    {
        StringChunk_Free(ModuleMap->Distributor, TRUE);
        SafeFree(ModuleMap->Distributor);
    }
    SafeFree(ModuleMap);
}

static int
#ifdef WIN32
WINAPI
#endif
Modules_SafeCleanup(ModuleMap *ModuleMap)
{
    StableBufferIterator BI;
    ModuleInterface *M = NULL;
    int i, BytesOfMetaInfo;
    BOOL InUse = TRUE;

    if( ModuleMap == NULL  || StableBufferIterator_Init(&BI, ModuleMap->Modules) != 0 )
    {
        return -1;
    }

    while( InUse )
    {
        InUse = FALSE;
        BI.Reset(&BI);
        while( (M = BI.NextBlock(&BI)) != NULL )
        {
            BytesOfMetaInfo = BI.CurrentBlockUsed(&BI);
            for( i = 0; i * (int)sizeof(ModuleInterface) < (int)BytesOfMetaInfo; ++i, ++M )
            {
                /* A module whose constructor failed (UdpM_Init / TcpM_Init
                 * returned non-zero) never started its worker threads and
                 * never initialized its lock; StoreAModule left its Send
                 * NULL.  Such entries only exist when Modules_Load() bails out
                 * after a partial group-file load and runs this routine on the
                 * half-built map.  Touching their lock / thread handles would
                 * be undefined behaviour (uninitialized spin lock, garbage
                 * thread ids), so skip them. */
                if( M->Send == NULL )
                {
                    continue;
                }

                if( strcmp(M->ModuleName, "UDP") == 0 )
                {
                    /* Clear IsServer and read the thread handles under the
                     * module's spin lock, matching the locking done by
                     * UdpM_Works / UdpM_Cleanup / UdpM_Sweep_Thread.  Without
                     * this synchronization the shutdown writer races with the
                     * still-running worker threads on these fields (data race
                     * reported by helgrind).  Keep the lock brief: the sleep
                     * below must happen lock-free so the workers can finish. */
                    EFFECTIVE_LOCK_GET(M->ModuleUnion.Udp.Lock);
                    M->ModuleUnion.Udp.IsServer = 0;
                    InUse |= M->ModuleUnion.Udp.WorkThread != NULL_THREAD;
                    InUse |= M->ModuleUnion.Udp.SweepThread != NULL_THREAD;
                    EFFECTIVE_LOCK_RELEASE(M->ModuleUnion.Udp.Lock);
                }
                else if( strcmp(M->ModuleName, "TCP") == 0 )
                {
                    EFFECTIVE_LOCK_GET(M->ModuleUnion.Tcp.Lock);
                    M->ModuleUnion.Tcp.IsServer = 0;
                    InUse |= M->ModuleUnion.Tcp.WorkThread != NULL_THREAD;
                    EFFECTIVE_LOCK_RELEASE(M->ModuleUnion.Tcp.Lock);
                }
            }
        }

        if( !InUse )
        {
            break;
        }

        SLEEP(1000);
    }

    /* Ensure no other thread is still holding ModulesLock (e.g. MMgr_Send
     * dereferencing CurModuleMap->Distributor / a module's Send pointer).
     * Taking and immediately releasing the write lock blocks until every
     * reader has exited, so the structures we are about to free cannot be
     * in use. Without this barrier a concurrent MMgr_Send could touch freed
     * memory (use-after-free) during a group-file reload. */
    RWLock_WrLock(ModulesLock);
    RWLock_UnWLock(ModulesLock);

    Modules_Free(ModuleMap);
    INFO("Last GroupFile Modules freed.\n");

    return 0;
}

static int Modules_Load(ConfigFileInfo *ConfigInfo)
{
    ModuleMap *NewModuleMap;
    ThreadHandle th;
    int ret;

    CurrConfigInfo = ConfigInfo;

    NewModuleMap = SafeMalloc(sizeof(ModuleMap));
    if( NewModuleMap == NULL )
    {
        return -1;
    }

    /* SafeMalloc is plain malloc() and leaves the block uninitialised.
       Every failure path below jumps to ModulesFree, which reads (and
       cleans up through) NewModuleMap->Modules / NewModuleMap->ModuleArray
       before those fields are assigned.  With garbage non-NULL values the
       cleanup would dereference a wild StableBuffer/Array pointer and
       crash on an OOM error path.  Zero the whole map up front so unset
       fields read as NULL and the cleanup paths become safe no-ops. */
    memset(NewModuleMap, 0, sizeof(ModuleMap));
    if( InitChunk(&(NewModuleMap->Distributor)) != 0 )
    {
        ret = -10;
        goto ModulesFree;
    }

    NewModuleMap->Modules = SafeMalloc(sizeof(StableBuffer));
    if( NewModuleMap->Modules == NULL)
    {
        ret = -27;
        goto ModulesFree;
    }

    if( StableBuffer_Init(NewModuleMap->Modules) != 0 )
    {
        ret = -27;
        goto ModulesFree;
    }

    NewModuleMap->ModuleArray = SafeMalloc(sizeof(Array));
    if( NewModuleMap->ModuleArray == NULL)
    {
        ret = -98;
        goto ModulesFree;
    }

    if( Array_Init(NewModuleMap->ModuleArray,
                   sizeof(ModuleInterface *),
                   0,
                   FALSE,
                   NULL
                   )
       != 0 )
    {
        ret = -98;
        goto ModulesFree;
    }

    ret = Modules_Init(NewModuleMap, ConfigInfo);

    if (ret)
    {
        goto ModulesFree;
    }

    {
        ModuleMap *OldModuleMap;

        RWLock_WrLock(ModulesLock);
        OldModuleMap = CurModuleMap;
        CurModuleMap = NewModuleMap;   /* publish the new map first */
        RWLock_UnWLock(ModulesLock);   /* then release the lock */

        /* Spawn the cleanup thread only after publishing the new map and
           dropping the lock.  Modules_SafeCleanup re-acquires ModulesLock at
           its end as a barrier to drain any in-flight MMgr_Send readers that
           still reference OldModuleMap; if we held the lock here the new
           thread would block forever on that wrlock (it runs in a different
           thread and the rwlock is not recursive), stalling every reload and
           every reader behind the writer-priority lock.

           CREATE_THREAD behaves differently per platform: on POSIX it expands
           to pthread_create() and its value is the int return code (0 on
           success), while `th` receives the thread id; on Windows it assigns
           the HANDLE to `th` and its value is that HANDLE.  Capture/check
           accordingly so the code compiles and behaves on both. */
#ifdef _WIN32
        CREATE_THREAD(Modules_SafeCleanup, OldModuleMap, th);
        if( th == NULL_THREAD )
        {
            ERRORMSG("Failed to start cleanup thread.\n");
            return -99;
        }
#else
        ret = CREATE_THREAD(Modules_SafeCleanup, OldModuleMap, th);
        if( ret != 0 )
        {
            ERRORMSG("Failed to start cleanup thread: %d\n", ret);
            return -99;
        }
#endif
        DETACH_THREAD(th);
    }

    INFO("Loading GroupFile(s) completed.\n");

    return 0;

ModulesFree:
    if( NewModuleMap->Modules != NULL )
    {
        /* Some groups may already have been created before a later group
         * failed, and their worker threads (UdpM_Works / UdpM_Sweep_Thread /
         * TcpM_Works) are still running.  A bare Modules_Free() would free
         * those instances -- including the spin lock every worker acquires on
         * each loop iteration -- out from under the threads: use-after-free
         * on the module lock / context / pullers.  Modules_SafeCleanup()
         * clears IsServer so each started worker exits, waits for the thread
         * handles to be nulled, drains in-flight MMgr_Send readers via the
         * ModulesLock barrier, and only then frees the map.  Entries whose
         * constructor failed (Send == NULL) are skipped because they never
         * started a thread. */
        Modules_SafeCleanup(NewModuleMap);
    }
    else
    {
        Modules_Free(NewModuleMap);
    }
    INFO("Loading GroupFile(s) failed.\n");
    return ret;
}

static void Modules_Cleanup(void)
{
    /* Do NOT call Modules_Free() directly: the module instances (e.g.
       UdpM_Instance) hold the working threads' state and the spin lock those
       threads keep using. Freeing them while UdpM_Works / UdpM_Sweep_Thread
       are still spinning overwrites their memory and is a use-after-free
       (valgrind reports invalid reads/writes on the freed 1552-byte block and
       a spin_lock on a destroyed lock). Modules_SafeCleanup first clears
       IsServer so every worker thread exits and nulls its handle, then takes
       ModulesLock to drain any in-flight MMgr_Send, and only then frees. */
    if( CurModuleMap != NULL )
    {
        Modules_SafeCleanup(CurModuleMap);
    }
    RWLock_Destroy(ModulesLock);
}

int MMgr_Init(ConfigFileInfo *ConfigInfo)
{
    int ret;

    EnableUDPtoTCP = ConfigGetBoolean(ConfigInfo, "EnableUDPtoTCP");
    EnableTCPtoUDP = ConfigGetBoolean(ConfigInfo, "EnableTCPtoUDP");
    TCPM_Keep_Alive = ConfigGetInt32(ConfigInfo, "TCPKeepAlive");

    RWLock_Init(ModulesLock);

    ret = Modules_Load(ConfigInfo);
    if( ret != 0 )
    {
        return ret;
    }
    atexit(Modules_Cleanup);

    if( Filter_Init(ConfigInfo) != 0 )
    {
        return -159;
    }

    if( DNSCache_Init(ConfigInfo) != 0 )
    {
        return -164;
    }

    if( IpMiscMapping_Init(ConfigInfo) != 0 )
    {
        return -176;
    }

    /* The last: reloading */
    if( Hosts_Init(ConfigInfo) != 0 )
    {
        return -165;
    }

    INFO("Loading Configuration completed.\n");

    return 0;
}

int Modules_Update(void)
{
    /* CurrConfigInfo is assigned by Modules_Load() during MMgr_Init(). A
       reload triggered (e.g. by the dynamic-hosts timer) before that point
       would otherwise pass NULL straight into ConfigGetBoolean(), which
       dereferences it and crashes. Guard against the not-yet-initialized
       state. */
    if( CurrConfigInfo == NULL )
    {
        return 0;
    }

    if ( ConfigGetBoolean(CurrConfigInfo, "ReloadGroupFile") )
    {
        Modules_Load(CurrConfigInfo);
    }
    return 0;
}

static BOOL ModuleFitRequest(const void **Data, const void *Expected)
{
    const ModuleInterface *m = *(ModuleInterface **)Data;
    const MsgContext *MsgCtx = (MsgContext *)Expected;

    if( MsgContext_IsFromTCP(MsgCtx) || ((IHeader *)Expected)->RequestTcp )
    {
        if( EnableTCPtoUDP == FALSE )
        {
            if( strcmp(m->ModuleName, "UDP") == 0 )
            {
                return FALSE;
            }
        }
    } else if( EnableUDPtoTCP == FALSE ) {
        if( strcmp(m->ModuleName, "TCP") == 0 )
        {
            return FALSE;
        }
    }

    return TRUE;
}

int MMgr_Send(const char *Buffer, int BufferLength)
{
    ModuleInterface **i;
    ModuleInterface *TheModule;
    MsgContext *MsgCtx = (MsgContext *)Buffer;
    IHeader *h = (IHeader *)Buffer;

    int ret;

    /* Determine whether to discard the query */
    if( Filter_Out(MsgCtx) )
    {
        /* Dropped before any module saw it: release the TCP socket hold so the
           frontend can close it. Hosts/Cache hits (below) release through
           MsgContext_SendBack; the dispatched-to-module path releases through
           the module's own MsgContext_SendBack. */
        MsgContext_ReleaseSocket(MsgCtx);
        return 0;
    }

    /* Hosts & Cache */
    if( Hosts_Get(MsgCtx, BufferLength) == 0 )
    {
        return 0;
    }

    if( DNSCache_FetchFromCache(MsgCtx, BufferLength) == 0 )
    {
        return 0;
    }

    /* Ordinary models */

    RWLock_RdLock(ModulesLock);

    /* CurModuleMap stays NULL if Modules_Load failed (e.g. bad config) and
     * the front-end threads are already running; dereferencing it would crash. */
    if( CurModuleMap == NULL )
    {
        RWLock_UnRLock(ModulesLock);
        MsgContext_ReleaseSocket(MsgCtx);
        return -190;
    }

    if( StringChunk_Domain_Match_WildCardRandom(CurModuleMap->Distributor,
                                                 h->Domain,
                                                 &(h->HashValue),
                                                 (void **)&i,
                                                 ModuleFitRequest,
                                                 h
                                                 )
       )
    {
    } else if( Array_GetUsed(CurModuleMap->ModuleArray) > 0 ){
        /* DNSGetQueryIdentifier() returns a signed 16-bit value; its high
           bit (>= 0x8000) makes it negative after the int promotion, and the
           modulo below would then yield a negative subscript that
           Array_GetBySubscript rejects, silently dropping ~half of all
           queries. Mask with 0xFFFF first so the result is always a valid
           positive index. */
        i = Array_GetBySubscript(CurModuleMap->ModuleArray,
                                 (int)((unsigned short)DNSGetQueryIdentifier(IHEADER_TAIL(h))) %
                                 Array_GetUsed(CurModuleMap->ModuleArray)
                                 );
    } else {
        i = NULL;
    }

    if( i == NULL || *i == NULL )
    {
        /* No upstream module could take this query: it is dropped, so release
           the TCP socket hold here. */
        MsgContext_ReleaseSocket(MsgCtx);
        ret = -190;
    } else {
        TheModule = *i;

        if( TheModule->Send == NULL )
        {
            /* A module whose constructor failed (bad config, bind error, out
               of memory) never got a Send routine (see StoreAModule).  Do not
               call the NULL pointer; drop the query instead. */
            MsgContext_ReleaseSocket(MsgCtx);
            ret = -190;
        } else {
            ret = TheModule->Send(&(TheModule->ModuleUnion), Buffer, BufferLength);
        }
    }

    RWLock_UnRLock(ModulesLock);

    return ret;
}
