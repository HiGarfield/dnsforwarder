#include <string.h>
#include <time.h>
#include "common.h"
#include "stringchunk.h"
#include "domainstatistic.h"
#include "utils.h"
#include "timedtask.h"
#include "logs.h"

typedef struct _DomainInfo{
    int     Count;
    int     Refused;
    int     Hosts;
    int     Cache;
    int     Udp;
    int     Tcp;
    int     BlockedMsg;
} DomainInfo;

typedef struct _RankList{
    const char  *Domain;
    DomainInfo  *Info;
} RankList;

static EFFECTIVE_LOCK   StatisticLock;

/* Becomes TRUE only after StatisticLock and MainChunk are both initialised.
   DomainStatistic_Cleanup() is registered with atexit() before the lock is
   created (the init code may still fail afterwards, e.g. fopen of the output
   file), so without this guard the atexit handler would lock/destroy a
   never-initialised lock -- undefined behaviour. */
static BOOL             StatisticInited = FALSE;

static StringChunk      MainChunk;

static FILE             *MainFile = NULL;

static unsigned long int    InitTime_Num;

static char *PreOutput = NULL;
static char *PostOutput = NULL;

static volatile BOOL    SkipStatistic = FALSE;

/* Cooperative shutdown flag.  DomainStatistic_Works runs in a detached
   TimedTask thread with no cancellation API, while DomainStatistic_Cleanup
   (registered via atexit) frees PreOutput/PostOutput and closes MainFile.
   Setting this flag before freeing makes the worker bail out instead of
   touching the freed buffer or closed stream (use-after-free on exit). */
static volatile BOOL    ToExit = FALSE;

static int GetPreAndPost(ConfigFileInfo *ConfigInfo)
{
    const char  *TemplateFile = ConfigGetRawString(ConfigInfo, "DomainStatisticTempletFile");
    const char  *InsertionPosString = ConfigGetRawString(ConfigInfo, "StatisticInsertionPosition");
    char    *ip = NULL;
    int FileSize;
    char    *FileContent = NULL;

    if( TemplateFile == NULL )
    {
        return -1;
    }

    if( InsertionPosString == NULL )
    {
        /* `StatisticInsertionPosition' is required to locate where the
           generated data is injected into the template. A missing value
           would be passed as NULL to strstr/strlen below (undefined
           behaviour). */
        return -1;
    }

    FileSize = GetFileSizePortable(TemplateFile);
    if( FileSize <= 0 )
    {
        return -1;
    }

    FileContent = SafeMalloc(FileSize + 1);
    if( FileContent == NULL )
    {
        return -1;
    }

    memset(FileContent, 0, FileSize + 1);

    if( GetTextFileContent(TemplateFile, FileContent, FileSize + 1) != 0 )
    {
        goto EXIT;
    }

    ip = strstr(FileContent, InsertionPosString);
    if( ip == NULL )
    {
        goto EXIT;
    }

    PreOutput = FileContent;
    PostOutput = ip + strlen(InsertionPosString);
    *ip = '\0';

    return 0;

EXIT:
    SafeFree(FileContent);
    return -1;
}

static void DomainStatistic_Works(void *Unused, void *Unused2)
{
    const char *Str;
    int32_t Enum_Start;

    DomainInfo *Info;
    DomainInfo Sum;

    unsigned long int GenerateTime_Num;

    /* Hold the lock for the ENTIRE generation.  DomainStatistic_Cleanup()
       takes the same lock before freeing PreOutput/PostOutput, MainFile and
       MainChunk, so it can never tear the shared state down underneath a
       worker that already passed its checks; and DomainStatistic_Add() (which
       also locks) can never interleave with the enumeration.  The lock-free
       +SkipStatistic scheme of the old code left a window: the detached worker
       checked ToExit, then Cleanup freed the buffers before the worker used
       them -- a use-after-free / write-to-closed-stream at process exit. */
    EFFECTIVE_LOCK_GET(StatisticLock);

    if( MainFile == NULL || ToExit )
    {
        EFFECTIVE_LOCK_RELEASE(StatisticLock);
        return;
    }

    /* Use fseek instead of rewind: rewind does not report failure, so the
       analyzer cannot tell whether errno was consumed; fseek lets us check
       the result explicitly. This also avoids memset() clobbering an
       unchecked errno left by rewind(). */
    if( fseek(MainFile, 0L, SEEK_SET) != 0 )
    {
        EFFECTIVE_LOCK_RELEASE(StatisticLock);
        return;
    }

    memset(&Sum, 0, sizeof(DomainInfo));

    GenerateTime_Num = time(NULL);

    fprintf(MainFile, "%s", PreOutput);
    fprintf(MainFile,
            "<script type=\"text/javascript\">"
            "   var StartUpTime = %lu;"
            "   var LastStatistic = %lu;"
            "   var InfoArray = [",
            InitTime_Num,
            GenerateTime_Num
            );

    Enum_Start = 0;

    SkipStatistic = TRUE;

    Str = StringChunk_Enum_NoWildCard(&MainChunk, &Enum_Start, (void **)&Info);
    while( Str != NULL )
    {
        if( Info != NULL )
        {
            Sum.Count += Info->Count;
            Sum.Refused += Info->Refused;
            Sum.Hosts += Info->Hosts;
            Sum.Cache += Info->Cache;
            Sum.Udp += Info->Udp;
            Sum.Tcp += Info->Tcp;
            Sum.BlockedMsg += Info->BlockedMsg;

            fprintf(MainFile,
                    "{"
                        "Domain:\"%s\","
                        "Total:%d,"
                        "RaF:%d,"
                        "Hosts:%d,"
                        "Cache:%d,"
                        "UDP:%d,"
                        "TCP:%d,"
                        "BlockedMsg:%d"
                    "},",
                    Str,
                    Info->Count,
                    Info->Refused,
                    Info->Hosts,
                    Info->Cache,
                    Info->Udp,
                    Info->Tcp,
                    Info->BlockedMsg
                     );
        }

        Str = StringChunk_Enum_NoWildCard(&MainChunk, &Enum_Start, (void **)&Info);
    }

    SkipStatistic = FALSE;

    fprintf(MainFile, "];");

    fprintf(MainFile,
            "var Sum = { Total      :   %d,"
                        "RaF        :   %d,"
                        "Hosts      :   %d,"
                        "Cache      :   %d,"
                        "UDP        :   %d,"
                        "TCP        :   %d,"
                        "BlockedMsg :   %d"
                        "};"
            "</script>",
            Sum.Count,
            Sum.Refused,
            Sum.Hosts,
            Sum.Cache,
            Sum.Udp,
            Sum.Tcp,
            Sum.BlockedMsg
            );

    fprintf(MainFile, "%s", PostOutput);

    fflush(MainFile);

    EFFECTIVE_LOCK_RELEASE(StatisticLock);

    return;
}

static void DomainStatistic_Cleanup(void)
{
    /* Signal the (detached) statistic worker thread to stop and free every
       shared resource while holding StatisticLock -- the same lock that
       DomainStatistic_Works() holds for its whole body.  The worker therefore
       cannot be in the middle of writing to PreOutput / MainFile / MainChunk
       when they are released here (the ToExit flag alone had a check-then-use
       window: the worker could pass the check and then be pre-empted before
       the free happened).  We cannot join the worker (TimedTask detaches it),
       so mutual exclusion over the shared state is the only safe scheme. */
    /* If Init() never reached the point where StatisticLock / MainChunk were
       created (e.g. the output file could not be opened), the resources below
       are uninitialised; touching them would be UB. */
    if( !StatisticInited )
    {
        if( PreOutput != NULL )
        {
            SafeFree(PreOutput);
            PreOutput = NULL;
            PostOutput = NULL;
        }
        if( MainFile != NULL )
        {
            fclose(MainFile);
            MainFile = NULL;
        }
        return;
    }

    EFFECTIVE_LOCK_GET(StatisticLock);
    ToExit = TRUE;

    if( PreOutput != NULL )
    {
        SafeFree(PreOutput);
        PreOutput = NULL;
        PostOutput = NULL;
    }
    if( MainFile != NULL )
    {
        fclose(MainFile);
        MainFile = NULL;
    }
    StringChunk_Free(&MainChunk, FALSE);
    EFFECTIVE_LOCK_RELEASE(StatisticLock);

    /* Do NOT destroy StatisticLock here.  DomainStatistic_Works() is a
       persistent task scheduled on the TimedTask worker thread, and
       TimedTask_Cleanup() (registered before this module, so it runs AFTER
       this handler under atexit's LIFO order) is what joins that worker.  A
       worker mid-way through DomainStatistic_Works() can therefore still be
       about to take this lock after we released it; destroying the lock here
       would let it lock freed/destroyed state (undefined behaviour).  This
       matches the established shutdown convention in udpm.c / tcpm.c /
       dynamichosts.c, which deliberately leave their locks intact for the OS
       to reclaim at process exit. */
}

int DomainStatistic_Init(ConfigFileInfo *ConfigInfo)
{
    BOOL DomainStatistic = ConfigGetBoolean(ConfigInfo, "DomainStatistic");
    int OutputInterval;
    char FilePath[1024];

    if( !DomainStatistic )
    {
        return 0;
    }

    OutputInterval = ConfigGetInt32(ConfigInfo, "StatisticUpdateInterval");

    if( OutputInterval < 1 )
    {
        ERRORMSG("`StatisticUpdateInterval' should be positive.\n");
        return 1;
    }

    if( GetPreAndPost(ConfigInfo) != 0 )
    {
        WARNING("Domain statistic init failed, it may due to lack of memory or templet file.\n");
        return 0;
    }

    atexit(DomainStatistic_Cleanup);

    GetFileDirectory(FilePath);
    snprintf(FilePath + strlen(FilePath),
             sizeof(FilePath) - strlen(FilePath),
             "%s%s",
             PATH_SLASH_STR,
             "statistic.html");

    MainFile = fopen(FilePath, "w");

    if( MainFile == NULL )
    {
        ERRORMSG("Writing %s failed.\n", FilePath);
        return 3;
    }

    EFFECTIVE_LOCK_INIT(StatisticLock);
    if( StringChunk_Init(&MainChunk, NULL) != 0 )
    {
        EFFECTIVE_LOCK_DESTROY(StatisticLock);
        if( MainFile != NULL )
        {
            fclose(MainFile);
            MainFile = NULL;
        }
        if( PreOutput != NULL )
        {
            SafeFree(PreOutput);
            PreOutput = NULL;
            PostOutput = NULL;
        }
        return 4;
    }

    /* Only now may the atexit handler touch StatisticLock / MainChunk. */
    StatisticInited = TRUE;

    InitTime_Num = time(NULL);
    SkipStatistic = FALSE;

    TimedTask_Add(TRUE,
                  FALSE,
                  OutputInterval * 1000,
                  DomainStatistic_Works,
                  NULL,
                  NULL,
                  FALSE
                  );

    return 0;
}

int DomainStatistic_Add(IHeader *h, StatisticType Type)
{
    DomainInfo *ExistInfo;

    if( h == NULL )
    {
        return 0;
    }

    /* Re-check MainFile/ToExit under the lock: DomainStatistic_Cleanup()
       clears them while holding the same lock, so without this a request
       thread that waited for the lock during cleanup could touch a freed
       MainChunk afterwards. */
    EFFECTIVE_LOCK_GET(StatisticLock);

    if( MainFile == NULL || ToExit )
    {
        EFFECTIVE_LOCK_RELEASE(StatisticLock);
        return 0;
    }

    if( SkipStatistic == FALSE )
    {

        if( StringChunk_Match(&MainChunk,
                              h->Domain,
                              &(h->HashValue),
                              (void **)&ExistInfo,
                              NULL,
                              NULL
                              )
            == FALSE )
        {
            DomainInfo NewInfo;

            memset(&NewInfo, 0, sizeof(DomainInfo));

            switch( Type )
            {
                case STATISTIC_TYPE_REFUSED:
                    NewInfo.Count = 1;
                    NewInfo.Refused = 1;
                    break;

                case STATISTIC_TYPE_HOSTS:
                    NewInfo.Count = 1;
                    NewInfo.Hosts = 1;
                    break;

                case STATISTIC_TYPE_CACHE:
                    NewInfo.Count = 1;
                    NewInfo.Cache = 1;
                    break;

                case STATISTIC_TYPE_UDP:
                    NewInfo.Count = 1;
                    NewInfo.Udp = 1;
                    break;

                case STATISTIC_TYPE_TCP:
                    NewInfo.Count = 1;
                    NewInfo.Tcp = 1;
                    break;

                case STATISTIC_TYPE_BLOCKEDMSG:
                    NewInfo.Count = 0;
                    NewInfo.BlockedMsg = 1;
                    break;

            }

            StringChunk_Add(&MainChunk, h->Domain, (const char *)&NewInfo, sizeof(DomainInfo));
        } else {
            if( ExistInfo != NULL )
            {
                switch( Type )
                {
                    case STATISTIC_TYPE_REFUSED:
                        ++(ExistInfo->Count);
                        ++(ExistInfo->Refused);
                        break;

                    case STATISTIC_TYPE_HOSTS:
                        ++(ExistInfo->Count);
                        ++(ExistInfo->Hosts);
                        break;

                    case STATISTIC_TYPE_CACHE:
                        ++(ExistInfo->Count);
                        ++(ExistInfo->Cache);
                        break;

                    case STATISTIC_TYPE_UDP:
                        ++(ExistInfo->Count);
                        ++(ExistInfo->Udp);
                        break;

                    case STATISTIC_TYPE_TCP:
                        ++(ExistInfo->Count);
                        ++(ExistInfo->Tcp);
                        break;

                    case STATISTIC_TYPE_BLOCKEDMSG:
                        ++(ExistInfo->BlockedMsg);
                        break;
                }
            }
        }

    }

    EFFECTIVE_LOCK_RELEASE(StatisticLock);

    return 0;
}
