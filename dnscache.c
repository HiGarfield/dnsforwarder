#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "dnscache.h"
#include "dnsgenerator.h"
#include "utils.h"
#include "rwlock.h"
#include "cacheht.h"
#include "cachettlcrtl.h"
#include "logs.h"
#include "timedtask.h"
#include "domainstatistic.h"

#define CACHE_VERSION   23

#define CACHE_END   '\x0A'
#define CACHE_START '\xFF'

/*  Headroom Vs Sharing-Ratio
    Average domain name length, top 10k: 8, 1M: 10;
    IPv4: 4; IPv6: 16.
    (1 + ({10} + 1) + (2 + 1) + (1 + 1)) + [4, 16] = 17 + [4, 16] = [21, 33]
    8: [[24-3, 32-11], [40-7, 48-15]]
    16: [[32-11], [48-15]]
    32: [[32-11], [64-31]]
 */
#define CACHE_ROUND_UP(v)   ROUND_UP(v, 16)

static BOOL             Inited = FALSE;
static BOOL             CacheParallel = FALSE;

static RWLock           CacheLock = NULL_RWLOCK;

static FileHandle       CacheFileHandle = INVALID_FILE;
static MappingHandle    CacheMappingHandle = INVALID_MAP;
static char             *MapStart = NULL;
static BOOL             MemoryCache = FALSE;

static int32_t          CacheSize;
static BOOL             IgnoreTTL;

static int32_t          *CacheCount;

static volatile int32_t *CacheEnd; /* Offset */

static CacheHT          *CacheInfo;

static CacheTtlCtrl     *TtlCtrl = NULL;

struct _Header{
    uint32_t    Ver;
    int32_t     CacheSize;
    int32_t     End;
    int32_t     CacheCount;
    CacheHT     ht;
    char        Comment[128 - sizeof(uint32_t) - sizeof(int32_t) - sizeof(int32_t) - sizeof(int32_t) - sizeof(CacheHT)];
};

static void DNSCacheTTLCountdown_Task(void *Unused, void *Unused2)
{
    /* Take the cache write lock *before* touching any shared cache state
     * (including the CacheInfo pointer itself).  Without this, the very first
     * read of CacheInfo->NodeChunk races with the one-time initialization
     * done on the main thread.  This task runs as a low-frequency timer, so
     * holding the lock for the scan is acceptable. */
    RWLock_WrLock(CacheLock);

    {
        const Array *ChunkList = &(CacheInfo->NodeChunk);
        int         loop = ChunkList->Used - 1;
        Cht_Node    *Node;
        time_t      CurrentTime;

        if( loop < 0 )
        {
            RWLock_UnWLock(CacheLock);
            return;
        }

        Node = (Cht_Node *)Array_GetBySubscript(ChunkList, loop);

        CurrentTime = time(NULL);


    while( Node != NULL )
    {
        if( Node->TTL > 0 )
        {
            if( CurrentTime - Node->TimeAdded >= Node->TTL )
            {
                Node->TTL = 0;

                /* Mark the slot as expired with a sentinel byte. The field is
                   declared `char' (signed) in the shared mmap layout, so
                   writing 0xFD (253) directly triggers -Woverflow under
                   -Wconversion/-pedantic because 253 is out of range for a
                   signed char (it would wrap to -3). Cast through unsigned
                   char so the byte stored is exactly 0xFD; no code path ever
                   reads this sentinel back, so the value is purely cosmetic,
                   but the cast keeps the strict build warning-free. */
                *(unsigned char *)(MapStart + Node->Offset) = 0xFD;

                CacheHT_RemoveFromSlot(CacheInfo, loop, Node);

                --(*CacheCount);

            }
        }

        --loop;
        if( loop < 0 )
        {
            Node = NULL;
        } else {
            Node = (Cht_Node *)Array_GetBySubscript(ChunkList, loop);
        }
    }

    if( ChunkList->Used == 0 )
    {
        (*CacheEnd) = sizeof(struct _Header);
    } else {
        /* Do NOT roll CacheEnd back to the tail node's end: the node at
           ChunkList->Used - 1 may be a reused (low-offset) entry from the
           free 2D-list, and lowering CacheEnd would let a subsequent new
           allocation overwrite still-valid records living at higher
           offsets.  CacheEnd is the high-water mark for new nodes; the
           free list services reuse independently, so keep it monotonic. */
    }

    RWLock_UnWLock(CacheLock);
    }
}

static BOOL IsReloadable(void)
{
    const struct _Header *Header = (struct _Header *)MapStart;

    if( Header->Ver != CACHE_VERSION )
    {
        ERRORMSG("The existing cache is not compatible with this version of program.\n");
        return FALSE;
    }

    if( Header->CacheSize != CacheSize )
    {
        ERRORMSG("The size of the existing cache and the value of `CacheSize' should be equal.\n");
        return FALSE;
    }

    if( Header->CacheCount < 0 )
    {
        ERRORMSG("The existing cache is corrupted and cannot be reloaded.\n");
        return FALSE;
    }

    /* Everything below the header -- the hash table, the slot chains and every
       node's Offset -- comes verbatim from the cache file, yet the cache write
       paths trust it: neither DNSCacheTTLCountdown_Task nor
       DNSCache_GetAvailableChunk bounds-check Node->Offset before writing
       through it. Refuse to reload a structurally inconsistent image. */
    if( !CacheHT_IsStructureSane(&(Header->ht),
                                 MapStart,
                                 CacheSize,
                                 (int)sizeof(struct _Header),
                                 Header->End
                                 )
      )
    {
        ERRORMSG("The existing cache is corrupted and cannot be reloaded.\n");
        return FALSE;
    }

    return TRUE;
}

static void ReloadCache(void)
{
    struct _Header  *Header = (struct _Header *)MapStart;

    INFO("Reloading the cache ...\n");

    CacheInfo = &(Header->ht);

    CacheHT_ReInit(CacheInfo, MapStart, CacheSize);

    CacheEnd = &(Header->End);
    CacheCount = &(Header->CacheCount);

    INFO("Cache reloaded, containing %d entries for %d items.\n", CacheInfo->NodeChunk.Used, (*CacheCount));
}

static void CreateNewCache(void)
{
    struct _Header  *Header = (struct _Header *)MapStart;

    memset(MapStart, 0, CacheSize);

    Header->Ver = CACHE_VERSION;
    Header->CacheSize = CacheSize;
    Header->CacheCount = 0;
    CacheEnd = &(Header->End);
    *CacheEnd = sizeof(struct _Header);
    memset(Header->Comment, 0, sizeof(Header->Comment));
    strncpy(Header->Comment,
            "\nDo not edit this file.\n",
            sizeof(Header->Comment)
            );

    Header->Comment[sizeof(Header->Comment) - 1] = '\0';

    CacheInfo = &(Header->ht);
    CacheCount = &(Header->CacheCount);

    CacheHT_Init(CacheInfo, MapStart, CacheSize);

}

static int InitCacheInfo(ConfigFileInfo *ConfigInfo, BOOL Reload)
{
    if( Reload == TRUE )
    {
        if( IsReloadable() )
        {
            ReloadCache();
        } else {
            if( ConfigGetBoolean(ConfigInfo, "OverwriteCache") == FALSE )
            {
                return -1;
            } else {
                CreateNewCache();
                INFO("The existing cache has been overwritten.\n");
            }
        }
    } else {
        CreateNewCache();
    }
    return 0;
}

static void DNSCache_Cleanup(void)
{
    if( CacheFileHandle != INVALID_FILE )
    {
        if(CacheMappingHandle != INVALID_MAP)
        {
            UNMAP_FILE(MapStart, CacheSize);
            DESTROY_MAPPING(CacheMappingHandle);
        }
        CLOSE_FILE(CacheFileHandle);
    }
    if( TtlCtrl != NULL)
    {
        CacheTtlCrtl_Free(TtlCtrl);
    }
    if( MemoryCache && MapStart != NULL )
    {
        CacheHT_Free(CacheInfo);
        SafeFree(MapStart);
    }
    RWLock_Destroy(CacheLock);
}

int DNSCache_Init(ConfigFileInfo *ConfigInfo)
{
    int         _CacheSize = ConfigGetInt32(ConfigInfo, "CacheSize");
    const char  *CacheFile = ConfigGetRawString(ConfigInfo, "CacheFile");
    int         InitCacheInfoState;

    int         OverrideTTL;
    int         TTLMultiple;

    StringList  *ctc = ConfigGetStringList(ConfigInfo, "CacheControl");

    if( ConfigGetBoolean(ConfigInfo, "UseCache") == FALSE )
    {
        return 0;
    }

    CacheParallel = ConfigGetBoolean(ConfigInfo, "CacheParallel");

    IgnoreTTL = ConfigGetBoolean(ConfigInfo, "IgnoreTTL");

    OverrideTTL = ConfigGetInt32(ConfigInfo, "OverrideTTL");
    TTLMultiple = ConfigGetInt32(ConfigInfo, "MultipleTTL");

    if( ctc != NULL || OverrideTTL > -1 || TTLMultiple > 1 )
    {
        TtlCtrl = malloc(sizeof(CacheTtlCtrl));
        if( TtlCtrl == NULL || CacheTtlCrtl_Init(TtlCtrl) != 0 )
        {
            /* CacheTtlCrtl_Init failing (or malloc failing) must not leak the
               control block we just allocated. */
            SafeFree(TtlCtrl);
            return -1;
        }
    }

    atexit(DNSCache_Cleanup);

    if( ctc != NULL )
    {
        CacheTtlCrtl_Add_From_StringList(TtlCtrl, ctc);
    }

    if( OverrideTTL > -1 )
    {
        CacheTtlCrtl_Add(TtlCtrl, "*", TTL_STATE_FIXED, 1, OverrideTTL, TRUE);
    } else {
        if( TTLMultiple < 1 )
        {
            ERRORMSG("Invalid `MultipleTTL'.\n");
        } else if( TTLMultiple > 1 ){
            CacheTtlCrtl_Add(TtlCtrl, "*", TTL_STATE_VARIABLE, TTLMultiple, 0, TRUE);
        }
    }

    CacheSize = CACHE_ROUND_UP(_CacheSize);

    if( CacheSize < 102400 )
    {
        ERRORMSG("Cache size must not less than 102400 bytes.\n");
        return 1;
    }

    if( ConfigGetBoolean(ConfigInfo, "MemoryCache") == TRUE )
    {
        MemoryCache = TRUE;
        MapStart = SafeMalloc(CacheSize);

        if( MapStart == NULL )
        {
            ERRORMSG("Cache initializing failed.\n");
            return 2;
        }

        InitCacheInfoState = InitCacheInfo(ConfigInfo, FALSE);
    } else {
        BOOL FileExists;

        INFO("Cache File : %s\n", CacheFile);

        FileExists = FileIsReadable(CacheFile);

        CacheFileHandle = OPEN_FILE(CacheFile);
        if(CacheFileHandle == INVALID_FILE)
        {
            int ErrorNum = GET_LAST_ERROR();
            char ErrorMessage[320];

            GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

            ERRORMSG("Cache initializing failed : %d : %s.\n", ErrorNum, ErrorMessage);

            return 3;
        }

        CacheMappingHandle = CREATE_FILE_MAPPING(CacheFileHandle, CacheSize);
        if(CacheMappingHandle == INVALID_MAP)
        {
            int ErrorNum = GET_LAST_ERROR();
            char ErrorMessage[320];

            GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

            ERRORMSG("Cache initializing failed : %d : %s.\n", ErrorNum, ErrorMessage);
            return 4;
        }

        MapStart = (char *)MPA_FILE(CacheMappingHandle, CacheSize);
        /* On Linux mmap() fails with MAP_FAILED == (void *)-1, which equals
         * INVALID_MAPPING_FILE. On Windows MapViewOfFile() fails with NULL,
         * which does NOT equal INVALID_MAPPING_FILE, so a NULL return would
         * have slipped past the original check and been treated as a valid
         * mapping -- every later access then dereferences NULL/garbage. Test
         * both sentinel values to stay correct on every supported platform. */
        if(MapStart == INVALID_MAPPING_FILE || MapStart == NULL)
        {
            int ErrorNum = GET_LAST_ERROR();
            char ErrorMessage[320];

            GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

            ERRORMSG("Cache initializing failed : %d : %s.\n", ErrorNum, ErrorMessage);
            return 5;
        }

        if( FileExists == FALSE )
        {
            InitCacheInfoState = InitCacheInfo(ConfigInfo, FALSE);
        } else {
            InitCacheInfoState = InitCacheInfo(ConfigInfo, ConfigGetBoolean(ConfigInfo, "ReloadCache"));
        }
    }

    if( InitCacheInfoState != 0 )
    {
        return 6;
    }

    RWLock_Init(CacheLock);

    /* Synchronization barrier: the cache header (CacheInfo) and the mapped
     * region (MapStart) were written by this thread during initialization
     * *without* holding CacheLock.  Acquire and release the write lock once
     * here so that the happens-before relationship between this
     * initialization and the later lock-protected reads in
     * DNSCacheTTLCountdown_Task is explicit.  This is required for tools such
     * as helgrind to see the ordering (and is harmless at runtime). */
    RWLock_WrLock(CacheLock);
    RWLock_UnWLock(CacheLock);

    Inited = TRUE;

    if( !IgnoreTTL )
    {
        TimedTask_Add(TRUE,
                      FALSE,
                      59000,
                      (TaskFunc)DNSCacheTTLCountdown_Task,
                      NULL,
                      NULL,
                      TRUE
                      );
    }

    return 0;
}

BOOL Cache_IsInited(void)
{
    return Inited;
}

static BOOL IsValidCachedType(DNSRecordType Type)
{
    return  /* raw */
            Type == DNS_TYPE_A ||
            Type == DNS_TYPE_AAAA ||
            Type == DNS_TYPE_HTTPS ||
            Type == DNS_TYPE_TXT ||
            /* labeled names */
            Type == DNS_TYPE_CNAME ||
            Type == DNS_TYPE_PTR ||
            Type == DNS_TYPE_NS ||
            /* Has labeled names */
            Type == DNS_TYPE_MX;
}

static int32_t DNSCache_GetAvailableChunk(uint32_t Length, Cht_Node **Out)
{
    int32_t NodeNumber;
    Cht_Node    *Node;
    uint32_t    RoundedLength = CACHE_ROUND_UP(Length);

    BOOL    NewCreated;

    NodeNumber = CacheHT_FindUnusedNode(CacheInfo, RoundedLength, &Node, MapStart + (*CacheEnd) + RoundedLength, &NewCreated);
    if( NodeNumber >= 0 )
    {
        if( NewCreated == TRUE )
        {
            Node->Offset = (*CacheEnd);
            (*CacheEnd) += RoundedLength;
        }

        memset(MapStart + Node->Offset + Length, 0xFE, RoundedLength - Length);

        *Out = Node;
        return NodeNumber;
    } else {
        *Out = NULL;
        return -1;
    }

}

static Cht_Node *DNSCache_FindFromCache(const char *Content, size_t Length, Cht_Node *Start, time_t CurrentTime)
{
    Cht_Node *Node = Start;

    do{
        Node = CacheHT_Get(CacheInfo, Content, Node, NULL);
        if( Node == NULL )
        {
            return NULL;
        }

        if( IgnoreTTL == TRUE || (CurrentTime - Node->TimeAdded < Node->TTL) )
        {
            /* On reload the whole hash table (including every node's Offset,
               UsedLength and Length) is read verbatim from the on-disk cache
               file. A truncated or corrupted file could carry an Offset that
               points past the end of the mapping; reject such a node as a
               cache miss instead of reading out of bounds. */
            if( Node->Offset >= 0 &&
                (uint32_t)Node->Offset + 1 + (uint32_t)Length <= (uint32_t)CacheSize &&
                memcmp(Content, MapStart + Node->Offset + 1, Length) == 0
              )
            {
                return Node;
            }
        }

    } while( TRUE );

}

static uint32_t DNSCache_CacheMinTTL(const char *Content, size_t Length, uint32_t NewTTL, time_t CurrentTime)
{
    uint32_t RecordTTL = NewTTL;
    Cht_Node *Node = NULL;

    /* Get the smallest, in case of not equal. */
    while( (Node = DNSCache_FindFromCache(Content, Length, Node, CurrentTime)) != NULL )
    {
        uint32_t TTL;

        /* Saturating subtraction: Node->TTL and the elapsed time are both
           unsigned, so an expired node (elapsed >= TTL) would wrap to a
           huge value under modular arithmetic.  Clamp at 0 so an expired
           entry cannot be resurrected with a near-infinite TTL. */
        if( (uint32_t)(CurrentTime - Node->TimeAdded) >= Node->TTL )
        {
            TTL = 0;
        } else {
            TTL = Node->TTL - (uint32_t)(CurrentTime - Node->TimeAdded);
        }

        if( RecordTTL > TTL )
        {
            RecordTTL = TTL;
        }
    }

    Node = NULL;
    while( (Node = DNSCache_FindFromCache(Content, Length, Node, CurrentTime)) != NULL )
    {
        Node->TTL = RecordTTL;
        Node->TimeAdded = CurrentTime;
    }

    return RecordTTL;
}

/* Item: \xFFStrName\x20HexType\x20HexClass\x00(R)Data
   ht: StrName\x20HexType\x20HexClass, NtcTriplet
   https://tools.ietf.org/html/rfc1035 */
static int DNSCache_AddAItemToCache(DnsSimpleParserIterator *i,
                                    time_t CurrentTime,
                                    const CtrlContent *InfectedTtlContent
                                    )
{
    char            Buffer[512]; /* covers most cases */
    char            *Item = Buffer + 1;
    int             Length;

    /* Iterator of `Buffer' */
    char            *BufferItr;

    const CtrlContent   *TtlContent;

    /* Assign start byte of the cache */
    Buffer[0] = CACHE_START;

    /* Assign the name of the cache */
    if( i->GetName(i, Item, sizeof(Buffer) -1) < 0 )
    {
        return -1;
    }

    /* Jump just over the name, right at '\0' */
    BufferItr = Item + strlen(Item);
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -2;
    }

    /* Set record type and class */
    BufferItr += snprintf(BufferItr,
                          sizeof(Buffer) - (BufferItr - Buffer),
                          " %X %X",
                          i->Type,
                          i->Klass
                          );
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -3;
    }

    /* End of name\x20type\x20class triplet */
    BufferItr++;
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -4;
    }

    /* Generate data and store them */
    Length = i->ToCacheData(i,
                            BufferItr,
                            sizeof(Buffer) - (BufferItr - Buffer)
                            );
    if( Length <= 0 )
    {
        return -5;
    }
    BufferItr += Length;
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -6;
    }

    /* The whole cache data generating completed */

    /* Add the cache item to the main cache zone below */

    /* Determine whether the cache item has existed in the main cache zone */
    if(DNSCache_FindFromCache(Item, BufferItr - Item, NULL, CurrentTime) == NULL)
    {
        /* If not, add it */
        {
        int32_t Subscript;
        uint32_t RecordTTL;
        Cht_Node    *Node;

        DEBUG("Add cache: %s\n", Item);

        /* Detemine which TTL scheme will be used */
        if( InfectedTtlContent != NULL )
        {
            switch( InfectedTtlContent->Infection )
            {
                default:
                case TTL_CTRL_INFECTION_AGGRESSIVLY:
                    TtlContent = InfectedTtlContent;
                    break;

                case TTL_CTRL_INFECTION_PASSIVLY:
                    TtlContent = CacheTtlCrtl_Get(TtlCtrl, Item);
                    if( TtlContent == NULL )
                    {
                        TtlContent = InfectedTtlContent;
                    }
                    break;

                case TTL_CTRL_INFECTION_NONE:
                    TtlContent = CacheTtlCrtl_Get(TtlCtrl, Item);
                    break;
            }
        } else {
            TtlContent = CacheTtlCrtl_Get(TtlCtrl, Item);
        }

        if( TtlContent != NULL )
        {
            switch( TtlContent->State )
            {
                case TTL_STATE_NO_CACHE:
                    RecordTTL = 0;
                    break;

                case TTL_STATE_ORIGINAL:
                    RecordTTL = i->GetTTL(i);
                    break;

                default:
                    /* Avoid uint32_t overflow of the Coefficient * TTL product
                       without a 64-bit type (ISO C90 has no `long long`): if
                       the multiplication would exceed 0xFFFFFFFF, saturate to
                       the maximum directly instead of letting it wrap to a tiny
                       value (which would corrupt the cached record's lifetime).
                       Then add the increment with the same saturation. */
                    {
                        uint32_t coeff = TtlContent->Coefficient;
                        uint32_t base  = i->GetTTL(i);
                        uint32_t prod;
                        if( coeff != 0 && base > 0xFFFFFFFFU / coeff )
                        {
                            prod = 0xFFFFFFFFU;
                        }
                        else
                        {
                            prod = coeff * base;
                        }
                        RecordTTL = (prod >= 0xFFFFFFFFU - TtlContent->Increment)
                                    ? 0xFFFFFFFFU
                                    : prod + TtlContent->Increment;
                    }
                    break;
            }
        } else {
            RecordTTL = i->GetTTL(i);
        }

        if( RecordTTL == 0 )
        {
            return 0;
        }

        /* Get a usable chunk and its subscript */
        Subscript = DNSCache_GetAvailableChunk(BufferItr - Buffer, &Node);

        /* If there is a usable chunk */
        if(Subscript >= 0)
        {
            /* Copy the cache to this entry */
            memcpy(MapStart + Node->Offset, Buffer, BufferItr - Buffer);
            Node->UsedLength = BufferItr - Buffer;

            if( CacheParallel )
            {
                /* Exact match: requires trailing '\x0' */
                RecordTTL = DNSCache_CacheMinTTL(Item, strlen(Item) + 1, RecordTTL, CurrentTime);
            }

            /* Assign TTL */
            Node->TTL = RecordTTL;

            Node->TimeAdded = CurrentTime;

            /* Index this entry on the hash table */
            CacheHT_InsertToSlot(CacheInfo, Item, Subscript, Node, NULL);

            ++(*CacheCount);
            DEBUG("DNSCache count: %d, entries: %d, cid: %d\n",
                  *CacheCount,
                  ((struct _Header *)MapStart)->ht.NodeChunk.Used,
                  Subscript
                  );
        } else {
            WARNING("No available cache: %s\n", Item);
            return -1;
        }
        }
    }

    return 0;
}

int DNSCache_AddItemsToCache(MsgContext *MsgCtx, BOOL IsFirst)
{
    IHeader *Header = (IHeader *)MsgCtx;
    char *DnsEntity = IHEADER_TAIL(Header);
    const CtrlContent *TtlContent = NULL;

    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    if(Inited == FALSE) return 0;
    if(!IsFirst && !CacheParallel) return 0;

    if( DnsSimpleParser_Init(&p, DnsEntity, Header->EntityLength, FALSE) != 0 )
    {
        return -1;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        return -2;
    }

    TtlContent =  CacheTtlCrtl_Get(TtlCtrl, Header->Domain);
    RWLock_WrLock(CacheLock);

    while( i.Next(&i) != NULL )
    {
        BOOL RightPurpose = i.Purpose != DNS_RECORD_PURPOSE_UNKNOWN &&
                            i.Purpose != DNS_RECORD_PURPOSE_QUESTION;

        BOOL CachedClass = i.Klass == DNS_CLASS_IN;

        if( RightPurpose && IsValidCachedType(i.Type) && CachedClass )
        {
            DNSCache_AddAItemToCache(&i, time(NULL), TtlContent);
        }
    }

    RWLock_UnWLock(CacheLock);

    return 0;
}

/* State code returned */
static int DNSCache_GetRawRecordsFromCache(__in    const char *Name,
                                           __in    DNSRecordType Type,
                                           __in    DNSRecordClass Klass,
                                           __inout DnsGenerator *g,
                                           __in    time_t CurrentTime
                                           )
{
    int Ret = -100;

    char Name_Type_Class[253 + 1 + 4 + 1 + 4 + 1];

    uint32_t    NewTTL;

    Cht_Node *Node = NULL; /* Important */

    int KeyLength = snprintf(Name_Type_Class,
                             sizeof(Name_Type_Class),
                             "%s %X %X",
                             Name,
                             Type,
                             Klass
                             );

    /* snprintf() returns a negative value on encoding failure. Casting that
       to size_t for the comparison below would turn it into a huge unsigned
       number and defeat this boundary check, letting a negative KeyLength
       reach the cache lookup. Reject negatives explicitly first. */
    if( KeyLength < 0 || KeyLength >= (int)sizeof(Name_Type_Class) )
    {
            return -609;
    }

    DEBUG("Get cache: %s\n", Name_Type_Class);
    do
    {
        Node = DNSCache_FindFromCache(Name_Type_Class,
                                      KeyLength + 1,
                                      Node,
                                      CurrentTime
                                      );

        if( Node == NULL )
        {
            DEBUG("Get cache: N\n");
            break;
        }
        DEBUG("Get cache: Y\n");

        if( Node->TTL != 0 )
        {
            char *CacheItr;
            int iRet;

            /* TTL*/
            if( IgnoreTTL == TRUE )
            {
                NewTTL = Node->TTL;
            } else {
                /* Saturating subtraction: both operands are unsigned, and
                   between the freshness check above and here wall-clock time
                   may have advanced past the node's TTL, which would wrap to a
                   near-infinite value under modular arithmetic.  Clamp at 0 so
                   an expired entry cannot be served with a huge TTL.  Mirrors
                   the handling in DNSCache_CacheMinTTL(). */
                if( (uint32_t)(CurrentTime - Node->TimeAdded) >= Node->TTL )
                {
                    NewTTL = 0;
                } else {
                    NewTTL = Node->TTL - (uint32_t)(CurrentTime - Node->TimeAdded);
                }
            }

            /* A corrupted node from a reloaded cache file could carry a
               UsedLength that runs past the mapping; reject it before we
               compute the data pointer so the generator never reads or
               writes out of bounds. */
            if( Node->Offset < 0 ||
                (uint32_t)Node->Offset + Node->UsedLength > (uint32_t)CacheSize ||
                (uint32_t)Node->Offset + 1 + (uint32_t)KeyLength + 1 > (uint32_t)CacheSize
              )
            {
                break;
            }

            /* Skip key to get data */
            CacheItr = MapStart + Node->Offset + 1 + KeyLength + 1;

            /* Now the data position */
            iRet = g->Generate(g, Name, Type, Klass, CacheItr,
                        MapStart + Node->Offset + Node->UsedLength - CacheItr,
                        NewTTL
                        );
            if( iRet != 0 )
            {
                if( Ret == 0 )
                {
                    INFO("Partial cache used for: %s\n", Name_Type_Class);
                }
                break;
            }
            Ret = iRet;
        }
    } while ( TRUE );
    DEBUG("Get cache: %d\n", Ret);

    return Ret;
}

static Cht_Node *DNSCache_GetCNameFromCache(__in char *Name,
                                            __out char *Buffer,
                                            __in int BufferLength,
                                            __in time_t CurrentTime
                                            )
{
    char Name_Type_Class[253 + 1 + 4 + 1 + 4 + 1];
    Cht_Node *Node = NULL;
    int KeyLength = snprintf(Name_Type_Class,
                             sizeof(Name_Type_Class),
                             "%s %X %X",
                             Name,
                             DNS_TYPE_CNAME,
                             1
                             );

    /* snprintf() returns a negative value on encoding failure. Casting that
       to size_t for the comparison below would turn it into a huge unsigned
       number and defeat this boundary check, letting a negative KeyLength
       reach the cache lookup. Reject negatives explicitly first. */
    if( KeyLength < 0 || KeyLength >= (int)sizeof(Name_Type_Class) )
    {
        return NULL;
    }

    do
    {
        Cht_Node *iNode = DNSCache_FindFromCache(Name_Type_Class,
                                                 KeyLength + 1,
                                                 Node,
                                                 CurrentTime
                                                 );
        if( Node != NULL ) {
            if( iNode != NULL )
            {
                WARNING("1+ CNAME chains: %s\n", Name);
            }
            return Node;
        }

        if( iNode == NULL )
        {
            return NULL;
        }

        Node = iNode;

        /* The CNAME target stored in the cache is an attacker-controllable,
         * NUL-terminated string whose length is only bounded by the on-disk
         * cache file. Copy it with an explicit upper bound so a corrupted or
         * oversized cache entry cannot overflow `Buffer` (a 254-byte stack
         * array at the call site). DNSCache_FindFromCache only bounds the key
         * portion (Offset + 1 + Length); the target that follows it could sit
         * partly or wholly outside the mapping when the cache file is
         * truncated, so also clamp the source read to CacheSize to avoid an
         * out-of-bounds read of the mapping. */
        {
            const char *Src = MapStart + Node->Offset + 1 + strlen(Name_Type_Class) + 1;
            int j;
            int32_t SrcAvail;

            if( Src >= MapStart + CacheSize )
            {
                SrcAvail = 0;
            } else {
                SrcAvail = CacheSize - (int32_t)(Src - MapStart);
            }

            for( j = 0; j < BufferLength - 1 && j < SrcAvail && Src[j] != '\0'; ++j )
            {
                Buffer[j] = Src[j];
            }
            Buffer[j] = '\0';
        }

    } while( TRUE );

}

/* State code returned */
static int DNSCache_GetByQuestion(__inout DnsGenerator *g,
                                  __inout DnsSimpleParser *p,
                                  __in time_t CurrentTime
                                  )
{
    char    Name[253 + 1];

    DnsSimpleParserIterator i;

    if( DnsSimpleParserIterator_Init(&i, p) != 0 )
    {
        return -1;
    }

    if( i.Next(&i) == NULL || i.Purpose != DNS_RECORD_PURPOSE_QUESTION )
    {
        return -2;
    }

    if( i.Klass != DNS_CLASS_IN || !IsValidCachedType(i.Type) )
    {
        return -4;
    }

    if( i.GetName(&i, Name, sizeof(Name)) < 0 )
    {
        return -3;
    }

    RWLock_RdLock(CacheLock);

    /* If the intended type is not DNS_TYPE_CNAME, then first find its cname */
    if( i.Type != DNS_TYPE_CNAME )
    {
        char    CName[253 + 1];
        Cht_Node *Node = NULL;
        int     CNameDepth = 0;

        while( (Node = DNSCache_GetCNameFromCache(Name, CName, sizeof(CName), CurrentTime))
               != NULL
               )
        {
            uint32_t NewTTL;

            /* Guard against CNAME chains that loop (a->a or a->b->a),
               which would otherwise spin forever while holding CacheLock. */
            if( ++CNameDepth > 16 )
            {
                RWLock_UnRLock(CacheLock);
                return -5;
            }

            if( IgnoreTTL == TRUE )
            {
                NewTTL = Node->TTL;
            } else {
                /* Saturating subtraction (see DNSCache_GetRawRecordsFromCache
                   for the rationale): clamp at 0 if the node has since expired
                   so we never emit a near-infinite TTL. */
                if( (uint32_t)(CurrentTime - Node->TimeAdded) >= Node->TTL )
                {
                    NewTTL = 0;
                } else {
                    NewTTL = Node->TTL - (uint32_t)(CurrentTime - Node->TimeAdded);
                }
            }

            if( g->CName(g, Name, CName, NewTTL) != 0 )
            {
                RWLock_UnRLock(CacheLock);
                return -5;
            }

            strcpy(Name, CName);
        }
    }

    if( DNSCache_GetRawRecordsFromCache(Name, i.Type, i.Klass, g, CurrentTime)
        != 0
        )
    {
        RWLock_UnRLock(CacheLock);
        return -6;
    }

    RWLock_UnRLock(CacheLock);
    return 0;
}

/* Content length returned */
int DNSCache_FetchFromCache(MsgContext *MsgCtx, int BufferLength)
{
    IHeader *h = (IHeader *)MsgCtx;
    char *RequestContent = (char *)(h + 1);

    DnsSimpleParser p;
    DnsGenerator g;

    /* The response is generated into a scratch region immediately following the
       request.  RequestContent is 8-byte aligned, but h->EntityLength is the
       client's request length and is frequently odd (ordinary domain names), so
       HereToGenerate can land on a 2-/4-byte boundary.  The DNSHeader overlay
       used by the generator would then be misaligned, which is undefined
       behaviour on strict-alignment platforms and trips UBSan everywhere.  Align
       the scratch pointer up to an 8-byte boundary; the finished response is
       memmove()'d back onto the aligned RequestContent before being sent, so the
       shift is invisible to clients and does not change wire output. */
    char *HereToGenerate = (char *)(((uintptr_t)(RequestContent + h->EntityLength) + 7) & ~(uintptr_t)7);
    int LeftBufferLength = BufferLength - sizeof(IHeader) - (int)(HereToGenerate - RequestContent);

    int ResultLength;

    if( Inited != TRUE )
    {
        return -792;
    }

    if( DnsSimpleParser_Init(&p, RequestContent, h->EntityLength, FALSE) != 0 )
    {
        return -1;
    }

    if( DnsGenerator_Init(&g,
                          HereToGenerate,
                          LeftBufferLength,
                          RequestContent,
                          h->EntityLength,
                          TRUE
                          )
       != 0)
    {
        return -2;
    }

    if( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ANSWER )
    {
        return -5;
    }

    if( DNSCache_GetByQuestion(&g, &p, time(NULL)) != 0 )
    {
        return -3;
    }

    g.Header->Flags.Direction = 1;
    g.Header->Flags.AuthoritativeAnswer = 0;
    g.Header->Flags.RecursionAvailable = 1;
    g.Header->Flags.ResponseCode = 0;
    g.Header->Flags.Type = 0;

    /* hop-by-hop extension:
        EDNS Extensions: https://datatracker.ietf.org/doc/html/rfc6891
        EDNS0: https://datatracker.ietf.org/doc/html/rfc2671
        DNSSEC Indicating: https://datatracker.ietf.org/doc/html/rfc3225
     */
    if( h->EDNSEnabled )
    {
        while( g.CurrentPurpose(&g) != DNS_RECORD_PURPOSE_ADDITIONAL )
        {
            if( g.NextPurpose(&g) == DNS_RECORD_PURPOSE_UNKNOWN )
            {
                return -4;
            }
        }
        if( g.EDns(&g, 1280) != 0 )
        {
            return -4;
        }
    }

    ResultLength = DNSCompress(HereToGenerate, g.Length(&g));
    if( ResultLength < 0 )
    {
        return -6;
    }

    memmove(RequestContent, HereToGenerate, ResultLength);

    h->EntityLength = ResultLength;
    if( MsgContext_SendBack(MsgCtx) < 0 )
    {
        /** TODO: Error handling */
        return -861;
    }

    ShowNormalMessage(h, 'C');
    DomainStatistic_Add(h, STATISTIC_TYPE_CACHE);

    return 0;
}
