#include <string.h>
#include "ipmisc.h"
#include "utils.h"
#include "readline.h"
#include "logs.h"
#include "rwlock.h"

#define SIZE_OF_PATH_BUFFER 384

static int IPMisc_AddBlockFromString(IPMisc *m, const char *Ip)
{
    return IpChunk_Add(&(m->c),
                        Ip,
                        (int)IP_MISC_TYPE_BLOCK,
                        NULL,
                        0
                        );
}

static int IPMisc_AddSubstituteFromString(IPMisc *m,
                                          const char *Ip,
                                          const char *Substituter
                                          )
{
    if( strchr(Ip, ':') != NULL )
    {   /* IPv6 */
        char    IpSubstituter[16];

        /* Mirror the IPv4 branch: reject a substitute address the parser
           could not fully decode.  IPv6AddressToNum() returns 0 (not 16)
           for malformed "::"-abbreviated literals, so treat anything other
           than a full 16-byte address as invalid rather than silently
           installing a wrong substitute. */
        if( IPv6AddressToNum(Substituter, IpSubstituter) != 16 )
        {
            ERRORMSG("Invalid IPv6 substitute address: %s\n", Substituter);
            return -1;
        }

        return IpChunk_Add(&(m->c),
                              Ip,
                              (int)IP_MISC_TYPE_SUBSTITUTE,
                              IpSubstituter,
                              16
                              );
    } else {
        /* IPv4 */
        char    IpSubstituter[4];

        if( IPv4AddressToNum(Substituter, IpSubstituter) <= 0 )
        {
            ERRORMSG("Invalid IPv4 substitute address: %s\n", Substituter);
            return -1;
        }

        return IpChunk_Add(&(m->c),
                             Ip,
                             (int)IP_MISC_TYPE_SUBSTITUTE,
                             IpSubstituter,
                             4
                             );
    }
}

static int IPMisc_Process(IPMisc *m,
                          char *DNSPackage, /* Without TCPLength */
                          int PackageLength
                          )
{
    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    if( DnsSimpleParser_Init(&p, DNSPackage, PackageLength, FALSE) != 0 )
    {
        return IP_MISC_NOTHING;
    }

    if( m->BlockNegative &&
        p._Flags.ResponseCode(&p) != RESPONSE_CODE_NO_ERROR
        )
    {
        return IP_MISC_NEGATIVE_RESULT;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        return IP_MISC_NOTHING;
    }

    i.GotoAnswers(&i);
    while( i.Next(&i) != NULL && i.Purpose == DNS_RECORD_PURPOSE_ANSWER )
    {
        MiscType ActionType = IP_MISC_TYPE_UNKNOWN;
        const char *Data = NULL;
        int DataLength = 0;
        char *RowDataPos;

        if( i.Klass != DNS_CLASS_IN )
        {
            continue;
        }

        switch( i.Type )
        {
        case DNS_TYPE_A:
            DataLength = 4;
            break;
        case DNS_TYPE_AAAA:
            DataLength = 16;
            break;
        default:
            continue;
        }

        RowDataPos = i.RowData(&i);
        /* The RDATA must stay inside the DNS message buffer. Otherwise the
           lookup below reads out of bounds, and a SUBSTITUTE action would
           write out of bounds. */
        if( RowDataPos == NULL ||
            (const char *)RowDataPos + DataLength > DNSPackage + PackageLength )
        {
            continue;
        }
        if( IpChunk_Find(&(m->c),
                         (unsigned char *)RowDataPos,
                         DataLength,
                         (int *)&ActionType,
                         &Data)
            == FALSE )
        {
            continue;
        }

        switch( ActionType )
        {
        case IP_MISC_TYPE_BLOCK:
            return IP_MISC_FILTERED_IP;
            break;

        case IP_MISC_TYPE_SUBSTITUTE:
            memcpy(RowDataPos, Data, DataLength);
            break;

        default:
            break;
        }

    }

    return IP_MISC_NOTHING;
}

static void IPMisc_SetBlockNegative(IPMisc *m, BOOL Value)
{
    m->BlockNegative = Value;
}

static void IPMisc_Free(IPMisc *m)
{
    IpChunk_Free(&(m->c));
}

int IPMisc_Init(IPMisc *m)
{
    if( m == NULL || IpChunk_Init(&(m->c)) != 0 )
    {
        return -1;
    }

    m->BlockNegative = FALSE;

    m->AddBlockFromString = IPMisc_AddBlockFromString;
    m->AddSubstituteFromString = IPMisc_AddSubstituteFromString;
    m->SetBlockNegative = IPMisc_SetBlockNegative;
    m->Process = IPMisc_Process;

    return 0;
}

/** Mapping */

static IPMisc   *CurrIpMiscMapping = NULL;
static RWLock   IpMiscMappingLock = NULL_RWLOCK;
static ConfigFileInfo   *CurrConfigInfo = NULL;

static void IpMiscMapping_Free(IPMisc *ipMiscMapping)
{
    if( ipMiscMapping == NULL )
    {
        return;
    }

    IPMisc_Free(ipMiscMapping);
    SafeFree(ipMiscMapping);
}

static void IpMiscMapping_Cleanup(void)
{
    IpMiscMapping_Free(CurrIpMiscMapping);
    RWLock_Destroy(IpMiscMappingLock);
}

static int LoadIPSubstitutingFromFile(IPMisc *ipMiscMapping, const char *FilePath)
{
    FILE *fp;
    char    Mapping[512];

    if( ipMiscMapping == NULL || FilePath == NULL )
    {
        return 0;
    }

    fp = fopen(FilePath, "r");
    if( fp == NULL )
    {
        return -118;
    }

    while( TRUE )
    {
        ReadLineStatus  Status;

        Status = ReadLine(fp, Mapping, sizeof(Mapping));
        if( Status == READ_FAILED_OR_END )
        {
            break;
        }

        if( Status == READ_DONE )
        {
            char *p, *Itr = NULL, *Itr2 = NULL;

            for( p = Mapping; *p; ++p)
            {
                if( strchr(" \t", *p) != NULL )
                {
                    *p = 0;
                } else if ( Itr == NULL ) {
                    Itr = p;
                } else if ( Itr2 == NULL && *(p - 1) == 0 ) {
                    Itr2 = p;
                }
            }

            if( Itr != NULL && Itr2 != NULL )
            {
                ipMiscMapping->AddSubstituteFromString(ipMiscMapping, Itr, Itr2);
            }else if( Itr != NULL )
            {
                WARNING("IPSubstitutingFile has invalid tuple: %s\n", Mapping);
            }
        } else {
            ReadLine_GoToNextLine(fp);
        }
    }

    fclose(fp);

    return 0;
}

static int IpMiscMapping_Load(void)
{
    IPMisc *IpMiscMapping;
    StringList *BlockIP = ConfigGetStringList(CurrConfigInfo, "BlockIP");
    StringList *IPSubstituting = ConfigGetStringList(CurrConfigInfo, "IPSubstituting");
    StringList *IPSubstitutingFile = ConfigGetStringList(CurrConfigInfo, "IPSubstitutingFile");

    BOOL BlockNegative = ConfigGetBoolean(CurrConfigInfo, "BlockNegativeResponse");

    StringListIterator i;

    int ret = 0;

    if( BlockIP == NULL && IPSubstituting == NULL && IPSubstitutingFile == NULL && !BlockNegative )
    {
        return 0;
    }

    IpMiscMapping = SafeMalloc(sizeof(IPMisc));
    if( IpMiscMapping == NULL )
    {
        return -146;
    }

    if( IPMisc_Init(IpMiscMapping) != 0 )
    {
        ret = -147;
        goto EXIT_1;
    }

    IpMiscMapping->SetBlockNegative(IpMiscMapping, BlockNegative);

    if( BlockIP != NULL )
    {
        const char *Itr;

        if( StringListIterator_Init(&i, BlockIP) != 0 )
        {
            ret = -165;
            goto EXIT_2;
        }

        while( (Itr = i.Next(&i)) != NULL )
        {
            IpMiscMapping->AddBlockFromString(IpMiscMapping, Itr);
        }
    }

    if( IPSubstituting != NULL )
    {
        const char *Itr, *Itr2;

        if( StringListIterator_Init(&i, IPSubstituting) != 0 )
        {
            ret = -176;
            goto EXIT_2;
        }

        Itr = i.Next(&i);
        Itr2 = i.Next(&i);
        while( Itr != NULL && Itr2 != NULL )
        {
            IpMiscMapping->AddSubstituteFromString(IpMiscMapping, Itr, Itr2);

            Itr = i.Next(&i);
            Itr2 = i.Next(&i);
        }

        if( Itr != NULL )
        {
            WARNING("Invalid IPSubstituting: %s\n", Itr);
        }
    }

    if( IPSubstitutingFile != NULL )
    {
        const char *FilePath;

        if( StringListIterator_Init(&i, IPSubstitutingFile) != 0 )
        {
            ret = -176;
            goto EXIT_2;
        }

        while( (FilePath = i.Next(&i)) != NULL )
        {
            char NewPath[SIZE_OF_PATH_BUFFER];

            if( ExpandPathTo(NewPath, SIZE_OF_PATH_BUFFER, FilePath) != 0 )
            {
                ERRORMSG("Failed to expand path: %s.\n", FilePath);
                continue;
            }
            if( LoadIPSubstitutingFromFile(IpMiscMapping, NewPath) != 0 )
            {
                ERRORMSG("Failed loading: %s.\n", FilePath);
            }
        }
    }

    RWLock_WrLock(IpMiscMappingLock);

    IpMiscMapping_Free(CurrIpMiscMapping);
    CurrIpMiscMapping = IpMiscMapping;

    RWLock_UnWLock(IpMiscMappingLock);

    INFO("Loading IPSubstituting(File)s completed.\n");

    return 0;

EXIT_2:
    /* The load failed partway through: discard the half-built mapping we
       allocated locally. Do NOT free CurrIpMiscMapping here, it is still the
       live mapping in use by concurrent readers (freeing it would be a
       use-after-free). */
    IPMisc_Free(IpMiscMapping);
    SafeFree(IpMiscMapping);
    return ret;

EXIT_1:
    SafeFree(IpMiscMapping);

   return ret;
}

int IpMiscMapping_Init(ConfigFileInfo *ConfigInfo)
{
    int ret;
    RWLock_Init(IpMiscMappingLock);
    CurrConfigInfo = ConfigInfo;

    ret = IpMiscMapping_Load();
    if( ret == 0 )
    {
        atexit(IpMiscMapping_Cleanup);
    }

    return ret;
}

void IpMiscMapping_Update(void)
{
    if ( ConfigGetBoolean(CurrConfigInfo, "ReloadIPSubstituting") )
    {
        IpMiscMapping_Load();
    }
}

int IPMiscMapping_Process(MsgContext *MsgCtx)
{
    IHeader *h = (IHeader *)MsgCtx;
    int ret;

    if( CurrIpMiscMapping == NULL )
    {
        return IP_MISC_NOTHING;
    }

    RWLock_RdLock(IpMiscMappingLock);

    ret = CurrIpMiscMapping->Process(CurrIpMiscMapping,
                                   IHEADER_TAIL(h),
                                   h->EntityLength
                                   );

    RWLock_UnRLock(IpMiscMappingLock);

    return ret;
}
