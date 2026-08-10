#include <string.h>
#include <ctype.h>
#include "ipchunk.h"
#include "hostscontainer.h"
#include "logs.h"

typedef struct _TableNode TableNode;

struct _TableNode{
    const TableNode *Next;
    HostsRecordType Type;
    const void      *Data;
};

PRIFUNC HostsRecordType HostsContainer_DetermineType(const char *IPOrCName)
{
    if( IPOrCName == NULL )
    {
        return HOSTS_TYPE_UNKNOWN;
    }

    /* Good IP List */
    if( *IPOrCName == '<' && IPOrCName[strlen(IPOrCName) - 1] == '>' )
    {
        return HOSTS_TYPE_GOOD_IP_LIST;
    }

    /* A host IPOrCName started with "@@ " is excluded */
    if( *IPOrCName == '@' && *(IPOrCName + 1) == '@' )
    {
        return HOSTS_TYPE_EXCLUEDE;
    }

    if( isxdigit(*IPOrCName) )
    {
        const char *Itr;
        /* Check if it is IPv6 */
        if( strchr(IPOrCName, ':') != NULL )
        {
            return HOSTS_TYPE_AAAA;
        }

        /* Check if it is CNAME */
        for(Itr = IPOrCName; *Itr != '\0'; ++Itr)
        {
            if( isalpha(*Itr) || *Itr == '-' )
            {
                return HOSTS_TYPE_CNAME;
            }
        }

        for(Itr = IPOrCName; *Itr != '\0'; ++Itr)
        {
            if( isdigit(*Itr) || *Itr == '.' )
            {
                return HOSTS_TYPE_A;
            }
        }

        return HOSTS_TYPE_UNKNOWN;

    } else {

        if( *IPOrCName == ':' )
        {
            return HOSTS_TYPE_AAAA;
        }

        for(; *IPOrCName != '\0'; ++IPOrCName)
        {
            if( !isalnum(*IPOrCName) && *IPOrCName != '-' && *IPOrCName != '.' )
            {
                return HOSTS_TYPE_UNKNOWN;
            }
        }

        return HOSTS_TYPE_CNAME;
    }
}

/*
 If Func == NULL:
    Return NULL : No match found;
    Otherwise : A match found;

 If Func != NULL:
    Return NULL : Func returned non-zero at a call or no match found;
    Otherwise : Func returned zero at every call and at least one match found;
*/
PUBFUNC const void *HostsContainer_Find(HostsContainer  *Container,
                                        const char      *Name,
                                        HostsRecordType Type,
                                        HostsFindFunc   Func,
                                        void            *Arg
                                        )
{
    const TableNode **Matched = NULL;
    const TableNode *IP = NULL;
    const TableNode *IP4to6 = NULL;

    if( !StringChunk_Match(&(Container->Mappings), Name, NULL, (void **)&Matched, NULL, NULL) )
    {
        return NULL;
    }

    if( Matched != NULL )
    {
        IP = *Matched;
    }

    while( IP != NULL )
    {
        if( Type == HOSTS_TYPE_UNKNOWN || IP->Type == Type )
        {
            Type = IP->Type;
            break;
        }
        if( Type == HOSTS_TYPE_AAAA && IP->Type == HOSTS_TYPE_A && IP4to6 == NULL )
        {
            IP4to6 = IP;
        }

        IP = IP->Next;
    }

    if( IP == NULL )
    {
        IP = IP4to6;
    }

    if( IP != NULL )
    {
        if( Func != NULL )
        {
            int i = 1;

            if( Func(i++, Type, IP->Data, Arg) != 0 )
            {
                return NULL;
            }
        }
    }

    return IP;
}

PRIFUNC const void *HostsContainer_FindExist(HostsContainer  *Container,
                                            const char      *Name
                                            )
{
    const TableNode **Matched = NULL;
    const TableNode *IP = NULL;

    if( !StringChunk_Match_Exactly(&(Container->Mappings), Name, NULL, (void **)&Matched, NULL, NULL) )
    {
        return NULL;
    }

    if( Matched != NULL )
    {
        IP = *Matched;
    }

    if( IP != NULL )
    {
        return IP;
    } else {
        return NULL;
    }
}

PRIFUNC int HostsContainer_AddNode(HostsContainer   *Container,
                                   const char       *Name,
                                   HostsRecordType  Type,
                                   const void       *Data,
                                   int              DataLength
                                   )
{
    TableNode   n, *s = NULL, *Exist = NULL;

    if( Data != NULL )
    {
        if( Type == HOSTS_TYPE_A || Type == HOSTS_TYPE_AAAA )
        {
            StableBufferIterator IPI;
            IpAddr *ipAddr;

            if(StableBufferIterator_Init(&IPI, &(Container->TableIPAddr)) != 0)
            {
                return -170;
            }
            IPI.Reset(&IPI);
            while( (ipAddr = IPI.NextBlock(&IPI)) != NULL )
            {
                int i, BytesOfMetaInfo;
                BytesOfMetaInfo = IPI.CurrentBlockUsed(&IPI);
                for( i = 0; (i + 1) * (int)sizeof(IpAddr) <= BytesOfMetaInfo; ++i, ++ipAddr )
                {
                    const IpAddr *NewIp = (const IpAddr *)Data;

                    /* `Zone` is a pointer: comparing the whole struct with
                       memcmp would compare pointer VALUES, which differ
                       between a freshly parsed IpAddr (Zone on the caller's
                       stack) and a stored one (Zone rebound into the
                       persistent Container->Table). Compare the wire address
                       and the Zone string content instead, so de-duplication
                       of hosts entries actually works. */
                    if( memcmp(ipAddr->Addr, NewIp->Addr, sizeof(ipAddr->Addr)) == 0 &&
                        IpAddr_HasZone(ipAddr) == IpAddr_HasZone(NewIp) &&
                        (!IpAddr_HasZone(ipAddr) ||
                         strcmp(ipAddr->Zone, NewIp->Zone) == 0)
                      )
                    {
                        goto OUT_SEARCH;
                    }
                }
            }

OUT_SEARCH:
            if( ipAddr == NULL )
            {
                ipAddr = Container->TableIPAddr.Add(&(Container->TableIPAddr),
                                                      Data,
                                                      DataLength,
                                                      TRUE
                                                      );

                if( ipAddr == NULL )
                {
                    /* Out of memory: TableIPAddr.Add() failed, so there is no
                       valid IpAddr to rebind a Zone onto. Bail out instead of
                       dereferencing a NULL pointer at the IpAddr_HasZone call
                       below. */
                    return -171;
                }
            }

            /* `ipAddr` now lives inside TableIPAddr, but IpAddr_Parse points
               `Zone` at the caller's string (e.g. a stack buffer in
               HostsContainer_Load). Copy that Zone string into the persistent
               Container->Table and rebind the pointer, otherwise the stored
               IpAddr keeps a dangling pointer. Sentinel Zones (Z0/Z4/Z6noz)
               are compile-time constants and need no copy. */
            if( ipAddr != NULL && IpAddr_HasZone((const IpAddr *)ipAddr) )
            {
                const char *z = Container->Table.Add(&(Container->Table),
                                                      ((const IpAddr *)ipAddr)->Zone,
                                                      strlen(((const IpAddr *)ipAddr)->Zone) + 1,
                                                      TRUE
                                                      );
                if( z == NULL )
                {
                    return -172;
                }
                ((IpAddr *)ipAddr)->Zone = z;
            }

            n.Data = ipAddr;
        } else {
            n.Data = Container->Table.Add(&(Container->Table),
                                          Data,
                                          DataLength,
                                          TRUE
                                          );
        }

        if( n.Data == NULL )
        {
            return -171;
        }
    } else {
        n.Data = NULL;
    }

    n.Type = Type;

    Exist = (TableNode *)HostsContainer_FindExist(Container, Name);
    if( Exist == NULL )
    {
        n.Next = NULL;
        s = Container->Table.Add(&(Container->Table),
                                 &n,
                                 sizeof(TableNode),
                                 TRUE
                                 );
        if( s == NULL )
        {
            return -201;
        }

        if( StringChunk_Add(&(Container->Mappings),
                            Name,
                            &s,
                            sizeof(TableNode *)
                            )
            != 0 )
        {
            return -212;
        }
    } else {
        n.Next = Exist->Next;
        s = Container->Table.Add(&(Container->Table),
                                 &n,
                                 sizeof(TableNode),
                                 TRUE
                                 );
        if( s == NULL )
        {
            return -213;
        }

        Exist->Next = s;
    }

    return 0;
}

PRIFUNC int HostsContainer_AddIP(HostsContainer *Container,
                                 HostsRecordType  Type,
                                 const char *IP,
                                 const char *Domain
                                )
{
    IpAddr ipAddr;

    IpAddr_Parse(IP, &ipAddr);

    return HostsContainer_AddNode(Container,
                                  Domain,
                                  Type,
                                  &ipAddr,
                                  sizeof(IpAddr)
                                  );
}

PRIFUNC int HostsContainer_AddCName(HostsContainer *Container,
                                    const char *CName,
                                    const char *Domain
                                    )
{
    return HostsContainer_AddNode(Container,
                                  Domain,
                                  HOSTS_TYPE_CNAME,
                                  CName,
                                  strlen(CName) + 1
                                  );
}

PRIFUNC int HostsContainer_AddGoodIpList(HostsContainer *Container,
                                         const char *ListName,
                                         const char *Domain
                                         )
{
    char            Trimed[128];

    Trimed[0] = '\0';

    /* Only trust the conversion when sscanf actually matched the <...> pattern.
       Otherwise Trimed would keep its (uninitialized) stack contents and
       strlen() below could read out of bounds. */
    if( sscanf(ListName, "<%127[^>]", Trimed) != 1 )
    {
        return -1;
    }

    return HostsContainer_AddNode(Container,
                                  Domain,
                                  HOSTS_TYPE_GOOD_IP_LIST,
                                  Trimed,
                                  strlen(Trimed) + 1
                                  );
}

PRIFUNC int HostsContainer_AddExcluded(HostsContainer *Container,
                                       const char *Domain
                                       )
{
    return HostsContainer_AddNode(Container,
                                  Domain,
                                  HOSTS_TYPE_EXCLUEDE,
                                  NULL,
                                  0
                                  );
}

PRIFUNC HostsRecordType HostsContainer_Add(HostsContainer *Container,
                                           const char *IPOrCName,
                                           const char *Domain
                                           )
{
    HostsRecordType  Type = HostsContainer_DetermineType(IPOrCName);

    switch( Type )
    {
        case HOSTS_TYPE_AAAA:
        case HOSTS_TYPE_A:
            if( HostsContainer_AddIP(Container, Type, IPOrCName, Domain) != 0 )
            {
                return HOSTS_TYPE_UNKNOWN;
            } else {
                return Type;
            }
            break;

        case HOSTS_TYPE_CNAME:
            if( HostsContainer_AddCName(Container, IPOrCName, Domain) != 0 )
            {
                return HOSTS_TYPE_UNKNOWN;
            } else {
                return HOSTS_TYPE_CNAME;
            }
            break;

        case HOSTS_TYPE_EXCLUEDE:
            if( HostsContainer_AddExcluded(Container, Domain) != 0 )
            {
                return HOSTS_TYPE_UNKNOWN;
            } else {
                return HOSTS_TYPE_EXCLUEDE;
            }
            break;

        case HOSTS_TYPE_GOOD_IP_LIST:
            if( HostsContainer_AddGoodIpList(Container, IPOrCName, Domain) != 0 )
            {
                return HOSTS_TYPE_UNKNOWN;
            } else {
                return HOSTS_TYPE_GOOD_IP_LIST;
            }
            break;

        default:
            INFO("Unrecognisable host : %s %s\n", IPOrCName, Domain);
            return HOSTS_TYPE_UNKNOWN;
            break;
    }
}

PUBFUNC HostsRecordType HostsContainer_Load(HostsContainer *Container,
                                            const char *MetaLine
                                            )
{
    char IPOrCName[DOMAIN_NAME_LENGTH_MAX + 1];
    char Domain[DOMAIN_NAME_LENGTH_MAX + 1];

    if( sscanf(MetaLine,
               "%" STRINGIZINGINT(DOMAIN_NAME_LENGTH_MAX) "s%" STRINGIZINGINT(DOMAIN_NAME_LENGTH_MAX) "s",
               IPOrCName,
               Domain
               )
     != 2 )
    {
        INFO("Unrecognisable host : %s, it may be too long.\n", MetaLine);
        return HOSTS_TYPE_UNKNOWN;
    }

    return HostsContainer_Add(Container, IPOrCName, Domain);
}

PUBFUNC void HostsContainer_Free(HostsContainer *Container)
{
    StringChunk_Free(&(Container->Mappings), TRUE);
    Container->Table.Free(&(Container->Table));
    Container->TableIPAddr.Free(&(Container->TableIPAddr));
}

int HostsContainer_Init(HostsContainer *Container)
{
    if( StringChunk_Init(&(Container->Mappings), NULL) != 0 )
    {
        return -2;
    }

    if( StableBuffer_Init(&(Container->Table)) != 0 )
    {
        StringChunk_Free(&(Container->Mappings), TRUE);
        return -6;
    }

    if( StableBuffer_Init(&(Container->TableIPAddr)) != 0 )
    {
        StringChunk_Free(&(Container->Mappings), TRUE);
        Container->Table.Free(&(Container->Table));
        return -7;
    }

    Container->Load = HostsContainer_Load;
    Container->Find = HostsContainer_Find;
    Container->Free = HostsContainer_Free;

    return 0;
}
