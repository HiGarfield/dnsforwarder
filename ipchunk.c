#include <string.h>
#include "utils.h"
#include "ipchunk.h"

static const char *Z0 = NULL;
static const char *Z4 = "\x01";
static const char *Z6noz = "\x02";

/*
IPv6: https://datatracker.ietf.org/doc/html/rfc8200
Zone: https://datatracker.ietf.org/doc/html/rfc6874
CIDR: https://datatracker.ietf.org/doc/html/rfc4632
      https://datatracker.ietf.org/doc/html/rfc4291#section-2.3
*/

int IpAddr_BitLength(const IpAddr *ipAddr)
{
    if( ipAddr->Zone == Z0 )
    {
        return 0;
    } else if( ipAddr->Zone == Z4 )
    {
        return 32;
    }

    return 128;
}

int IpAddr_Is6(const IpAddr *ipAddr)
{
    return ipAddr->Zone != Z0 && ipAddr->Zone != Z4;
}

int IpAddr_HasZone(const IpAddr *ipAddr)
{
    return IpAddr_Is6(ipAddr) && ipAddr->Zone != Z6noz;
}

int IpAddr_IsValid(const IpAddr *ipAddr)
{
    return ipAddr->Zone != Z0;
}

static void IpAddr_SetPrefix4(unsigned char Addr[16])
{
    memset(Addr, 0, 10);
    *(uint16_t *)(Addr + 10) = 0xffff;
}

void IpAddr_From4(const unsigned char Addr[4], IpAddr *ipAddr)
{
    ipAddr->Zone = Z4;
    IpAddr_SetPrefix4(ipAddr->Addr);
    *(uint32_t *)(ipAddr->Addr + 12) = *(uint32_t *)Addr;
}

void IpAddr_From6(const unsigned char Addr[16], IpAddr *ipAddr)
{
    ipAddr->Zone = Z6noz;
    memcpy(ipAddr->Addr, Addr, 16);
}

int IpAddr_Parse(const char *s, IpAddr *ipAddr)
{
    const char *p = s;

    for(; *p; ++p)
    {
        switch( *p )
        {
        case '.':
            ipAddr->Zone = Z4;
            IpAddr_SetPrefix4(ipAddr->Addr);
            return IPv4AddressToNum(s, ipAddr->Addr + 12) != 4;
        case ':':
            p = strchr(p, '%');
            if( p == NULL )
            {
                ipAddr->Zone = Z6noz;
            } else {
                ipAddr->Zone = p + 1;
            }
            return IPv6AddressToNum(s, ipAddr->Addr) != 16;
        case '%':
            break;
        }
    }

    ipAddr->Zone = Z0;
    memset(ipAddr->Addr, 0, 16);
    return -1;
}

BOOL IpSet_IsSingleIp(const IpSet *ipSet)
{
    return ipSet->PrefixBits != 0 && ipSet->PrefixBits == IpAddr_BitLength(&(ipSet->Ip));
}

int IpSet_Parse(const char *s, const char *p, IpSet *ipSet)
{
    int n, L;
    IpAddr *ipAddr = &(ipSet->Ip);

    if( IpAddr_Parse(s, ipAddr) != 0 )
    {
        return -1;
    }

    L = IpAddr_BitLength(ipAddr);

    if( p != NULL && *p )
    {
        n = atoi(p);
        if( n < 0 )
        {
            n = -1;
        } else if( n > L ) {
            n = L;
        }

        L = n;
        if( IpAddr_Is6(ipAddr) )
        {
            ipSet->Ip.Zone = Z6noz;
            L += 10;
        }
        if( L < 16 )
        {
            int i = 0;
            for( ; L > 0; L -= 8, i++ )
            {
                ipAddr->Addr[i] &= ~(0xff >> (L >= 8 ? 8 : L));
            }
        }
    } else {
        n = L;
    }

    ipSet->PrefixBits = n;

    return 0;
}


static int Contain(IpElement *New, IpElement *Elm)
{
    IpSet *ipSetNew = &(New->IpSet);
    IpSet *ipSetElm = &(Elm->IpSet);
    IpAddr *ipAddrNew = &(ipSetNew->Ip);
    IpAddr *ipAddrElm = &(ipSetElm->Ip);
    int BitsNew;
    int BitsElm;

    if( IpAddr_IsValid(ipAddrElm) == FALSE )
    {
        return -1;
    }

    BitsNew = IpAddr_BitLength(ipAddrNew);
    BitsElm = IpAddr_BitLength(ipAddrElm);

    /* 1st: type */
    if( BitsNew != BitsElm )
    {
        return  BitsNew - BitsElm;
    } else {
        unsigned char *bn = ipAddrNew->Addr;
        unsigned char *be = ipAddrElm->Addr;
        int prefixBitsNew = ipSetNew->PrefixBits;
        int prefixBitsElm = ipSetElm->PrefixBits;
        /* Compare networks masked to the SHORTER of the two prefix lengths.
           Masking to only the longer (existing) prefix previously discarded
           the bytes where two ranges differ (e.g. 10.0.0.0/8 vs 10.1.0.0/16),
           so they compared equal and one range was silently dropped during
           Bst_Add. */
        int cmpBits = prefixBitsNew < prefixBitsElm ? prefixBitsNew : prefixBitsElm;
        int ret = 0;

        if( BitsElm == 32 )
        {
            bn += 12;
            be += 12;
        }

        while( cmpBits >= 32 )
        {
            ret = memcmp(bn, be, 4);
            if( ret != 0 )
            {
                return ret;
            }
            bn += 4;
            be += 4;
            cmpBits -= 32;
        }
        if( cmpBits > 0 )
        {
            uint32_t u32New, u32Elm, mask;
            mask = htonl(~(~0U >> cmpBits));
            u32New = *(uint32_t *)bn & mask;
            u32Elm = *(uint32_t *)be & mask;
            ret = (u32New > u32Elm) - (u32New < u32Elm);
        }

        /* Same network prefix: order by prefix length so two distinct ranges
           that share a network become distinct BST nodes (no false duplicate
           or data loss). */
        if( ret == 0 )
        {
            if( prefixBitsNew != prefixBitsElm )
            {
                return (prefixBitsNew > prefixBitsElm) - (prefixBitsNew < prefixBitsElm);
            }

            /* Exact same network and prefix: distinguish by zone. */
            if( IpAddr_HasZone(ipAddrElm) )
            {
                if( IpAddr_HasZone(ipAddrNew) )
                {
                    return strcmp(ipAddrNew->Zone, ipAddrElm->Zone);
                }
                return 1;
            }
            else if( IpAddr_HasZone(ipAddrNew) )
            {
                return -1;
            }
        }

        return ret;
    }
}


void IpChunk_Free(IpChunk *ic)
{
    ic->AddrChunk.Free(&(ic->AddrChunk));
    ic->CidrChunk.Free(&(ic->CidrChunk));
    ic->Datas.Free(&(ic->Datas));
    ic->Extra.Free(&(ic->Extra));
}

int IpChunk_Init(IpChunk *ic)
{
    if( Bst_Init(&(ic->AddrChunk), sizeof(IpElement), (CompareFunc)Contain) != 0 )
    {
        return -1;
    }

    if( Bst_Init(&(ic->CidrChunk), sizeof(IpElement), (CompareFunc)Contain) != 0 )
    {
        goto EXIT_1;
    }

    if( StableBuffer_Init(&(ic->Datas)) != 0 )
    {
        goto EXIT_2;
    }

    if( StableBuffer_Init(&(ic->Extra)) != 0 )
    {
        goto EXIT_3;
    }

    return 0;

EXIT_3:
    ic->Datas.Free(&(ic->Datas));
EXIT_2:
    ic->CidrChunk.Free(&(ic->CidrChunk));
EXIT_1:
    ic->AddrChunk.Free(&(ic->AddrChunk));
    return -1;
}

int IpChunk_Add(IpChunk *ic,
                const char *Ip,
                int Type,
                const void *Data,
                uint32_t DataLength
                )
{
    char *p;
    IpElement   New;
    const IpElement   *elm;

    char *ip = ic->Extra.Add(&(ic->Extra), Ip, strlen(Ip) + 1, FALSE);
    if( ip == NULL )
    {
        return -1;
    }

    p = ip;
    for(; *p; ++p)
    {
        if( *p == '/' )
        {
            *p = 0;
            p++;
            break;
        }
    }

    if( IpSet_Parse(ip, p, &(New.IpSet)) != 0 )
    {
        return -1;
    }

    New.Type = Type;
    New.Data = NULL;

    if( Data != NULL )
    {
        New.Data = ic->Datas.Add(&(ic->Datas), Data, DataLength, TRUE);
        if( New.Data == NULL )
        {
            /* The additional (SUBSTITUTE) data could not be stored. Do not
               register the rule with a NULL data pointer: IpChunk_Find would
               hand NULL back to ipmisc.c, which then does
               memcpy(RowDataPos, NULL, DataLength) on the SUBSTITUTE branch
               and crash. Reject the addition instead. */
            return -1;
        }
    }

    if( IpSet_IsSingleIp(&(New.IpSet)) )
    {
        elm = ic->AddrChunk.Add(&(ic->AddrChunk), &New);
    } else {
        elm = ic->CidrChunk.Add(&(ic->CidrChunk), &New);
    }

    return elm == NULL;
}

BOOL IpChunk_Find(IpChunk *ic, unsigned char *Ip, int IpBytes, int *Type, const char **Data)
{
    IpElement   Key;
    const IpElement *Result = NULL;
    int totalBits;
    int L;

    if( ic == NULL )
    {
        return FALSE;
    }

    switch( IpBytes )
    {
    case 4:
        IpAddr_From4(Ip, &(Key.IpSet.Ip));
        totalBits = 32;
        break;
    case 16:
        IpAddr_From6(Ip, &(Key.IpSet.Ip));
        totalBits = 128;
        break;
    default:
        return FALSE;
    }

    Key.Type = 0;
    Key.Data = NULL;

    /* Exact single-IP match first. */
    Key.IpSet.PrefixBits = totalBits;
    Result = ic->AddrChunk.Search(&(ic->AddrChunk), &Key, NULL);
    if( Result == NULL )
    {
        /* Longest-prefix match against the CIDR chunk. The comparator now
           orders ranges by (network, prefix length), so a query is contained
           in a stored CIDR exactly when the key built with that CIDR's prefix
           length compares equal. Search from the full address downwards so the
           most specific (longest) matching range wins. */
        for( L = totalBits; L >= 0; --L )
        {
            Key.IpSet.PrefixBits = L;
            Result = ic->CidrChunk.Search(&(ic->CidrChunk), &Key, NULL);
            if( Result != NULL )
            {
                break;
            }
        }
    }

    if( Result == NULL )
    {
        return FALSE;
    } else {
        if( Type != NULL )
        {
            *Type = Result->Type;
        }

        if( Data != NULL )
        {
            *Data = Result->Data;
        }

        return TRUE;
    }
}
