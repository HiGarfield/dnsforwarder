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
    /* ::ffff prefix.  Byte-wise writes avoid a strict-aliasing-violating
       uint16_t* store into an unsigned-char buffer. */
    Addr[10] = 0xff;
    Addr[11] = 0xff;
}

void IpAddr_From4(const unsigned char Addr[4], IpAddr *ipAddr)
{
    ipAddr->Zone = Z4;
    IpAddr_SetPrefix4(ipAddr->Addr);
    /* Copy the 4 octets without going through a uint32_t* : IpAddr_From4 is
       routinely fed DNS wire data (e.g. by IpChunk_Find) whose bytes can sit at
       an unaligned address.  *(uint32_t *)Addr there is both a strict-aliasing
       violation and an unaligned load that SIGBUSes on strict-alignment
       targets.  memcpy is well defined for every alignment. */
    memcpy(ipAddr->Addr + 12, Addr, 4);
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
            if( IPv4AddressToNum(s, ipAddr->Addr + 12) != 4 )
            {
                /* Malformed IPv4 literal: leave the IpAddr in the same
                   pristine state as a non-match so IpAddr_IsValid() cannot
                   report this half-written struct as a valid address. */
                ipAddr->Zone = Z0;
                memset(ipAddr->Addr, 0, 16);
                return -1;
            }
            return 0;
        case ':':
            p = strchr(p, '%');
            if( p == NULL )
            {
                ipAddr->Zone = Z6noz;
            } else {
                ipAddr->Zone = p + 1;
            }
            if( IPv6AddressToNum(s, ipAddr->Addr) != 16 )
            {
                ipAddr->Zone = Z0;
                memset(ipAddr->Addr, 0, 16);
                return -1;
            }
            return 0;
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

    /* A query key built by IpChunk_Find from raw DNS answer bytes never
       carries a scope zone (RFC 6874), so an entry that keeps its zone can
       never compare equal to a query key and is silently dead.  Strip the
       zone for every IPv6 entry, single-IP and CIDR alike.  The old code
       stripped it only for prefixed entries, so a zone-qualified single IP
       (e.g. "fe80::1%eth0") was stored with its zone and never matched any
       query, while the prefixed form (zone stripped) did match. */
    if( IpAddr_Is6(ipAddr) )
    {
        ipSet->Ip.Zone = Z6noz;
    }

    if( p != NULL && *p )
    {
        n = atoi(p);
        if( n < 0 )
        {
            /* A negative prefix length (e.g. "10.0.0.0/-5") is meaningless.
               Reject the entry instead of storing PrefixBits = -1, which would
               be accepted by IpChunk_Add yet could never match any query key
               (IpChunk_Find only builds keys with PrefixBits >= 0).  Such a
               silent dead rule makes a configured block/substitution vanish
               without any diagnostic.  Behaviour matches the n > L clamp below:
               out-of-range input is a parse failure, not a zeroed/garbage entry. */
            return -1;
        } else if( n > L ) {
            n = L;
        }

        L = n;
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


static int Contain(const void *One, const void *Two)
{
    const IpElement *New = (const IpElement *)One;
    const IpElement *Elm = (const IpElement *)Two;
    const IpSet *ipSetNew = &(New->IpSet);
    const IpSet *ipSetElm = &(Elm->IpSet);
    const IpAddr *ipAddrNew = &(ipSetNew->Ip);
    const IpAddr *ipAddrElm = &(ipSetElm->Ip);
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
        const unsigned char *bn = ipAddrNew->Addr;
        const unsigned char *be = ipAddrElm->Addr;
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
            /* bn/be point into IpAddr.Addr (an unsigned char array inside the
               BST keys).  That array sits at an unknown offset inside the
               struct, so a *(uint32_t *) cast is both a strict-aliasing
               violation and a potentially unaligned load (SIGBUS on strict-
               alignment targets).  Read through memcpy, which is defined for
               every alignment. */
            uint32_t u32New, u32Elm, mask, rawNew, rawElm;
            mask = htonl(~(~0U >> cmpBits));
            memcpy(&rawNew, bn, 4);
            memcpy(&rawElm, be, 4);
            u32New = rawNew & mask;
            u32Elm = rawElm & mask;
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
    /* Contain has the exact CompareFunc signature (const void *): the old
       (CompareFunc) cast hid a function-pointer type mismatch that
       -fsanitize=function flags as UB (every IpChunk_Find lookup through
       Bst_Search used to trip it). */
    if( Bst_Init(&(ic->AddrChunk), sizeof(IpElement), Contain) != 0 )
    {
        return -1;
    }

    if( Bst_Init(&(ic->CidrChunk), sizeof(IpElement), Contain) != 0 )
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
