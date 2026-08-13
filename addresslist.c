#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <ws2tcpip.h>
#include "addresslist.h"
#include "common.h"
#include "utils.h"

int AddressList_Init(AddressList *a)
{
    if( a == NULL )
    {
        return 0;
    }

    if( Array_Init(&(a->AddressList), sizeof(Address_Type), 8, FALSE, NULL) != 0 )
    {
        return -1;
    }

    a->Counter = 0;
    return 0;
}


int AddressList_Add(AddressList *a, const Address_Type *Addr)
{
    if( a == NULL )
    {
        return -1;
    }

    if( Array_PushBack(&(a->AddressList), Addr, NULL) < 0 )
    {
        return -1;
    } else {
        return 0;
    }

}

sa_family_t AddressList_ConvertFromString(Address_Type *Out, const char *Addr_Port, int DefaultPort)
{
    sa_family_t Family;

    memset(Out, 0, sizeof(Address_Type));

    Family = GetAddressFamily(Addr_Port);
    Out->family = Family;

    switch( Family )
    {
        case AF_INET6:
            {
                char        Addr[LENGTH_OF_IPV6_ADDRESS_ASCII + 1] = {0};
                in_port_t   Port;
                const char  *PortPos;

                memset(Addr, 0, sizeof(Addr));

                PortPos = strchr(Addr_Port, ']');
                if( PortPos == NULL )
                {
                    return AF_UNSPEC;
                }

                /* LENGTH_OF_IPV6_ADDRESS_ASCII = 45 */
                sscanf(Addr_Port + 1, "%45[^]]", Addr);

                PortPos = strchr(PortPos, ':');
                /* sscanf() leaves Port untouched when the text after ':' is
                   not a number (e.g. "[::1]:" or "[::1]:http"). Seed it with
                   the default so a malformed port can never make the server
                   talk to a random stack-garbage port. */
                Port = DefaultPort;
                if( PortPos != NULL )
                {
                    if( sscanf(PortPos + 1, "%hu", &Port) != 1 )
                    {
                        Port = DefaultPort;
                    }
                }

                /* Validate the literal with inet_pton instead of trusting
                   IPv6AddressToNum(), which silently turns garbage such as
                   "[foo]:53" or "[1.2.3.4]:53" into a malformed address. */
                if( inet_pton(AF_INET6, Addr, &(Out->Addr.Addr6.sin6_addr)) != 1 )
                {
                    return AF_UNSPEC;
                }

                Out->Addr.Addr6.sin6_family = Family;
                Out->Addr.Addr6.sin6_port = htons(Port);

                return AF_INET6;
            }
            break;

        case AF_INET:
            {
                char        Addr[LENGTH_OF_IPV4_ADDRESS_ASCII + 1] = {0};
                in_port_t   Port;
                const char  *PortPos;

                memset(Addr, 0, sizeof(Addr));

                PortPos = strchr(Addr_Port, ':');

                /* LENGTH_OF_IPV4_ADDRESS_ASCII = 15 */
                sscanf(Addr_Port, "%15[^:]", Addr);

                /* Same reasoning as the IPv6 branch: a trailing or
                   non-numeric port must fall back to DefaultPort instead of
                   leaving Port uninitialised. */
                Port = DefaultPort;
                if( PortPos != NULL )
                {
                    if( sscanf(PortPos + 1, "%hu", &Port) != 1 )
                    {
                        Port = DefaultPort;
                    }
                }
                /* inet_pton() rejects malformed literals (e.g. "foo") and is
                   free of inet_addr()'s INADDR_NONE/255.255.255.255 ambiguity. */
                if( inet_pton(AF_INET, Addr, &(Out->Addr.Addr4.sin_addr)) != 1 )
                {
                    return AF_UNSPEC;
                }

                Out->Addr.Addr4.sin_family = Family;
                Out->Addr.Addr4.sin_port = htons(Port);

                return AF_INET;
            }
            break;

        default:
            return AF_UNSPEC;
            break;
    }
}

int AddressList_Add_From_String(AddressList *a, const char *Addr_Port, int DefaultPort)
{
    Address_Type    Tmp;

    if( AddressList_ConvertFromString(&Tmp, Addr_Port, DefaultPort) == AF_UNSPEC )
    {
        return -1;
    }

    return AddressList_Add(a, &Tmp);

}

uint32_t AddressList_Advance(AddressList *a)
{
    if( a == NULL )
    {
        return 0;
    }

    return (a->Counter)++;
}

struct sockaddr *AddressList_GetOneBySubscript(AddressList *a, sa_family_t *family, int Subscript)
{
    Address_Type *Result;

    if( a == NULL )
    {
        return 0;
    }

    Result = (Address_Type *)Array_GetBySubscript(&(a->AddressList), Subscript);
    if( Result == NULL )
    {
        return NULL;
    } else {
        if( family != NULL )
        {
            *family = Result->family;
        }
        return (struct sockaddr *)&(Result->Addr);
    }
}

struct sockaddr *AddressList_GetOne(AddressList *a, sa_family_t *family)
{
    int Used;

    if( a == NULL )
    {
        return NULL;
    }

    Used = Array_GetUsed(&(a->AddressList));
    if( Used <= 0 )
    {
        return NULL;
    }

    return AddressList_GetOneBySubscript(a, family, a->Counter % Used);
}

struct sockaddr **AddressList_GetPtrListOfFamily(AddressList *a, sa_family_t family)
{
    int Itr;
    int NumberOfAddresses = AddressList_GetNumberOfAddresses(a);
    struct sockaddr **AddrList, **AddrList_Ori;
    struct sockaddr *OneAddr;
    sa_family_t OneFamily = AF_UNSPEC;

    AddrList = SafeMalloc(sizeof(struct sockaddr *) * (NumberOfAddresses + 1));
    if( AddrList == NULL )
    {
        return NULL;
    }

    AddrList_Ori = AddrList;
    Itr = 0;
    while( Itr != NumberOfAddresses )
    {
        OneAddr = AddressList_GetOneBySubscript(a, &OneFamily, Itr);
        if( OneFamily == family )
        {
            *AddrList = OneAddr;
            ++AddrList;
        }
        ++Itr;
    }

    *AddrList = NULL;
    return AddrList_Ori;
}

struct sockaddr **AddressList_GetPtrList(AddressList *a, sa_family_t **families)
{
    int Itr;

    int NumberOfAddresses = AddressList_GetNumberOfAddresses(a);
    struct sockaddr **AddrList;

    AddrList = SafeMalloc(sizeof(struct sockaddr *) * (NumberOfAddresses + 1));
    if( AddrList == NULL )
    {
        return NULL;
    }

    *families = SafeMalloc(sizeof(sa_family_t) * (NumberOfAddresses + 1));
    if( *families == NULL )
    {
        SafeFree(AddrList);
        return NULL;
    }

    Itr = 0;
    while( Itr != NumberOfAddresses )
    {
        AddrList[Itr] = AddressList_GetOneBySubscript(a, &((*families)[Itr]), Itr);

        ++Itr;
    }

    AddrList[Itr] = NULL;
    (*families)[Itr] = AF_UNSPEC;
    return AddrList;
}
