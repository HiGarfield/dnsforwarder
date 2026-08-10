#include "socketpuller.h"

PUBFUNC int SocketPuller_Add(SocketPuller *p,
                             SOCKET s,
                             const void *Data,
                             int DataLength
                             )
{
    if( s == INVALID_SOCKET )
    {
        return -11;
    }

    if( p->p.Add(&(p->p), s, Data, DataLength) != 0 )
    {
        return -16;
    }

    if( s > p->Max )
    {
        p->Max = s;
    }

    FD_SET(s, &(p->s));

    return 0;
}

PUBFUNC int SocketPuller_Del(SocketPuller *p, SOCKET s)
{
    if( p->p.Del(&(p->p), s) != 0 )
    {
        return -33;
    }

    FD_CLR(s, &(p->s));

    return 0;
}

PUBFUNC SOCKET SocketPuller_Select(SocketPuller *p,
                                   struct timeval *tv,
                                   void **Data,
                                   BOOL Reading,
                                   BOOL Writing,
                                   int *err
                                   )
{
    fd_set ReadySet;
    SOCKET s;
    int Err = 0;

    ReadySet = p->s;

    while( TRUE )
    {

        switch( select(p->Max + 1,
                       Reading ? &ReadySet : NULL,
                       Writing ? &ReadySet : NULL,
                       NULL,
                       tv)
                )
        {
        case SOCKET_ERROR:
            Err = GET_LAST_ERROR();
            SLEEP(1); /* dead loop? */
            if( FatalErrorDecideding(Err) == 0 )
            {
                continue;
            }
            /* fall through */
        case 0:
            /* timeout */
            s = INVALID_SOCKET;
            break;

        default:
            s = p->p.FetchOnSet(&(p->p), &ReadySet, Data);
            break;
        }

        break;
    }

    if( err != NULL )
    {
        *err = Err;
    }
    return s;
}

PUBFUNC void SocketPuller_CloseAll(SocketPuller *p, SOCKET ExceptFor)
{
    p->p.CloseAll(&(p->p), ExceptFor);
}

PUBFUNC void SocketPuller_Free(SocketPuller *p)
{
    p->p.Free(&(p->p), TRUE);
}

PUBFUNC void SocketPuller_FreeWithoutClose(SocketPuller *p)
{
    p->p.Free(&(p->p), FALSE);
}

int SocketPuller_Init(SocketPuller *p, int DataLength)
{
    p->Max = -1;

    p->Add = SocketPuller_Add;
    p->Del = SocketPuller_Del;
    p->Select = SocketPuller_Select;
    p->CloseAll = SocketPuller_CloseAll;
    p->Free = SocketPuller_Free;
    p->FreeWithoutClose = SocketPuller_FreeWithoutClose;

    FD_ZERO(&(p->s));
    return SocketPool_Init(&(p->p), DataLength);
}

SocketPuller **SocketPullers_Init(int Count, int DataLength)
{
    SocketPuller *Buffer;
    SocketPuller **Pullers;
    int i;

    if( Count <= 0 )
    {
        return NULL;
    }

    Pullers = SafeMalloc(sizeof(SocketPuller *) * (Count + 1));
    if( Pullers == NULL )
    {
        return NULL;
    }

    Buffer = SafeMalloc(sizeof(SocketPuller) * Count);
    if( Buffer == NULL )
    {
        SafeFree(Pullers);
        return NULL;
    }

    for( i = 0; i < Count; ++i )
    {
        Pullers[i] = Buffer + i;
        if( SocketPuller_Init(Pullers[i], DataLength) != 0 )
        {
            Pullers[i] = NULL;
            goto EXIT_1;
        }
    }
    Pullers[i] = NULL;

    return Pullers;

EXIT_1:
    SocketPullers_FreeWithoutClose(Pullers);
    SafeFree(Buffer);
    return NULL;
}

void SocketPullers_CloseAll(SocketPuller **Pullers)
{
    for( ; *Pullers != NULL; ++Pullers )
    {
        (*Pullers)->CloseAll(*Pullers, INVALID_SOCKET);
    }
}

void SocketPullers_FreeWithoutClose(SocketPuller **Pullers)
{
    SocketPuller **p;

    p = Pullers;
    for( ; *Pullers != NULL; ++Pullers )
    {
        (*Pullers)->FreeWithoutClose(*Pullers);
    }
    SafeFree(p);
}

void SocketPullers_Free(SocketPuller **Pullers)
{
    SocketPuller **p;

    p = Pullers;
    for( ; *Pullers != NULL; ++Pullers )
    {
        (*Pullers)->Free(*Pullers);
    }
    SafeFree(p);
}
