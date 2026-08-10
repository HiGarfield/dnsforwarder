#include <string.h>
#include "socketpool.h"
#include "utils.h"

static int SocketPool_Add(SocketPool *sp,
                          SOCKET Sock,
                          const void *Data,
                          int DataLength
                          )
{
    SOCKET *s = (SOCKET *)sp->SocketUnit;
    int Capacity = sp->DataLength - (int)sizeof(SOCKET);

    if( DataLength < 0 || Capacity < 0 || DataLength > Capacity )
    {
        return -120;
    }

    *s = Sock;

    if( Data != NULL )
    {
        memcpy((char *)s + sizeof(SOCKET), Data, DataLength);
    }
    /* Clear the trailing bytes of the unit. s is a SOCKET*, so pointer
       arithmetic uses sizeof(SOCKET); cast to char* to keep byte offsets. */
    memset((char *)s + sizeof(SOCKET) + DataLength, 0,
           (size_t)(Capacity - DataLength));

    if( sp->t.Add(&(sp->t), sp->SocketUnit) == NULL )
    {
        return -27;
    }

    return 0;
}

static int SocketPool_Del(SocketPool *sp, SOCKET Sock)
{
    const SocketUnit *r;

    r = sp->t.Search(&(sp->t), &Sock, NULL);
    if( r != NULL )
    {
        sp->t.Delete(&(sp->t), r);
    }

    return 0;
}

typedef struct _SocketPool_Fetch_Arg
{
    SOCKET Sock;
    fd_set *fs;
    void **DataOut;
} SocketPool_Fetch_Arg;

static int SocketPool_Fetch_Inner(Bst *t,
                                  const SocketUnit *su,
                                  SocketPool_Fetch_Arg *Arg)
{
    SOCKET *s = (SOCKET *)su;

    if( FD_ISSET(*s, Arg->fs) )
    {
        Arg->Sock = *s;

        if( Arg->DataOut != NULL )
        {
            *(Arg->DataOut) = (void *)(s + 1);
        }

        return 1;
    }

    return 0;
}

static SOCKET SocketPool_FetchOnSet(SocketPool *sp,
                                    fd_set *fs,
                                    void **Data
                                    )
{
    SocketPool_Fetch_Arg ret = {INVALID_SOCKET, fs, Data};

    sp->t.Enum(&(sp->t),
               (Bst_Enum_Callback)SocketPool_Fetch_Inner,
               &ret
               );

    return ret.Sock;
}

static int SocketPool_CloseAll_Inner(Bst *t,
                                     SocketUnit *Data,
                                     const SOCKET *ExceptFor
                                     )
{
    const SOCKET *s = (SOCKET *)Data;

    if( *s != INVALID_SOCKET && *s != *ExceptFor )
    {
        CLOSE_SOCKET(*s);
    }

    return 0;
}

static void SocketPool_CloseAll(SocketPool *sp, SOCKET ExceptFor)
{
    sp->t.Enum(&(sp->t),
               (Bst_Enum_Callback)SocketPool_CloseAll_Inner,
               &ExceptFor
               );
}

static void SocketPool_Free(SocketPool *sp, BOOL CloseAllSocket)
{
    if( CloseAllSocket )
    {
        SocketPool_CloseAll(sp, INVALID_SOCKET);
    }

    SafeFree(sp->SocketUnit);
    sp->t.Free(&(sp->t));
}

static int Compare(const SocketUnit *_1, const SocketUnit *_2)
{
    return (int)(*(SOCKET *)_1) - (int)(*(SOCKET *)_2);
}

int SocketPool_Init(SocketPool *sp, int DataLength)
{
    DataLength += sizeof(SOCKET);

    if( Bst_Init(&(sp->t),
                    DataLength,
                    (CompareFunc)Compare
                    )
       != 0 )
    {
        return -113;
    }

    sp->SocketUnit = SafeMalloc(DataLength);
    if( sp->SocketUnit == NULL )
    {
        sp->t.Free(&(sp->t));
        return -119;
    }

    sp->DataLength = DataLength;

    sp->Add = SocketPool_Add;
    sp->Del = SocketPool_Del;
    sp->CloseAll = SocketPool_CloseAll;
    sp->FetchOnSet = SocketPool_FetchOnSet;
    sp->Free = SocketPool_Free;

    return 0;
}
