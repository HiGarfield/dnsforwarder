#include <string.h>
#include "tcpm.h"
#include "stringlist.h"
#include "socketpuller.h"
#include "utils.h"
#include "logs.h"
#include "udpfrontend.h"
#include "timedtask.h"
#include "dnscache.h"
#include "dnsgenerator.h"
#include "ipmisc.h"
#include "domainstatistic.h"
#include "ptimer.h"

extern BOOL Ipv6_Enabled;

#define TIMEOUT     5
#define TIMEOUT_ms_SEND 2000
#define TIMEOUT_ms_RECV 2000
#define TIMEOUT_ms_ALIVE    100

extern int TCPM_Keep_Alive;
static const struct timeval TimeOut_Const = {TIMEOUT, 0};

/* How long the worker loop in TcpM_Works() may block in select().  Throughout
   that window the worker is blind: upstream sockets opened by TcpM_Send() on a
   frontend thread are not in its fd_set yet, and its context sweep cannot run.
   ModuleContext_Sweep() drops entries older than 2 seconds, so this interval
   has to stay below that deadline. */
#define TIMEOUT_WORKER_POLL 1
static const struct timeval TimeOut_WorkerPoll = {TIMEOUT_WORKER_POLL, 0};

typedef struct _TcpContext
{
    int     ServerIndex;
    time_t  LastActivity;
    /* To retry for server that force closed SOCKET. */
    int         Queried;
    int         MsgCtxQid;
    uint32_t    MsgCtxHash;
    MsgContext  *MsgCtx;
} TcpContext;

static void SweepWorks(MsgContext *MsgCtx, int Number, TcpM *Module)
{
    IHeader *h = (IHeader *)MsgCtx;

    ShowTimeOutMessage(h, 'T');
    DomainStatistic_Add(h, STATISTIC_TYPE_REFUSED);

    if( Number == 1 && Module->SocksProxies == NULL )
    {
        AddressList_Advance(&(Module->ServiceList));
    }
}

static void TcpM_Connect_Recycle(SocketPuller *Puller, SocketPuller **Backups, int NumOfBackups)
{
    SocketPuller *p;
    TcpContext *TcpCtx;
    int Err;

    while( Puller != NULL )
    {
        SOCKET s = INVALID_SOCKET;
        struct timeval TimeOut = {0, TIMEOUT_ms_ALIVE * 1000};

        s = Puller->Select(Puller, &TimeOut, (void **)&TcpCtx, FALSE, TRUE, &Err);

        if( s == INVALID_SOCKET )
        {
            if( Err != 0 && !ErrorOfVoidSelect(Err) )
            {
                ERRORMSG("TCP fatal error %d.\n", Err);
            }
            break;
        } else {
            Puller->Del(Puller, s);

            /* The recycled context carries the index it was created with,
               which lives in the same numbering space as Backups (server or
               proxy).  Guard the index: an out-of-range value would be an
               out-of-bounds dereference of Backups.  Drop the socket rather
               than indexing past the array. */
            if( TcpCtx->ServerIndex < 0 || TcpCtx->ServerIndex >= NumOfBackups )
            {
                WARNING("Recycled socket has out-of-range ServerIndex %d (max %d), closing.\n",
                        TcpCtx->ServerIndex, NumOfBackups);
                /* Do NOT SafeFree(TcpCtx): it points into the SocketPool's
                   single shared SocketUnit buffer (SocketPool_Add always
                   inserts the same sp->SocketUnit and FetchOnSet returns
                   s + 1), so freeing it here would be an invalid free of a
                   pointer into the middle of an allocated block (heap
                   corruption). The buffer is owned and released by the
                   SocketPool on Free(). Just drop the socket. */
                CLOSE_SOCKET(s);
                continue;
            }

            DEBUG("Recycled socket for Pullers[%d]\n", TcpCtx->ServerIndex);
            p = Backups[TcpCtx->ServerIndex];
            p->Add(p, s, TcpCtx, sizeof(TcpContext));
        }
    }
}

/* Connection Handling: https://www.rfc-editor.org/rfc/rfc7766#section-6
    To get a clear state of the TCP, we don't use pipeline.
    We use a short keep-alive to avoid the server is non-readable but writable.
*/
static SOCKET TcpM_Connect_GetAvailable(SocketPuller *p, TcpContext **TcpCtx)
{
    SOCKET s = INVALID_SOCKET;
    int Err;


    while( TRUE )
    {
        struct timeval TimeOut = {0, TIMEOUT_ms_ALIVE * 1000};

        s = p->Select(p, &TimeOut, (void **)TcpCtx, FALSE, TRUE, &Err);
        if( s == INVALID_SOCKET )
        {
            if( Err != 0 && !ErrorOfVoidSelect(Err) )
            {
                ERRORMSG("TCP fatal error %d.\n", Err);
            }
            break;
        } else {
            p->Del(p, s); /* Single thread: delete before adding is safe. */

            if( time(NULL) - (*TcpCtx)->LastActivity > TCPM_Keep_Alive ) {
                INFO("Existing TCP connection expired, discard.\n");
                CLOSE_SOCKET(s);
            } else {
                break;
            }
        }
    }

    return s;
}

static SOCKET TcpM_Connect_Addr(sa_family_t af, const struct sockaddr *addr)
{
    SOCKET s = socket(af, SOCK_STREAM, IPPROTO_TCP);

    if( s == INVALID_SOCKET )
    {
        return INVALID_SOCKET;
    }

    if( SetSocketNonBlock(s, TRUE) != 0 )
    {
        CLOSE_SOCKET(s);
        return INVALID_SOCKET;
    }

#if defined(_WIN32) && defined(IPV6_V6ONLY)
    if( af == AF_INET6 )
    {
        SetSocketIPv6V6only(s, 0);
    }
#endif

    if( connect(s, addr, GetAddressLength(af)) != 0 )
    {
        if( GET_LAST_ERROR() != CONNECT_FUNCTION_BLOCKED )
        {
            CLOSE_SOCKET(s);
            return INVALID_SOCKET;
        }
    }

    return s;
}

static int TcpM_Connect(TcpM *m, int ServerIndex, BOOL IsProxy)
{
    struct sockaddr **ServerAddresses;
    sa_family_t *Families;
    const char *Name, *Type;

    SocketPuller **Pullers, *Puller;
    int i, NumOfServers, Shift, idx, n = 0;
    TcpContext *TcpCtx, TcpCtxNew;

    if( m->SocksProxies == NULL || IsProxy == FALSE )
    {
        ServerAddresses = m->Services;
        Families = m->ServiceFamilies;
        Pullers = m->Agents;
        Puller = &(m->QueryPuller);
        Name = m->ServiceName;
        Type = "server";
        NumOfServers = AddressList_GetNumberOfAddresses(&(m->ServiceList));
    } else {
        ServerAddresses = m->SocksProxies;
        Families = m->SocksProxyFamilies;
        Pullers = m->Proxies;
        Puller = &(m->ProxyPuller);
        Name = m->ProxyName;
        Type = "proxy";
        NumOfServers = AddressList_GetNumberOfAddresses(&(m->SocksProxyList));
    }

    TcpM_Connect_Recycle(Puller, Pullers, NumOfServers);

    /* Seed the PRNG only once (same rationale as stringchunk.c): seeding on
       every call re-initializes the sequence with the same second-resolution
       value, so all connections made within one second pick the same Shift
       and upstream rotation collapses to a fixed choice. */
    {
        static BOOL Seeded = FALSE;
        if( Seeded == FALSE )
        {
            srand((unsigned int)time(NULL));
            Seeded = TRUE;
        }
    }
    Shift = rand();

    idx = ServerIndex;

    if( ServerIndex >= 0 )
    {
        NumOfServers = 1;
    }

    DEBUG("Connecting to %s: %s ...\n", Type, Name);

    for( i = 0; i < NumOfServers; ++i )
    {
        SOCKET s = INVALID_SOCKET;

        if( ServerIndex < 0 )
        {
            idx = (Shift + i) % NumOfServers;
        }

        DEBUG("Pullers[%d]:\n", idx);

        /* Existing */
        s = TcpM_Connect_GetAvailable(Pullers[idx], &TcpCtx);
        if( s != INVALID_SOCKET )
        {
            DEBUG("Got existing connection from Pullers[%d].\n", idx);
            Puller->Add(Puller, s, TcpCtx, sizeof(TcpContext));
            n++;
            continue;
        }

        /* New */
        if( m->SocksProxies == NULL || IsProxy == TRUE )
        {
            s = TcpM_Connect_Addr(Families[idx], ServerAddresses[idx]);
            if( s == INVALID_SOCKET )
            {
                continue;
            }
            DEBUG("Created new connection for Pullers[%d].\n", idx);
            TcpCtxNew.ServerIndex = idx;
            TcpCtxNew.LastActivity = time(NULL);
            TcpCtxNew.Queried = 0;
            TcpCtx = &TcpCtxNew;
        } else {
            if( TcpM_Connect(m, -1, TRUE) > 0 ) {
                s = TcpM_Connect_GetAvailable(&(m->ProxyPuller), &TcpCtx);
                if( s == INVALID_SOCKET )
                {
                    continue;
                }
                DEBUG("Got proxy connection for Pullers[%d].\n", idx);
                TcpCtx->ServerIndex = idx;
            } else {
                continue;
            }
        }

        Puller->Add(Puller, s, TcpCtx, sizeof(TcpContext));
        n++;
    }

    return n;
}

static int TcpM_SendWrapper(SOCKET Sock, const char *Start, int Length)
{
    time_t t = time(NULL);
    int SentTotal = 0;

    while( SentTotal < Length )
    {
        int Sent = send(Sock, Start + SentTotal, Length - SentTotal, MSG_NOSIGNAL);

        if( Sent < 0 )
        {
            int LastError = GET_LAST_ERROR();
            if( FatalErrorDecideding(LastError) != 0 ||
                    !SocketIsWritable(Sock, TIMEOUT_ms_SEND) ||
                    time(NULL) - t > TIMEOUT_ms_SEND / 1000
                    )
            {
                ShowSocketError("Sending to TCP server or proxy failed.", LastError);
                return (-1) * LastError;
            }
            continue;
        }

        SentTotal += Sent;
    }

    return Length;
}

static int TcpM_RecvWrapper(SOCKET Sock, char *Buffer, int BufferSize)
{
    int Recvlength;
    time_t t = time(NULL);

    while( (Recvlength = recv(Sock, Buffer, BufferSize, 0)) < 0 )
    {
        int LastError = GET_LAST_ERROR();
        if( FatalErrorDecideding(LastError) != 0 ||
                !SocketIsStillReadable(Sock, TIMEOUT_ms_RECV) ||
                time(NULL) - t > TIMEOUT_ms_RECV / 1000
                )
        {
            ShowSocketError("Receiving from TCP server or proxy failed", LastError);
            return (-1) * LastError;
        }
    }
    /* recv() returning 0 means the peer closed the connection (FIN).  Treat it
       as a closure/error, never as a successful read of zero bytes: callers
       that expect an exact byte count (e.g. the 2-byte TCP length prefix) must
       not mistake a closed connection for a valid short read, nor feed a zero
       "length" into later size arithmetic (which, with unsigned counters, would
       wrap to a huge value).  Normalise it to a negative error code. */
    if( Recvlength == 0 )
    {
        return -1;
    }

    return Recvlength;
}

/* Receive exactly `Length' bytes, or fail.
 *
 * TCP is a byte stream: a single recv() may return fewer bytes than requested
 * however small the expected record is. Callers that parse a fixed-size record
 * (the SOCKS5 handshake replies below) must not treat such a short read as a
 * protocol error -- doing so both drops a perfectly good connection and leaves
 * the unconsumed remainder in the socket, desynchronising every later read.
 *
 * Returns `Length' on success, or the negative error code from
 * TcpM_RecvWrapper() (which already retries EINTR/EAGAIN and maps a peer
 * close to a negative value) on failure. A close observed mid-record is an
 * error: the record can never be completed. */
static int TcpM_RecvAllWrapper(SOCKET Sock, char *Buffer, int Length)
{
    int Got = 0;

    while( Got < Length )
    {
        int State = TcpM_RecvWrapper(Sock, Buffer + Got, Length - Got);

        if( State <= 0 )
        {
            /* Propagate the original error code; never report a partial count
               as success. */
            return State < 0 ? State : -1;
        }

        Got += State;
    }

    return Got;
}

static int TcpM_ProxyPreparation(SOCKET Sock,
                                 const struct sockaddr  *NestedAddress,
                                 sa_family_t Family
                                 )
{
    char AddressInfos[4 + 1 + LENGTH_OF_IPV6_ADDRESS_ASCII + 2 + 1];
    char *AddressString = AddressInfos + 5;
    int NumberOfCharacter;
    unsigned short Port;
    char RecvBuffer[16];
    char TmpByte;

    DEBUG("Negotiating with TCP proxy ...\n");

    if( TcpM_SendWrapper(Sock, "\x05\x01\x00", 3) != 3 )
    {
        ERRORMSG("Cannot negotiate with TCP proxy.\n");
        return -1;
    }

    if( TcpM_RecvAllWrapper(Sock, RecvBuffer, 2) != 2 )
    {
        ERRORMSG("Cannot negotiate with TCP proxy.\n");
        return -2;
    }

    if( RecvBuffer[0] != '\x05' || RecvBuffer[1] != '\x00' )
    {
        ERRORMSG("Cannot negotiate with TCP proxy.\n");
        return -3;
    }

    memcpy(AddressInfos, "\x05\x01\x00\x03", 4);

    if( Family == AF_INET )
    {
        IPv4AddressToAsc(&(((const struct sockaddr_in *)NestedAddress)->sin_addr), AddressString);
        Port = ((const struct sockaddr_in *)NestedAddress)->sin_port;
    } else {
        IPv6AddressToAsc(&(((const struct sockaddr_in6 *)NestedAddress)->sin6_addr), AddressString);
        Port = ((const struct sockaddr_in6 *)NestedAddress)->sin6_port;
    }

    NumberOfCharacter = strlen(AddressString);
    memcpy(AddressInfos + 4, &NumberOfCharacter, 1);
    memcpy(AddressInfos + 5 + NumberOfCharacter,
           (const char *)&Port,
           sizeof(Port)
           );

    DEBUG("Proxy is Connecting to TCP server ...\n");

    if( TcpM_SendWrapper(Sock,
                         AddressInfos,
                         4 + 1 + NumberOfCharacter + 2
                         )
     != 4 + 1 + NumberOfCharacter + 2 )
    {
        ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
        return -4;
    }

    if( TcpM_RecvAllWrapper(Sock, RecvBuffer, 4) != 4 )
    {
        ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
        return -9;
    }

    if( RecvBuffer[1] != '\x00' )
    {
        ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
        return -10;
    }

    switch( RecvBuffer[3] )
    {
        case 0x01:
            NumberOfCharacter = 6;
            break;

        case 0x03:
            /* The domain-name length octet is controlled by the (possibly
             * malicious) upstream proxy. Read it as unsigned into a separate
             * byte to avoid signed-char overflow/UB, and verify the read
             * actually succeeded before using the value. */
            if( TcpM_RecvAllWrapper(Sock, &TmpByte, 1) != 1 )
            {
                ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
                return -12;
            }
            NumberOfCharacter = (int)(unsigned char)TmpByte + 2;
            break;

        case 0x04:
            NumberOfCharacter = 18;
            break;

        default:
            ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
            return -11;
    }
    ClearTCPSocketBuffer(Sock, NumberOfCharacter);

    INFO("Proxy has Connected to TCP server.\n");

    return 0;

}

static int TcpM_Send_Actual(TcpM *m, MsgContext *MsgCtx, int SingleServerIndex)
{
    char *Type;

    SocketPuller *p;
    TcpContext *TcpCtx;
    int i, NumOfServers, n = 0;

    IHeader *h = (IHeader *)MsgCtx;
    char *msg = (char *)(IHEADER_TAIL(h)) - 2;

    DNSSetTcpLength(msg, h->EntityLength);

    if( SingleServerIndex == -1 && m->Parallel )
    {
        NumOfServers = AddressList_GetNumberOfAddresses(&(m->ServiceList));
    } else {
        NumOfServers = 1;
    }

    p = &(m->QueryPuller);

    if( m->SocksProxies == NULL )
    {
        Type = "server";
    } else {
        Type = "proxy";
    }

    DEBUG("Send to Pullers[%d].\n", SingleServerIndex);

    if( TcpM_Connect(m, SingleServerIndex, FALSE) < 1 )
    {
        return 0;
    }

    for( i = 0; i < NumOfServers; ++i )
    {
        SOCKET s;
        int Err;
        struct timeval TimeOut = TimeOut_Const;

        s = p->Select(p, &TimeOut, (void **)&TcpCtx, FALSE, TRUE, &Err);

        if( s == INVALID_SOCKET )
        {
            if( Err != 0 && !ErrorOfVoidSelect(Err) )
            {
                ERRORMSG("TCP fatal error %d.\n", Err);
                break;
            }
            INFO("No %s TCP connection is established.\n", Type);
            continue;
        } else {
            p->Del(p, s);
        }

        /* p->Del returns the node holding TcpCtx to p's (QueryPuller's) free
           list, where it can be reused by a concurrent Add.  Copy it out so
           the references below are not dangling (use-after-free / data race).
           This mirrors the fix at TcpM_Works() that introduced a local Ctx. */
        {
            TcpContext Ctx = *TcpCtx;

        if( m->SocksProxies != NULL && Ctx.Queried == 0 )
        {
            struct sockaddr *addr;
            sa_family_t family;

            /* TcpCtx->ServerIndex is the *proxy* index (set in the
               TcpM_Connect proxy path), NOT an index into the DNS upstream
               service list.  Indexing m->ServiceList with it is both an
               out-of-bounds risk (proxy count need not equal server count,
               yielding a NULL addr and a crash inside TcpM_ProxyPreparation)
               and semantically wrong (the proxy tunnels to whichever upstream
               we ask it to reach).  Pick the upstream server from the service
               rotation independently of the proxy index. */
            addr = AddressList_GetOne(&(m->ServiceList), &family);
            if( addr == NULL || TcpM_ProxyPreparation(s, addr, family) != 0 )
            {
                AddressList_Advance(&(m->ServiceList));
                CLOSE_SOCKET(s);
                continue;
            }
        }

        if( TcpM_SendWrapper(s,
                             msg,
                             h->EntityLength + 2
                             )
            < 0 )
        {
            if( m->SocksProxies != NULL )
            {
                AddressList_Advance(&(m->ServiceList));
            }
            CLOSE_SOCKET(s);
            continue;
        }

        DEBUG("Sent by Pullers[%d].\n", Ctx.ServerIndex);

        Ctx.LastActivity = time(NULL);
        Ctx.Queried++;
        Ctx.MsgCtxQid = DNSGetQueryIdentifier(h + 1);
        Ctx.MsgCtxHash = h->HashValue;
        Ctx.MsgCtx = MsgCtx;
        m->Puller.Add(&(m->Puller), s, &Ctx, sizeof(TcpContext));

        }   /* end of copied TcpCtx scope */

        n++;
    }

    return n;
}

PUBFUNC int TcpM_Send(TcpM *m,
                      const char *Buffer,
                      int BufferLength
                      )
{
    /* This is the ModuleInterface.Send entry invoked by MMgr_Send when a query
       is routed to a TCP upstream (e.g. a Server group configured over TCP, or
       UDP-to-TCP fallback).  The previous implementation did a sendto() to
       m->IncomingAddr on m->Incoming -- the module's own *listen* socket, which
       is never connect()ed -- so on Linux it returned ENOTCONN and every such
       query was silently dropped.  Forward the query the same way TcpM_Works
       does when it reads a client query from the listen socket: connect to an
       upstream in m->ServiceList and send the (length-prefixed) payload. */
    MsgContext *MsgCtxStored;
    int r;

    (void)BufferLength;

    /* TcpM_Send_Actual mutates shared module state (m->Puller, m->QueryPuller,
       m->ServiceList, m->Context).  It can be called concurrently from this
       MMgr_Send entry (a frontend thread) and from TcpM_Works (the worker
       thread); SocketPuller is documented non-thread-safe, so serialize the
       call with the module lifecycle lock to avoid corrupting the puller's
       fd_set / internal arrays. */
    EFFECTIVE_LOCK_GET(m->Lock);

    /* Register the query in m->Context *before* it goes out, exactly like the
       listen-socket path in TcpM_Works and like UdpM_Send.  Two things depend
       on it:

       - The answer read back in TcpM_Works is matched against this table by
         GenAnswerHeaderAndRemove(); without an entry that lookup fails (-60)
         and every answer to a query routed here was discarded, so queries sent
         to a TCP upstream never produced a reply.

       - TcpM_Send_Actual stores the MsgContext in TcpContext->MsgCtx and reuses
         it later (keep-alive re-send / retry on another socket).  `Buffer` is
         the calling frontend's receive buffer, which is reused for the next
         client query, so it must not be captured; hand over the stable copy
         owned by m->Context instead. */
    MsgCtxStored = m->Context.Add(&(m->Context), (MsgContext *)Buffer);
    if( MsgCtxStored == NULL )
    {
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        return -1;
    }

    r = TcpM_Send_Actual(m, MsgCtxStored, -1);

    if( r <= 0 )
    {
        /* Nothing was sent, so no answer can ever arrive: drop the entry rather
           than leave it for the sweeper. */
        IHeader_Reset((IHeader *)MsgCtxStored);
        m->Context.Del(&(m->Context), MsgCtxStored);
    }

    EFFECTIVE_LOCK_RELEASE(m->Lock);

    return r <= 0;
}

static int TcpM_Cleanup(TcpM *m)
{
    m->IsServer = 0;

    CLOSE_SOCKET(m->Incoming);
    m->Incoming = INVALID_SOCKET;
    m->Puller.Free(&(m->Puller));

    ModuleContext_Free(&(m->Context));

    if( m->SocksProxies != NULL )
    {
        m->ProxyPuller.Free(&(m->ProxyPuller));
        SocketPullers_Free(m->Proxies);
        SafeFree(m->SocksProxies);
        AddressList_Free(&(m->SocksProxyList));
        SafeFree(m->SocksProxyFamilies);
    }

    m->QueryPuller.Free(&(m->QueryPuller));
    SocketPullers_Free(m->Agents);
    SafeFree(m->Services);
    AddressList_Free(&(m->ServiceList));
    SafeFree(m->ServiceFamilies);

    free((void *)(m->ServiceName));
    m->ServiceName = NULL;
    free((void *)(m->ProxyName));
    m->ProxyName = NULL;

    /* Publish "thread exited" under the lock so Modules_SafeCleanup's wait
     * loop reads it synchronously instead of racing on a plain write.
     *
     * Note: the lock is deliberately *not* destroyed here.  Modules_SafeCleanup
     * keeps polling IsServer/WorkThread under this very lock until it observes
     * that the thread is gone, so destroying it at this point would leave that
     * loop locking freed/destroyed state on its next iteration.  The lock lives
     * inside the module instance and dies with it in Modules_Free(). */
    EFFECTIVE_LOCK_GET(m->Lock);
    m->WorkThread = NULL_THREAD;
    EFFECTIVE_LOCK_RELEASE(m->Lock);

    return 0;
}

static int
#ifdef _WIN32
WINAPI
#endif
TcpM_Works(TcpM *m)
{
    int Err;

    char ReceiveBuffer[SOCKET_CONTEXT_LENGTH];
    MsgContext *MsgCtx;
    IHeader *Header;

    #define LEFT_LENGTH  (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))
    char *Entity;

    SocketPuller *p = &(m->Puller);
    TcpContext *TcpCtx;

    int NumberOfCumulated = 0;

    MsgCtx = (MsgContext *)ReceiveBuffer;
    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    for( ; ; )
    {
        int KeepServing;
        SOCKET  s;
        /* Not TimeOut_Const: blocking for TIMEOUT (5s) here exceeded the 2s
           ModuleContext sweep deadline, so the worker woke up only after every
           query registered by TcpM_Send() had already aged out and swept them
           before it ever polled the socket carrying their answer. */
        struct timeval TimeOut = TimeOut_WorkerPoll;

        /* IsServer is toggled to 0 by Modules_SafeCleanup on shutdown.  Read
         * it under the module spin lock so the read is synchronized with that
         * writer (avoids a data race / UB). */
        EFFECTIVE_LOCK_GET(m->Lock);
        KeepServing = m->IsServer;
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        if( !KeepServing )
        {
            break;
        }

        /* Serialize m->Puller access with TcpM_Send (frontend thread), which
           also mutates the puller's fd_set / BST under m->Lock. */
        EFFECTIVE_LOCK_GET(m->Lock);
        s = p->Select(p, &TimeOut, (void **)&TcpCtx, TRUE, FALSE, &Err);
        EFFECTIVE_LOCK_RELEASE(m->Lock);

        if( s == INVALID_SOCKET )
        {
            if( Err != 0 )
            {
                ERRORMSG("TcpM fatal error %d.\n", Err);
                break;
            }
            /* Sweep modifies the per-module context BST, which is also touched
               by TcpM_Send() (frontend thread) under m->Lock. Serialize it. */
            EFFECTIVE_LOCK_GET(m->Lock);
            m->Context.Sweep(&(m->Context), (SweepCallback)SweepWorks, m);
            EFFECTIVE_LOCK_RELEASE(m->Lock);
            NumberOfCumulated = 0;
            continue;
        }

        if( s == m->Incoming ) {
            int State;

            if( NumberOfCumulated > 1024 )
            {
                /* Sweep modifies the per-module context BST, which is also
                   touched by TcpM_Send() (frontend thread) under m->Lock. */
                EFFECTIVE_LOCK_GET(m->Lock);
                m->Context.Sweep(&(m->Context), (SweepCallback)SweepWorks, m);
                EFFECTIVE_LOCK_RELEASE(m->Lock);
                NumberOfCumulated = 0;
            }

            State = recvfrom(s,
                             Entity, /* Receiving the DNS payload, as UdpFrontend_Work does */
                             LEFT_LENGTH,
                             0,
                             NULL,
                             NULL
                             );

            if( State > 0 )
            {
                MsgContext *MsgCtxStored;

                ++NumberOfCumulated;

                /* `m->Incoming` is the module's own UDP *listen* socket.  A
                   datagram read here is a client DNS query delivered over UDP,
                   so the stored context must be filled exactly like
                   UdpFrontend_Work does: set SendBackSocket to this socket,
                   BackAddress to the client's address family, and parse the
                   QUESTION to populate Domain/HashValue/EntityLength.  Without
                   this, the IHeader is left uninitialized: SendBackSocket is
                   garbage, BackAddress.family stays AF_UNSPEC (so
                   MsgContext_IsFromTCP() wrongly returns TRUE and the reply is
                   sent with TCP-style send() on a UDP socket -> ENOTCONN), and
                   Domain/HashValue are empty so filter/hosts/cache matching is
                   broken.  The query would otherwise be forwarded but its
                   answer could never be returned to the client. */
                if( IHeader_Fill(Header,
                                 FALSE,
                                 Entity,
                                 State,
                                 (const struct sockaddr *)&(m->IncomingAddr.Addr),
                                 m->Incoming,
                                 m->IncomingAddr.family,
                                 NULL
                                 )
                    != 0 )
                {
                    WARNING("Malformed message received on TCP module's UDP "
                            "incoming socket, discarded.\n");
                    EFFECTIVE_LOCK_GET(m->Lock);
                    p->Del(p, s);
                    p->Add(p, s, TcpCtx, sizeof(TcpContext));
                    EFFECTIVE_LOCK_RELEASE(m->Lock);
                    continue;
                }

                /* Serialize the per-module context BST with TcpM_Send
                   (frontend thread), which also calls Context.Add under m->Lock. */
                EFFECTIVE_LOCK_GET(m->Lock);
                MsgCtxStored = m->Context.Add(&(m->Context), MsgCtx);
                if( MsgCtxStored == NULL )
                {
                    EFFECTIVE_LOCK_RELEASE(m->Lock);
                    EFFECTIVE_LOCK_GET(m->Lock);
                    p->Del(p, s);
                    p->Add(p, s, TcpCtx, sizeof(TcpContext));
                    EFFECTIVE_LOCK_RELEASE(m->Lock);
                    continue;
                }

                /* Serialize with TcpM_Send (MMgr_Send entry): TcpM_Send_Actual
                   mutates the shared pullers / service list. */
                TcpM_Send_Actual(m, MsgCtxStored, -1);
                EFFECTIVE_LOCK_RELEASE(m->Lock);
            }

            EFFECTIVE_LOCK_GET(m->Lock);
            p->Del(p, s);
            p->Add(p, s, TcpCtx, sizeof(TcpContext));
            EFFECTIVE_LOCK_RELEASE(m->Lock);

        } else {
            int State;
            uint16_t TCPLength;
            uint16_t TotalLength;
            SocketPuller *p2;
            char *PartialData;
            TcpContext Ctx;

            /* `TcpCtx` points at the payload of a BST node owned by the
               puller `p`. `p->Del` below returns that node to `p`'s free
               list, where a later `Add` (e.g. inside TcpM_Send_Actual or
               the re-add at the end of this branch) may reuse and overwrite
               it. Copy the context by value and remove the node while holding
               m->Lock, so the copy is atomic with respect to TcpM_Send's
               concurrent Add/Select on the same puller. */
            EFFECTIVE_LOCK_GET(m->Lock);
            Ctx = *TcpCtx;

            p->Del(p, s);
            EFFECTIVE_LOCK_RELEASE(m->Lock);

            /* Read the 2-byte TCP length prefix. On a non-blocking socket the
               two bytes can arrive in separate segments, so keep reading until
               both are present instead of treating a single-byte read as bad
               data (which previously closed otherwise-valid connections). */
            {
                int Got = 0;
                char *Cur = (char *)&TCPLength;

                while( Got < 2 )
                {
                    State = TcpM_RecvWrapper(s, Cur, 2 - Got);
                    if( State < 1 )
                    {
                        /* If Server force closed the keep-alive SOCKET: */
                        IHeader *Header2 = (IHeader *)Ctx.MsgCtx;
                        if( Ctx.Queried > 1 && Header2 != NULL && *(Header2->Domain) != 0 &&
                            Ctx.MsgCtxQid == DNSGetQueryIdentifier(Header2 + 1) &&
                            Ctx.MsgCtxHash == Header2->HashValue
                            )
                        {
                            INFO("TCP retrying for %s ...\n", Header2->Domain);
                            /* TcpM_Send_Actual mutates the shared, non-thread-safe
                               m->Puller / m->QueryPuller (and the per-module context
                               BST). The frontend thread does the same under m->Lock
                               (see TcpM_Send and the listen-socket path above), so
                               this retry must be serialized too; otherwise the two
                               threads race on the puller's fd_set / internal arrays.
                               TcpM_Send_Actual does NOT take the lock itself. */
                            EFFECTIVE_LOCK_GET(m->Lock);
                            TcpM_Send_Actual(m, Ctx.MsgCtx, Ctx.ServerIndex);
                            EFFECTIVE_LOCK_RELEASE(m->Lock);
                        }
                        CLOSE_SOCKET(s);
                        Got = -1;
                        break;
                    }
                    Cur += State;
                    Got += State;
                }
                if( Got < 0 )
                {
                    continue;
                }
            }

            TCPLength = ntohs(TCPLength);
            if( TCPLength > LEFT_LENGTH )
            {
                WARNING("TCP segment is too large, discarded.\n");
                CLOSE_SOCKET(s);
                continue;
            }

            PartialData = Entity;
            TotalLength = TCPLength;
            while( TCPLength > 0 )
            {
                State = TcpM_RecvWrapper(s, PartialData, TCPLength);
                /* A non-positive result is an error or a closed
                   connection, never a length. Applying it would move
                   PartialData backwards out of the buffer and, because
                   TCPLength is unsigned, wrap it to a huge value. */
                if( State <= 0 )
                {
                    break;
                }

                PartialData += State;
                TCPLength -= State;
            }

            if( TCPLength != 0 )
            {
                WARNING("TCP %s received bad data, len: %d.\n",
                        m->SocksProxies != NULL ? "proxy" : "server",
                        (int)(PartialData - Entity));
                CLOSE_SOCKET(s);
                continue;
            }

            if( Ctx.ServerIndex < 0 ||
                Ctx.ServerIndex >= AddressList_GetNumberOfAddresses(&(m->ServiceList)) )
            {
                CLOSE_SOCKET(s);
                continue;
            }
            p2 = m->Agents[Ctx.ServerIndex];
            Ctx.LastActivity = time(NULL);
            Ctx.MsgCtx = NULL;
            /* m->Agents[] pullers are also mutated by TcpM_Send's connect path
               (TcpM_Connect_Recycle) under m->Lock; serialize this re-add. */
            EFFECTIVE_LOCK_GET(m->Lock);
            p2->Add(p2, s, &Ctx, sizeof(TcpContext));
            EFFECTIVE_LOCK_RELEASE(m->Lock);

            /* `ReceiveBuffer` lives on the stack and is reused by every
               iteration. When `IHeader_Fill` fails it returns before
               refreshing `Domain`, `HashValue` and `EntityLength`, so
               continuing here would match the malformed answer against the
               previous request and send it to that requester. */
            memset(Header, 0, sizeof(IHeader));
            if( IHeader_Fill(Header,
                             FALSE,
                             Entity,
                             TotalLength,
                             NULL,
                             INVALID_SOCKET,
                             AF_UNSPEC,
                             NULL
                             )
                != 0 )
            {
                WARNING("TCP %s returned a malformed message, discarded.\n",
                        m->SocksProxies != NULL ? "proxy" : "server");
                /* The matching client query stays in the context unanswered;
                   release its TCP socket hold. */
                MsgContext_ReleaseSocket(MsgCtx);
                continue;
            }

            switch( IPMiscMapping_Process(MsgCtx) )
            {
            case IP_MISC_NOTHING:
                break;

            case IP_MISC_FILTERED_IP:
                ShowBlockedMessage(Header, "Bad package, discarded");
                DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
                /* Query dropped without a response: release the TCP socket hold. */
                MsgContext_ReleaseSocket(MsgCtx);
                continue;
                break;

            case IP_MISC_NEGATIVE_RESULT:
                ShowBlockedMessage(Header, "Negative result, discarded");
                DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
                /* Query dropped without a response: release the TCP socket hold. */
                MsgContext_ReleaseSocket(MsgCtx);
                continue;
                break;

            default:
                ERRORMSG("Fatal error 155.\n");
                /* Query dropped without a response: release the TCP socket hold. */
                MsgContext_ReleaseSocket(MsgCtx);
                continue;
                break;
            }

            if( MsgContext_IsBlocked(MsgCtx) )
            {
                ShowBlockedMessage(Header, "False package, discarded");
                DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
                /* Query dropped without a response: release the TCP socket hold. */
                MsgContext_ReleaseSocket(MsgCtx);
                continue;
            }

            /* GenAnswerHeaderAndRemove mutates the per-module context BST, which
               is also touched by TcpM_Send() (frontend thread) under m->Lock. */
            EFFECTIVE_LOCK_GET(m->Lock);
            State = m->Context.GenAnswerHeaderAndRemove(&(m->Context), MsgCtx, MsgCtx);
            EFFECTIVE_LOCK_RELEASE(m->Lock);

            DNSCache_AddItemsToCache(MsgCtx, State == 0);

            if( State != 0 )
            {
                /* Query dropped without a response: release the TCP socket hold. */
                MsgContext_ReleaseSocket(MsgCtx);
                continue;
            }

            if( MsgContext_SendBack(MsgCtx) != 0 )
            {
                ShowErrorMessage(Header, 'T');
                continue;
            }

            ShowNormalMessage(Header, 'T');
            DomainStatistic_Add(Header, STATISTIC_TYPE_TCP);
        }
    }

    TcpM_Cleanup(m);

    return 0;
}

int TcpM_Init(TcpM *m, const char *Services, BOOL Parallel, const char *SocksProxies)
{
    int ret;

    if( m == NULL || Services == NULL )
    {
        return -7;
    }

    /* `Services` and `SocksProxies` may point into storage the caller
       releases as soon as this function returns (a group file holds its
       arguments in a temporary StringChunk), whereas the module keeps
       reporting both names in its logs for its whole lifetime. Own private
       copies. */
    m->ServiceName = strdup(Services);
    if( m->ServiceName == NULL )
    {
        return -8;
    }

    if( SocksProxies == NULL )
    {
        m->ProxyName = NULL;
    } else {
        m->ProxyName = strdup(SocksProxies);
        if( m->ProxyName == NULL )
        {
            free((void *)(m->ServiceName));
            m->ServiceName = NULL;
            return -9;
        }
    }

    if( ModuleContext_Init(&(m->Context), SOCKET_CONTEXT_LENGTH) != 0 )
    {
        ret = -12;
        goto EXIT_0;
    }

    if( SocketPuller_Init(&(m->Puller), sizeof(TcpContext)) != 0 )
    {
        ret = -389;
        goto EXIT_1;
    }

    m->Incoming = TryBindLocal(Ipv6_Enabled, 10400, &(m->IncomingAddr));
    if( m->Incoming == INVALID_SOCKET )
    {
        ret = -357;
        goto EXIT_1;
    }

    m->Puller.Add(&(m->Puller), m->Incoming, NULL, 0);

    if( AddressList_Init(&(m->ServiceList)) != 0 )
    {
        ret = -17;
        goto EXIT_2;
    } else {
        StringList l;
        StringListIterator i;
        const char *Itr;

        if( StringList_Init(&l, Services, ", ") != 0 )
        {
            ret = -23;
            goto EXIT_2;
        }

        l.TrimAll(&l, "\t .");

        if( StringListIterator_Init(&i, &l) != 0 )
        {
            ret = -29;
            goto EXIT_2;
        }

        while( (Itr = i.Next(&i)) != NULL )
        {
            AddressList_Add_From_String(&(m->ServiceList), Itr, 53);
        }

        l.Free(&l);
    }

    m->Services = AddressList_GetPtrList(&(m->ServiceList),
                                         &(m->ServiceFamilies)
                                         );
    if( m->Services == NULL )
    {
        ret = -45;
        goto EXIT_3;
    }

    if( SocketPuller_Init(&(m->QueryPuller), sizeof(TcpContext) ) != 0 )
    {
        ret = -46;
        goto EXIT_4;
    }

    m->Agents = SocketPullers_Init( AddressList_GetNumberOfAddresses(&(m->ServiceList)), sizeof(TcpContext) );
    if( m->Agents == NULL )
    {
        ret = -47;
        goto EXIT_5;
    }

    if( SocksProxies == NULL )
    {
        m->SocksProxies = NULL;
        m->SocksProxyFamilies = NULL;
    } else {
        /* Proxied */
        if( AddressList_Init(&(m->SocksProxyList)) != 0 )
        {
            ret = -53;
            goto EXIT_6;
        } else {
            StringList l;
            StringListIterator i;
            const char *Itr;

            if( StringList_Init(&l, SocksProxies, ", ") != 0 )
            {
                ret = -61;
                goto EXIT_7;
            }

            l.TrimAll(&l, "\t .");

            if( StringListIterator_Init(&i, &l) != 0 )
            {
                l.Free(&l);
                ret = -58;
                goto EXIT_7;
            }

            while( (Itr = i.Next(&i)) != NULL )
            {
                AddressList_Add_From_String(&(m->SocksProxyList), Itr, 1080);
            }

            l.Free(&l);

            m->SocksProxies = AddressList_GetPtrList(&(m->SocksProxyList),
                                                      &(m->SocksProxyFamilies)
                                                      );

            if( m->SocksProxies == NULL )
            {
                ret = -84;
                goto EXIT_7;
            }

            if( SocketPuller_Init(&(m->ProxyPuller), sizeof(TcpContext)) != 0 )
            {
                ret = -85;
                goto EXIT_8;
            }

            m->Proxies = SocketPullers_Init( AddressList_GetNumberOfAddresses(&(m->SocksProxyList)), sizeof(TcpContext) );
            if( m->Proxies == NULL )
            {
                ret = -86;
                goto EXIT_9;
            }

        }
    }

    m->Send = TcpM_Send;

    m->Parallel = Parallel;
    m->IsServer = 1;
    EFFECTIVE_LOCK_INIT(m->Lock);

    CREATE_THREAD(TcpM_Works, m, m->WorkThread);
    DETACH_THREAD(m->WorkThread);

    return 0;

EXIT_9:
    m->ProxyPuller.FreeWithoutClose(&(m->ProxyPuller));
EXIT_8:
    SafeFree(m->SocksProxies);
EXIT_7:
    AddressList_Free(&(m->SocksProxyList));

EXIT_6:
    SocketPullers_Free(m->Agents);
EXIT_5:
    m->QueryPuller.FreeWithoutClose(&(m->QueryPuller));
EXIT_4:
    SafeFree(m->Services);

EXIT_3:
    AddressList_Free(&(m->ServiceList));
EXIT_2:
    m->Puller.Free(&(m->Puller));
EXIT_1:
    ModuleContext_Free(&(m->Context));
EXIT_0:
    free((void *)(m->ServiceName));
    m->ServiceName = NULL;
    free((void *)(m->ProxyName));
    m->ProxyName = NULL;
    return ret;
}
