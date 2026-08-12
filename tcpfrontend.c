#include "tcpfrontend.h"
#include "socketpuller.h"
#include "addresslist.h"
#include "utils.h"
#include "mmgr.h"
#include "logs.h"

extern BOOL Ipv6_Enabled;

static SocketPuller Frontend;

#define LEFT_LENGTH  (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))

/*
 * Per-connection state, kept inside the socket puller.
 *
 * The one and only frontend thread serves every TCP client, so it must never
 * wait for a particular one of them: a client that opens a connection and
 * then sends nothing (or sends one octet of the two-octet length prefix and
 * stalls) would otherwise park the thread in recv() forever and no other TCP
 * client -- already connected or not -- could be served again. Reassembly
 * therefore has to survive across select() rounds, which means every
 * connection needs somewhere to keep the part of the message that has arrived
 * so far.
 *
 * `Addr' must stay first: a listening socket is told apart from an
 * established connection by the sa_family stored at the very beginning of the
 * record, and listening sockets are registered with an all-zero (AF_UNSPEC)
 * address.
 */
typedef struct {
    Address_Type    Addr;

    int             PrefixRead;     /* octets of the length prefix received */
    int             BodyRead;       /* octets of the body received */
    int             BodyLength;     /* announced length, once PrefixRead == 2 */

    char            Prefix[2];
    char            Body[LEFT_LENGTH];
} TcpClientState;

static void
#ifdef WIN32
WINAPI
#endif
TcpFrontend_Work(void *Unused)
{
    char *ReceiveBuffer;
    IHeader *Header;

    char *Entity;

    ReceiveBuffer = SafeMalloc(SOCKET_CONTEXT_LENGTH);
    if( ReceiveBuffer == NULL )
    {
        ERRORMSG("No enough memory, 26.\n");
        return;
    }

    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    /* Loop */
    while( TRUE )
    {
        SOCKET sock, sock_c;
        TcpClientState *State;
        void *Data;

        int RecvState;
        uint16_t TCPLength;

        char Agent[sizeof(Header->Agent)];

        sock = Frontend.Select(&Frontend,
                               NULL,
                               &Data,
                               TRUE,
                               FALSE,
                               NULL
                               );

        if( sock == INVALID_SOCKET )
        {
            ERRORMSG("Fatal error 58.\n");
            break;
        }

        State = (TcpClientState *)Data;

        if( ((struct sockaddr *)&(State->Addr))->sa_family == AF_UNSPEC )
        {
            /* A listening socket. Take the connection and hand it to
               select(); reading from it right here would block the whole
               frontend until this particular client decides to talk. */
            TcpClientState NewState;
            socklen_t AddrLen = sizeof(Address_Type);

            memset(&NewState, 0, sizeof(NewState));

            sock_c = accept(sock,
                            (struct sockaddr *)&(NewState.Addr.Addr),
                            &AddrLen
                            );
            if( sock_c == INVALID_SOCKET )
            {
                continue;
            }

            NewState.Addr.family =
                ((struct sockaddr *)&(NewState.Addr.Addr))->sa_family;

            if( Frontend.Add(&Frontend,
                             sock_c,
                             &NewState,
                             sizeof(NewState)
                             )
                != 0 )
            {
                CLOSE_SOCKET(sock_c);
            }

            continue;
        }

        sock_c = sock;

        if( State->Addr.family == AF_INET )
        {
            IPv4AddressToAsc(&(State->Addr.Addr.Addr4.sin_addr), Agent);
        } else {
            IPv6AddressToAsc(&(State->Addr.Addr.Addr6.sin6_addr), Agent);
        }

        /* Exactly one recv() per readiness notification. select() only
           promises that a single read will not block, so a second one in the
           same round could hang on a client that sent just a part of its
           message. Whatever arrives is accumulated in the connection's own
           state and the message is dispatched once it is complete. */
        if( State->PrefixRead < 2 )
        {
            RecvState = recv(sock_c,
                             State->Prefix + State->PrefixRead,
                             2 - State->PrefixRead,
                             0
                             );
            if( RecvState <= 0 )
            {
                /* RecvState == 0: peer closed (FIN); < 0: socket error. */
                if( RecvState < 0 )
                {
                    INFO("Connection error from TCP client %s.\n", Agent);
                } else {
                    INFO("TCP client %s disconnected.\n", Agent);
                }
                goto DropClient;
            }

            State->PrefixRead += RecvState;
            if( State->PrefixRead < 2 )
            {
                continue;
            }

            memcpy(&TCPLength, State->Prefix, 2);
            TCPLength = ntohs(TCPLength);

            if( TCPLength == 0 || TCPLength > LEFT_LENGTH )
            {
                WARNING("TCP client %s segment is too large, discarded.\n",
                        Agent
                        );
                goto DropClient;
            }

            State->BodyLength = TCPLength;
            State->BodyRead = 0;

            continue;
        }

        RecvState = recv(sock_c,
                         State->Body + State->BodyRead,
                         State->BodyLength - State->BodyRead,
                         0
                         );
        if( RecvState <= 0 )
        {
            if( RecvState < 0 )
            {
                INFO("Connection error from TCP client %s.\n", Agent);
            } else {
                INFO("TCP client %s disconnected.\n", Agent);
            }
            goto DropClient;
        }

        State->BodyRead += RecvState;
        if( State->BodyRead < State->BodyLength )
        {
            continue;
        }

        /* A whole message. Move it into the dispatch buffer and get the
           connection ready for the next one; TCP clients are allowed to
           pipeline queries over the same connection. */
        {
            int EntityLength = State->BodyLength;
            sa_family_t Family = State->Addr.family;

            memcpy(Entity, State->Body, EntityLength);

            State->PrefixRead = 0;
            State->BodyRead = 0;
            State->BodyLength = 0;

            /* `IHeader_Fill` returns before filling in
               `SendBackSocket` and `EntityLength` when the message
               is malformed. Since `ReceiveBuffer` is shared by all
               clients, sending such a context on would reply to the
               previously served client with stale data. */
            if( IHeader_Fill(Header,
                             FALSE,
                             Entity,
                             EntityLength,
                             NULL,
                             sock_c,
                             Family,
                             Agent
                             )
                != 0 )
            {
                INFO("Malformed message received from TCP client %s.\n",
                     Agent
                     );
                goto DropClient;
            }

            MMgr_Send(ReceiveBuffer, SOCKET_CONTEXT_LENGTH);
        }

        continue;

DropClient:
        /* `State' points into the puller's storage, so it must not be touched
           after the entry is removed. */
        Frontend.Del(&Frontend, sock_c);
        CLOSE_SOCKET(sock_c);
    }

    SafeFree(ReceiveBuffer);
}

void TcpFrontend_StartWork(void)
{
    ThreadHandle t;

    CREATE_THREAD(TcpFrontend_Work, NULL, t);
    DETACH_THREAD(t);
}

static void TcpFrontend_Cleanup(void)
{
    /* Do NOT free the global Frontend here: TcpFrontend_Work is a detached
       thread blocked in Frontend.Select() and may still read Frontend's
       internals (socket list, BST array) when atexit runs, which would be a
       use-after-free. The process is exiting and the OS reclaims the memory,
       so leaving it unfreed is the safe choice. */
}

int TcpFrontend_Init(ConfigFileInfo *ConfigInfo, BOOL StartWork)
{
    StringList *TCPLocal;
    StringListIterator i;
    const char *One;

    int Count = 0;

    TCPLocal = ConfigGetStringList(ConfigInfo, "TCPLocal");
    if( TCPLocal == NULL )
    {
        WARNING("No TCP interface specified.\n");
        return -11;
    }

    if( StringListIterator_Init(&i, TCPLocal) != 0 )
    {
        return -20;
    }

    if( SocketPuller_Init(&Frontend, sizeof(TcpClientState)) != 0 )
    {
        return -19;
    }

    while( (One = i.Next(&i)) != NULL )
    {
        Address_Type a;
        TcpClientState ListeningState;
        sa_family_t f;

        SOCKET sock;

        f = AddressList_ConvertFromString(&a, One, 53);
        if( f == AF_UNSPEC )
        {
            ERRORMSG("Invalid TCPLocal option: %s .\n", One);
            continue;
        }

        sock = socket(f, SOCK_STREAM, IPPROTO_TCP);
        if( sock == INVALID_SOCKET )
        {
            continue;
        }

        if( bind(sock,
                 (const struct sockaddr *)&(a.Addr),
                 GetAddressLength(f)
                 )
            != 0 )
        {
            char p[128];

            snprintf(p, sizeof(p), "Opening TCP interface %s failed", One);
            p[sizeof(p) - 1] = '\0';

            ShowSocketError(p, GET_LAST_ERROR());
            CLOSE_SOCKET(sock);
            continue;
        }

        if( listen(sock, 16) == SOCKET_ERROR )
        {
            /* Only this interface failed. Close its socket and move on to the
               remaining TCPLocal entries, exactly like the socket()/bind()
               failure paths above; breaking out of the loop would leak the
               descriptor and silently discard every interface that has not
               been processed yet. */
            ERRORMSG("Can't listen on interface: %s .\n", One);
            CLOSE_SOCKET(sock);
            continue;
        }

        if( f == AF_INET6 )
        {
            Ipv6_Enabled = TRUE;
        }

        memset(&ListeningState, 0, sizeof(ListeningState));
        /* Tag the listening socket with AF_UNSPEC so TcpFrontend_Work can
           tell it apart from an established connection and call accept() on
           it. Established connections are registered by TcpFrontend_Work with
           the real family, which routes them to the recv() branch. */
        ListeningState.Addr.family = AF_UNSPEC;
        Frontend.Add(&Frontend, sock, &ListeningState, sizeof(ListeningState));
        INFO("TCP interface %s opened.\n", One);
        ++Count;
    }

    atexit(TcpFrontend_Cleanup);

    if( Count == 0 )
    {
        ERRORMSG("No TCP interface opened.\n");
        return -163;
    }

    if( StartWork )
    {
        TcpFrontend_StartWork();
    }

    return 0;
}
