#include <string.h>
#include "hosts.h"
#include "addresslist.h"
#include "mcontext.h"
#include "socketpuller.h"
#include "goodiplist.h"
#include "logs.h"
#include "domainstatistic.h"
#include "mmgr.h"

extern BOOL Ipv6_Enabled;

static BOOL BlockIpv6WhenIpv4Exists = FALSE;

static SOCKET   InnerSocket = INVALID_SOCKET;
static Address_Type InnerAddress;
static SocketPuller Puller;

/* Set by Hosts_Cleanup() (atexit) so the detached Hosts_SocketLoop thread
   stops touching the StaticHosts/DynamicHosts containers (freed by their own
   cleanups) and the sockets as the process tears down. */
static volatile BOOL    Hosts_ToExit = FALSE;
static ThreadHandle     Hosts_Thread = NULL_THREAD;
static SOCKET           OuterSocket = INVALID_SOCKET;
/* Set true only after a successful SocketPuller_Init so Hosts_Cleanup never
   calls a NULL Puller.Free (e.g. when TryBindLocal or SocketPuller_Init
   failed before reaching it). */
static volatile BOOL    PullerReady = FALSE;

/* Query identifier of the single outer query currently in flight.  It is set
   right before MMgr_Send() and the response is only accepted when its own
   identifier matches, so a stray/replayed/unsolicited datagram can never be
   matched to the pending context. */
static uint16_t OuterQueryIdentifier = 0;

BOOL Hosts_TypeExisting(const char *Domain, HostsRecordType Type)
{
    return StaticHosts_TypeExisting(Domain, Type) ||
           DynamicHosts_TypeExisting(Domain, Type);
}

static HostsUtilsTryResult Hosts_Try_Inner(MsgContext *MsgCtx, int BufferLength)
{
    HostsUtilsTryResult ret;

    ret = StaticHosts_Try(MsgCtx, BufferLength);
    if( ret != HOSTSUTILS_TRY_NONE )
    {
        return ret;
    }

    return DynamicHosts_Try(MsgCtx, BufferLength);
}

static int Hosts_GetCName(const char *Domain, char *Buffer)
{
    return !(StaticHosts_GetCName(Domain, Buffer) == 0 ||
           DynamicHosts_GetCName(Domain, Buffer) == 0);
}

/* Called by ModuleContext_Sweep() right before it deletes a timed-out
   context.  If that context is the one OuterHeader->Parent currently points
   at (i.e. the outer query is still in flight while its back-trace context
   expired), clear the pointer: a response arriving later must be dropped
   rather than dereferenced through the about-to-be-recycled BST node. */
static void Hosts_SweepCallback(const MsgContext *MsgCtx, int Number, void *Arg)
{
    IHeader *OuterHeader = (IHeader *)Arg;

    (void)Number;

    if( OuterHeader != NULL && OuterHeader->Parent == (IHeader *)MsgCtx )
    {
        OuterHeader->Parent = NULL;
    }
}

HostsUtilsTryResult Hosts_Try(MsgContext *MsgCtx, int BufferLength)
{
    HostsUtilsTryResult ret;
    IHeader *Header = (IHeader *)MsgCtx;

    if( BlockIpv6WhenIpv4Exists )
    {
        if( Header->Type == DNS_TYPE_AAAA &&
            (Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_A) ||
             Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_GOOD_IP_LIST)
             )
            )
        {
            /** TODO: Show blocked message */
            return HOSTSUTILS_TRY_BLOCKED;
        }
    }

    if( Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_EXCLUEDE) )
    {
        return HOSTSUTILS_TRY_NONE;
    }

    ret = Hosts_Try_Inner(MsgCtx, BufferLength);

    if( ret == HOSTSUTILS_TRY_RECURSED )
    {
        if( sendto(InnerSocket,
                   (const char *)Header, /* Only send header and identifier */
                   sizeof(IHeader) + sizeof(uint16_t), /* Only send header and identifier */
                   MSG_NOSIGNAL,
                   (const struct sockaddr *)&(InnerAddress.Addr),
                   GetAddressLength(InnerAddress.family)
                   )
            < 0 )
        {
            return HOSTSUTILS_TRY_NONE;
        }
    }

    return ret;
}

int Hosts_Get(MsgContext *MsgCtx, int BufferLength)
{
    IHeader *Header = (IHeader *)MsgCtx;

    switch( Hosts_Try(MsgCtx, BufferLength) )
    {
    case HOSTSUTILS_TRY_BLOCKED:
        MsgContext_SendBackRefusedMessage(MsgCtx);
        ShowRefusingMessage(Header, "Disabled because of existing IPv4 host");
        DomainStatistic_Add(Header, STATISTIC_TYPE_REFUSED);
        return 0;
        break;

    case HOSTSUTILS_TRY_NONE:
        return -126;
        break;

    case HOSTSUTILS_TRY_RECURSED:
        /** TODO: Show hosts message */
        return 0;

    case HOSTSUTILS_TRY_OK:
        ShowNormalMessage(Header, 'H');
        DomainStatistic_Add(Header, STATISTIC_TYPE_HOSTS);
        return 0;
        break;

    default:
        return -139;
        break;
    }
}

static int
#ifdef WIN32
WINAPI
#endif
Hosts_SocketLoop(void *Unused)
{
    ModuleContext Context;

    Address_Type OuterAddress;

    const struct timeval LongTime = {3600, 0};
    const struct timeval ShortTime = {10, 0};
    /* Bounded timeout used to poll Hosts_ToExit promptly during shutdown. */
    const struct timeval ExitTime = {1, 0};

    struct timeval  TimeLimit = LongTime;

    #define LEFT_LENGTH_SL (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))

    char    InnerBuffer[SOCKET_CONTEXT_LENGTH];
    MsgContext *InnerMsgCtx = (MsgContext *)InnerBuffer;
    IHeader *InnerHeader = (IHeader *)InnerBuffer;
    /* char    *InnerEntity = InnerBuffer + sizeof(IHeader); */

    char OuterBuffer[SOCKET_CONTEXT_LENGTH];
    /* MsgContext *OuterMsgCtx = (MsgContext *)OuterBuffer; */
    IHeader *OuterHeader = (IHeader *)OuterBuffer;

    int State;
    int ret = 0;

    OuterSocket = TryBindLocal(Ipv6_Enabled, 10300, &OuterAddress);

    if( OuterSocket == INVALID_SOCKET )
    {
        return -416;
    }

    if( SocketPuller_Init(&Puller, 0) != 0 )
    {
        /* Puller is only partially initialized on failure (e.g. StableBuffer
           inside the backing BST did not come up); do NOT run Puller.Free on
           it. Hosts_Cleanup is also guarded by PullerReady, which is still
           FALSE here, so nothing frees it later either. */
        return -423;
    }
    PullerReady = TRUE;

    Puller.Add(&Puller, InnerSocket, NULL, 0);
    Puller.Add(&Puller, OuterSocket, NULL, 0);

    if( ModuleContext_Init(&Context, SOCKET_CONTEXT_LENGTH) != 0 )
    {
        ret = -431;
        goto EXIT_1;
    }

    srand(time(NULL));

    /* OuterBuffer is a shared stack buffer.  The response datagram is
       recvfrom()'d over the beginning of it (overwriting the IHeader
       stored there), so the fields that identify the pending query must be
       captured before that overwrite.  Start with a NULL Parent so an
       unsolicited datagram is never matched to a stale/uninitialised
       pointer. */
    OuterHeader->Parent = NULL;
    OuterQueryIdentifier = 0;

    while( TRUE )
    {
        SOCKET  Pulled;
        int Err;

        /* Bound the wait so we re-check Hosts_ToExit in a timely manner
           during shutdown (the normal LongTime/ShortTime sweep logic still
           applies otherwise). */
        if( Hosts_ToExit )
        {
            TimeLimit = ExitTime;
        }

        Pulled = Puller.Select(&Puller, &TimeLimit, NULL, TRUE, FALSE, &Err);

        /* Stop touching the containers/sockets once cleanup is underway. */
        if( Hosts_ToExit )
        {
            break;
        }
        if( Pulled == INVALID_SOCKET )
        {
            if( Err != 0 )
            {
                ERRORMSG("Fatal error 70.\n");
                break;
            }
            TimeLimit = LongTime;
            Context.Sweep(&Context, Hosts_SweepCallback, (void *)OuterBuffer);
        } else if( Pulled == InnerSocket )
        {
            /* Recursive query */
            MsgContext *MsgCtxStored;
            char RecursedDomain[DOMAIN_NAME_LENGTH_MAX + 1];
            uint16_t NewIdentifier;

            TimeLimit = ShortTime;

            State = recvfrom(InnerSocket,
                             InnerBuffer, /* Receiving a header */
                             sizeof(InnerBuffer),
                             0,
                             NULL,
                             NULL
                             );

            if( State < 1 )
            {
                continue;
            }

            if( State < (int)sizeof(IHeader) )
            {
                /* A truncated datagram cannot carry a whole IHeader.  Anything
                   past `State` is leftover/uninitialized stack, so Domain would
                   not be NUL-terminated and Hosts_GetCName() would read (and
                   copy) indeterminate bytes.  Drop the datagram instead. */
                continue;
            }

            if( Hosts_GetCName(InnerHeader->Domain, RecursedDomain) != 0 )
            {
                ERRORMSG("Fatal error 221.\n");
                continue;
            }

            NewIdentifier = rand();

            if( HostsUtils_GenerateQuery(OuterBuffer,
                                         SOCKET_CONTEXT_LENGTH,
                                         OuterSocket,
                                         &OuterAddress,
                                         MsgContext_IsFromTCP(InnerMsgCtx),
                                         NewIdentifier,
                                         RecursedDomain,
                                         InnerHeader->Type
                                         )
                != 0 )
            {
                /** TODO: Show an error */
                continue;
            }

            MsgCtxStored = Context.Add(&Context, InnerMsgCtx);
            if( MsgCtxStored == NULL )
            {
                ERRORMSG("Fatal error 230.\n");
                continue;
            }

            OuterHeader->Parent = (IHeader *)MsgCtxStored;
            OuterQueryIdentifier = NewIdentifier;

            MMgr_Send(OuterBuffer, SOCKET_CONTEXT_LENGTH);

        } else if( Pulled == OuterSocket )
        {
            IHeader *BackTraceHeader;
            MsgContext *BackTraceMsgCtx;
            char RecursedDomain[DOMAIN_NAME_LENGTH_MAX + 1];
            uint16_t QueryIdentifier;

            TimeLimit = ShortTime;

            /* Everything that identifies the pending query -- the parent
               context pointer and the recursed domain -- lives inside
               OuterBuffer, which the recvfrom() below is about to overwrite
               with the response.  Capture them BEFORE the receive: a
               datagram long enough to reach the Parent/Domain fields would
               otherwise hand bytes of the response (or, if nothing was ever
               sent, uninitialised stack memory) to be dereferenced as a
               pointer and parsed as a domain name. */
            BackTraceHeader = OuterHeader->Parent;
            BackTraceMsgCtx = (MsgContext *)BackTraceHeader;
            strncpy(RecursedDomain, OuterHeader->Domain, sizeof(RecursedDomain) - 1);
            RecursedDomain[sizeof(RecursedDomain) - 1] = '\0';

            State = recvfrom(OuterSocket,
                             OuterBuffer, /* Receiving a header */
                             sizeof(OuterBuffer),
                             0,
                             NULL,
                             NULL
                             );

            if( State < 1 )
            {
                continue;
            }

            if( BackTraceHeader == NULL )
            {
                /* No query is in flight (nothing was ever sent, or the
                   pending context was swept after its timeout): this
                   datagram cannot be matched to a live context, so drop it
                   instead of dereferencing a stale pointer. */
                continue;
            }

            /* The response datagram overwrote OuterBuffer's beginning.  Its
               query identifier must equal the one we put into the outer
               query, otherwise this is a stray/replayed/unsolicited packet
               that must not consume the pending context.  State is checked
               against DNS_HEADER_LENGTH so the two identifier octets are
               guaranteed to have been received. */
            if( State < DNS_HEADER_LENGTH ||
                DNSGetQueryIdentifier(OuterBuffer) != OuterQueryIdentifier
                )
            {
                continue;
            }

            /* Capture the original query identifier BEFORE
               GenAnswerHeaderAndRemove() resets and deletes the back-trace
               context: it unlinks the BST node (placing it on the free list),
               so reading BackTraceHeader + 1 afterwards is a use of a deleted
               object whose bytes may be recycled by the next Add. */
            QueryIdentifier = DNSGetQueryIdentifier(BackTraceHeader + 1);

            if( Context.GenAnswerHeaderAndRemove(&Context, BackTraceMsgCtx, InnerMsgCtx) != 0 )
            {
                /* The inner (recursed) context is gone -- it was swept after
                   its timeout while this outer response was in flight. Do not
                   touch BackTraceHeader any further (it may have been reset /
                   recycled); just drop the response. */
                ERRORMSG("Fatal error 267.\n");
                OuterHeader->Parent = NULL;
                OuterQueryIdentifier = 0;
                continue;
            }

            /* The back-trace context is now removed from the BST.  Clear the
               parent slot so a later (replayed) response is dropped instead
               of dereferencing the deleted node. */
            OuterHeader->Parent = NULL;
            OuterQueryIdentifier = 0;
            DNSSetQueryIdentifier(InnerHeader + 1, QueryIdentifier);

            /* The response was recvfrom()'d into the *beginning* of
               OuterBuffer (OuterBuffer[0 .. State)); the former `OuterEntity'
               argument pointed at the stale query we sent, not at the
               response.  Use OuterBuffer so the recursed response is actually
               parsed, and the pre-captured RecursedDomain (not the bytes of
               the response, which may have overwritten OuterHeader->Domain). */
            if( HostsUtils_CombineRecursedResponse((MsgContext *)InnerBuffer,
                                                   SOCKET_CONTEXT_LENGTH,
                                                   OuterBuffer,
                                                   State,
                                                   RecursedDomain
                                                   )
                != 0 )
            {
                ERRORMSG("Fatal error 279.\n");
                continue;
            }

            if( MsgContext_SendBack((MsgContext *)InnerBuffer) != 0 )
            {
                ERRORMSG("Fatal error 285.\n");
                continue;
            }

            ShowNormalMessage(InnerHeader, 'H');
        }
    }

    /* Reached on Hosts_ToExit break: free the per-thread context but leave
       Puller to Hosts_Cleanup (which also closes the sockets and joins us),
       avoiding a double free. */
    ModuleContext_Free(&Context);

    return ret;

EXIT_1:
    /* Puller.Free() closes both sockets via CloseAll; clear the module-level
       states so Hosts_Cleanup() (atexit) neither double-frees the puller
       (it checks PullerReady) nor double-closes the sockets. */
    Puller.Free(&Puller);
    PullerReady = FALSE;
    InnerSocket = INVALID_SOCKET;
    OuterSocket = INVALID_SOCKET;

    return ret;
}

static void Hosts_Cleanup(void)
{
    /* Stop the worker before StaticHosts_Cleanup / DynamicHosts_Cleanup free
       the containers it may still be reading, and close the sockets/puller it
       uses. Registered via atexit after those two, so it runs first (LIFO). */
    Hosts_ToExit = TRUE;

    if( InnerSocket != INVALID_SOCKET )
    {
        CLOSE_SOCKET(InnerSocket);
        InnerSocket = INVALID_SOCKET;
    }

    if( OuterSocket != INVALID_SOCKET )
    {
        CLOSE_SOCKET(OuterSocket);
        OuterSocket = INVALID_SOCKET;
    }

    if( Hosts_Thread != NULL_THREAD )
    {
        JOIN_THREAD(Hosts_Thread);
        Hosts_Thread = NULL_THREAD;
    }

    if( PullerReady )
    {
        Puller.Free(&Puller);
        PullerReady = FALSE;
    }
}

int Hosts_Init(ConfigFileInfo *ConfigInfo)
{
    ThreadHandle t;

    StaticHosts_Init(ConfigInfo);
    DynamicHosts_Init(ConfigInfo);

    GoodIpList_Init(ConfigInfo);

    BlockIpv6WhenIpv4Exists = ConfigGetBoolean(ConfigInfo,
                                                 "BlockIpv6WhenIpv4Exists"
                                                 );

    InnerSocket = TryBindLocal(Ipv6_Enabled, 10200, &InnerAddress);
    if( InnerSocket == INVALID_SOCKET )
    {
        return -25;
    }

    /* CREATE_THREAD expands to pthread_create() on POSIX (value is the int
       return code, 0 on success) and assigns a HANDLE on Windows (compare
       against NULL_THREAD). Capture accordingly. */
#ifdef _WIN32
    CREATE_THREAD(Hosts_SocketLoop, NULL, t);
    if( t == NULL_THREAD )
    {
        ERRORMSG("Failed to start Hosts socket loop thread.\n");
        CLOSE_SOCKET(InnerSocket);
        InnerSocket = INVALID_SOCKET;
        return -402;
    }
#else
    {
        int thr_ret = CREATE_THREAD(Hosts_SocketLoop, NULL, t);
        if( thr_ret != 0 )
        {
            ERRORMSG("Failed to start Hosts socket loop thread: %d\n", thr_ret);
            CLOSE_SOCKET(InnerSocket);
            InnerSocket = INVALID_SOCKET;
            return -402;
        }
    }
#endif
    Hosts_Thread = t;

    /* Register cleanup last so it runs first (atexit is LIFO) and stops the
       worker before StaticHosts_Cleanup / DynamicHosts_Cleanup free the
       containers it reads. */
    atexit(Hosts_Cleanup);

    return 0;
}
