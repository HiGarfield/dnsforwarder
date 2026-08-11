#include <string.h>
#include <time.h>
#include "udpm.h"
#include "logs.h"
#include "utils.h"
#include "dnscache.h"
#include "ipmisc.h"
#include "domainstatistic.h"
#include "timedtask.h"

static void SweepWorks(MsgContext *MsgCtx, int Number, UdpM *Module)
{
    IHeader *h = (IHeader *)MsgCtx;

    ShowTimeOutMessage(h, 'U');
    DomainStatistic_Add(h, STATISTIC_TYPE_REFUSED);
    ++(Module->CountOfTimeout);

    if( Number == 1 )
    {
        AddressList_Advance(&(Module->AddrList));
    }
}

static int SweepTask(UdpM *m, SweepCallback cb)
{
    EFFECTIVE_LOCK_GET(m->Lock);
    m->Context.Sweep(&(m->Context), cb, m);
    EFFECTIVE_LOCK_RELEASE(m->Lock);

    return 0;
}

static int
#ifdef _WIN32
WINAPI
#endif
UdpM_Sweep_Thread(UdpM *m)
{
    for( ; ; )
    {
        int KeepSweeping;

        /* Read the lifecycle flags under the lock.  Must release before
         * calling SweepTask(), which takes the same (non-recursive) spin
         * lock itself, otherwise we would deadlock on re-entry. */
        EFFECTIVE_LOCK_GET(m->Lock);
        KeepSweeping = m->IsServer || (m->WorkThread != NULL_THREAD);
        EFFECTIVE_LOCK_RELEASE(m->Lock);

        if( !KeepSweeping )
        {
            break;
        }

        SweepTask(m, (SweepCallback)SweepWorks);
        SLEEP(10000);
    }

    ModuleContext_Free(&(m->Context));
    EFFECTIVE_LOCK_DESTROY(m->Lock);

    free((void *)(m->ServiceName));
    m->ServiceName = NULL;

    /* Publish "sweep thread exited" under the lock. */
    EFFECTIVE_LOCK_GET(m->Lock);
    m->SweepThread = NULL_THREAD;
    EFFECTIVE_LOCK_RELEASE(m->Lock);

    return 0;
}

static int UdpM_Cleanup(UdpM *m)
{
    m->IsServer = 0;

    CLOSE_SOCKET(m->Departure);
    m->Departure = INVALID_SOCKET;

    SafeFree(m->Parallels.addrs);
    AddressList_Free(&(m->AddrList));

    /* Publish "thread exited" under the lock so Modules_SafeCleanup's wait
     * loop reads it synchronously instead of racing on a plain write. */
    EFFECTIVE_LOCK_GET(m->Lock);
    m->WorkThread = NULL_THREAD;
    EFFECTIVE_LOCK_RELEASE(m->Lock);

    return 0;
}

static void
#ifdef _WIN32
WINAPI
#endif
UdpM_Works(UdpM *m)
{
    static const struct timeval ShortTime = {10, 0};
    struct timeval Timeout;

    struct sockaddr *addr;

    char ReceiveBuffer[SOCKET_CONTEXT_LENGTH];
    MsgContext *MsgCtx;
    IHeader *Header;

    #define LEFT_LENGTH  (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))
    char *Entity;

    fd_set  ReadSet, ReadySet;

    /* Make analyzer happy. */
    FD_ZERO(&ReadSet);

    MsgCtx = (MsgContext *)ReceiveBuffer;
    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    for( ; ; )
    {
        int RecvState;
        int ContextState;
        int KeepServing;

        /* IsServer is toggled to 0 by Modules_SafeCleanup on shutdown.  Read
         * it under the module spin lock so the read is synchronized with that
         * writer (otherwise helgrind flags a data race and the access is UB). */
        EFFECTIVE_LOCK_GET(m->Lock);
        KeepServing = m->IsServer;
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        if( !KeepServing )
        {
            break;
        }

        /* Set up socket */
        if( m->Departure == INVALID_SOCKET )
        {
            sa_family_t family;

            EFFECTIVE_LOCK_GET(m->Lock);
            if( m->Parallels.addrs == NULL )
            {
                addr = AddressList_GetOne(&(m->AddrList), &family);
                if( addr == NULL )
                {
                    ERRORMSG("Fatal error 53.\n");
                    EFFECTIVE_LOCK_RELEASE(m->Lock);
                    break;
                }

            } else { /* Parallel query */
                family = m->Parallels.familiy;
            }
            m->Departure = socket(family, SOCK_DGRAM, IPPROTO_UDP);

            if( m->Departure == INVALID_SOCKET )
            {
                ERRORMSG("Fatal error 68.\n");
                EFFECTIVE_LOCK_RELEASE(m->Lock);
                break;
            }

#if defined(_WIN32) && defined(IPV6_V6ONLY)
            if( family == AF_INET6 )
            {
                SetSocketIPv6V6only(m->Departure, 0);
            }
#endif

            /* m->Lock is already held for the socket-setup block; the
               sweep thread also touches CountOfTimeout, so reset it here
               under the same lock to avoid a data race. */
            m->CountOfTimeout = 0;

            EFFECTIVE_LOCK_RELEASE(m->Lock);

            FD_ZERO(&ReadSet);
            FD_SET(m->Departure, &ReadSet);
        }

        ReadySet = ReadSet;
        Timeout = ShortTime;
        switch( select(m->Departure + 1, &ReadySet, NULL, NULL, &Timeout) )
        {
            case SOCKET_ERROR:
                WARNING("SOCKET_ERROR reached, 98.\n");
                FD_CLR(m->Departure, &ReadSet);
                CLOSE_SOCKET(m->Departure);
                m->Departure = INVALID_SOCKET;
                continue;
                break;

            case 0:
                #define RECREATION_THRESHOLD    8
                {
                    int CountOfTimeout;

                    /* Read CountOfTimeout under the lock: the sweep thread
                       increments it concurrently, so a plain read is a data
                       race that can yield a torn value. */
                    EFFECTIVE_LOCK_GET(m->Lock);
                    CountOfTimeout = m->CountOfTimeout;
                    EFFECTIVE_LOCK_RELEASE(m->Lock);

                    if( CountOfTimeout > RECREATION_THRESHOLD )
                    {
                        FD_CLR(m->Departure, &ReadSet);
                        CLOSE_SOCKET(m->Departure);
                        m->Departure = INVALID_SOCKET;

                        WARNING("UDP socket is about to be recreated.\n");
                    }
                }
                continue;
                break;

            default:
                /* Goto recv job */
                break;
        }

        /* recv */
        RecvState = recvfrom(m->Departure,
                             Entity,
                             LEFT_LENGTH,
                             0,
                             NULL,
                             NULL
                             );

        if( RecvState <= 0 )
        {
            ERRORMSG("recvfrom %s error: %d\n", m->ServiceName, RecvState);
            continue;
        }

        EFFECTIVE_LOCK_GET(m->Lock);
        m->CountOfTimeout = 0;
        EFFECTIVE_LOCK_RELEASE(m->Lock);

        /* Fill IHeader. Start from a clean slate so that, if IHeader_Fill
           bails out early on a malformed packet (e.g. < 12 bytes), the
           downstream code never reads uninitialized stack bytes left in
           ReceiveBuffer. Skip the packet entirely when parsing fails. */
        memset(Header, 0, sizeof(IHeader));
        if( IHeader_Fill(Header,
                         FALSE,
                         Entity,
                         RecvState,
                         NULL,
                         INVALID_SOCKET,
                         AF_UNSPEC,
                         NULL
                         ) != 0 )
        {
            continue;
        }

        switch( IPMiscMapping_Process(MsgCtx) )
        {
        case IP_MISC_NOTHING:
            break;

        case IP_MISC_FILTERED_IP:
            ShowBlockedMessage(Header, "Bad package, discarded");
            DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
            continue;
            break;

        case IP_MISC_NEGATIVE_RESULT:
            ShowBlockedMessage(Header, "Negative result, discarded");
            DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
            continue;
            break;

        default:
            ERRORMSG("Fatal error 155.\n");
            continue;
            break;
        }

        if( MsgContext_IsBlocked(MsgCtx) )
        {
            ShowBlockedMessage(Header, "False package, discarded");
            DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
            continue;
        }

        /* Fetch context item */
        EFFECTIVE_LOCK_GET(m->Lock);
        ContextState = m->Context.GenAnswerHeaderAndRemove(&(m->Context), MsgCtx, MsgCtx);
        EFFECTIVE_LOCK_RELEASE(m->Lock);

        DNSCache_AddItemsToCache(MsgCtx, ContextState == 0);

        if( ContextState != 0 )
        {
            continue;
        }

        if( MsgContext_SendBack(MsgCtx) != 0 )
        {
            ShowErrorMessage(Header, 'U');
            continue;
        }

        ShowNormalMessage(Header, 'U');
        DomainStatistic_Add(Header, STATISTIC_TYPE_UDP);
    }

    UdpM_Cleanup(m);
}

static int UdpM_Send(UdpM *m,
                     const char *Buffer,
                     int BufferLength
                     )
{
    int ret = 0;
    const IHeader *h = (IHeader *)Buffer;

    MsgContext_AddFakeEdns((MsgContext *)Buffer, BufferLength);

    EFFECTIVE_LOCK_GET(m->Lock);
    if( m->Context.Add(&(m->Context), (MsgContext *)Buffer) == NULL )
    {
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        return -242;
    }

    /* Keep m->Lock held across the send: m->Departure / m->AddrList /
     * m->Parallels are protected by m->Lock and may be torn down by the
     * UdpM_Works reconfiguration thread. Using them outside the lock is a
     * TOCTOU race (sendto on a closed/changed socket). */
    if( m->Departure != INVALID_SOCKET )
    {
        if( m->Parallels.addrs != NULL )
        { /* Parallel query */
            struct sockaddr **a = m->Parallels.addrs;

            while( *a != NULL )
            {
                int State;

                State = sendto(m->Departure,
                               (const void *)(h + 1),
                               h->EntityLength,
                               MSG_NOSIGNAL,
                               *a,
                               m->Parallels.addrlen
                               );

                ret |= (State > 0);

                ++a;
            }

        } else {
            struct sockaddr *a;
            sa_family_t family;

            int State;

            a = AddressList_GetOne(&(m->AddrList), &family);
            if( a == NULL )
            {
                ERRORMSG("Fatal error 205.\n");
                /* Roll back the Context entry we just registered, otherwise the
                 * stale context leaks and is counted as an unanswered query. */
                m->Context.Del(&(m->Context), (MsgContext *)Buffer);
                EFFECTIVE_LOCK_RELEASE(m->Lock);
                return -277;
            }

            State = sendto(m->Departure,
                           (const void *)(h + 1),
                           h->EntityLength,
                           MSG_NOSIGNAL,
                           a,
                           GetAddressLength(family)
                           );

            ret = (State > 0);

            /** TODO: Error handlings */

        }
    } else {
        /* m->Departure is not ready yet: the Context we registered above would
           otherwise leak and be counted as an unanswered query forever. Roll it
           back and report the failure. */
        m->Context.Del(&(m->Context), (MsgContext *)Buffer);
        ret = 0;
    }

    EFFECTIVE_LOCK_RELEASE(m->Lock);
    return !ret;
}

int UdpM_Init(UdpM *m, const char *Services, BOOL Parallel)
{
    StringList  Addresses;
    StringListIterator  sli;
    const char *Itr;
    int ret;

    if( m == NULL || Services == NULL )
    {
        return -141;
    }

    /* `Services` may point into storage the caller releases as soon as this
       function returns (a group file holds its arguments in a temporary
       StringChunk), whereas the module keeps reporting the name in its logs
       for its whole lifetime. Own a private copy. */
    m->ServiceName = strdup(Services);
    if( m->ServiceName == NULL )
    {
        return -147;
    }

    m->Departure = INVALID_SOCKET;
    if( StringList_Init(&Addresses, Services, ", ") != 0 )
    {
        ret = -364;
        goto EXIT_0;
    }

    Addresses.TrimAll(&Addresses, "\t .");

    if( StringListIterator_Init(&sli, &Addresses) != 0 )
    {
        ret = -169;
        goto EXIT_1;
    }

    if( AddressList_Init(&(m->AddrList)) != 0 )
    {
        ret = -171;
        goto EXIT_1;
    }

    Itr = sli.Next(&sli);
    while( Itr != NULL )
    {
        AddressList_Add_From_String(&(m->AddrList), Itr, 53);
        Itr = sli.Next(&sli);
    }

    Addresses.Free(&Addresses);

    if( Parallel )
    {
        if( AddressList_GetOneBySubscript(&(m->AddrList),
                                          &(m->Parallels.familiy),
                                          0
                                          )
           == NULL )
        {
            ret = -184;
            goto EXIT_2;
        }

        m->Parallels.addrs =
            AddressList_GetPtrListOfFamily(&(m->AddrList),
                                           m->Parallels.familiy
                                           );

        m->Parallels.addrlen = GetAddressLength(m->Parallels.familiy);

    } else {
        m->Parallels.addrs = NULL;
        m->Parallels.familiy = AF_UNSPEC;
        m->Parallels.addrlen = 0;
    }

    if( ModuleContext_Init(&(m->Context), SOCKET_CONTEXT_LENGTH) != 0 )
    {
        ret = -143;
        goto EXIT_3;
    }

    m->CountOfTimeout = 0;

    m->IsServer = 1;

    EFFECTIVE_LOCK_INIT(m->Lock);

    m->Send = UdpM_Send;

    CREATE_THREAD(UdpM_Works, m, m->WorkThread);
    DETACH_THREAD(m->WorkThread);
    CREATE_THREAD(UdpM_Sweep_Thread, m, m->SweepThread);
    DETACH_THREAD(m->SweepThread);

    return 0;

EXIT_3:
    SafeFree(m->Parallels.addrs);
EXIT_2:
    AddressList_Free(&(m->AddrList));
    goto EXIT_0;

EXIT_1:
    Addresses.Free(&Addresses);

EXIT_0:
    free((void *)(m->ServiceName));
    m->ServiceName = NULL;
    return ret;
}
