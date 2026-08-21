#ifndef TCPM_C_INCLUDED
#define TCPM_C_INCLUDED

#include "mcontext.h"
#include "addresslist.h"
#include "socketpuller.h"

typedef struct _TcpM TcpM;

struct _TcpM {
    /* private */
    SOCKET          Incoming;
    Address_Type    IncomingAddr;
    SocketPuller    Puller;

    ModuleContext   Context;

    ThreadHandle    WorkThread;

    /* Spin lock guarding the lifecycle flags (IsServer / WorkThread) so that
     * the shutdown path (Modules_SafeCleanup) can read them without racing
     * against the worker thread that writes them on exit. */
    EFFECTIVE_LOCK  Lock;

    int IsServer;

    const char      *ServiceName;
    AddressList     ServiceList;
    struct sockaddr **Services;
    sa_family_t     *ServiceFamilies;
    SocketPuller    QueryPuller;
    SocketPuller    **Agents;

    const char      *ProxyName;
    AddressList     SocksProxyList;
    struct sockaddr **SocksProxies;
    sa_family_t     *SocksProxyFamilies;
    SocketPuller    ProxyPuller;
    SocketPuller    **Proxies;

    /* TCP 3-way handshake is heavier. Connect all, and then choose. */
    BOOL            Parallel;

    /* public */
    int (*Send)(void *m,
                const char *Buffer,
                int BufferLength
                );
};

int TcpM_Init(TcpM *m, const char *Services, BOOL Parallel, const char *SocksProxies);

#endif /* TCPM_C_INCLUDED */
