/* Regression test for the hosts.c EXIT_1 teardown bug found in the Round-3
   review:

   Bug: when SocketPuller_Init() succeeded but ModuleContext_Init() failed,
   Hosts_SocketLoop() fell through to EXIT_1, which called Puller.Free() --
   closing InnerSocket/OuterSocket via CloseAll -- but left PullerReady == TRUE
   and the two socket globals untouched.  Hosts_Cleanup() (atexit) then:
     * double-freed the puller (it checks PullerReady), and
     * double-closed the sockets (close() on an already-closed descriptor
       can reuse another thread's descriptor).

   Fix: EXIT_1 now clears PullerReady and marks both sockets INVALID_SOCKET
   after Puller.Free().  Additionally, when SocketPuller_Init() itself fails,
   Hosts_SocketLoop() returns immediately instead of running Puller.Free() on
   a partially-initialized puller.

   The static declarations of hosts.c are exposed (via the #define static
   trick) so the test can drive Hosts_SocketLoop / Hosts_Cleanup directly and
   inspect PullerReady / InnerSocket / OuterSocket.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Headers used by hosts.c -- included BEFORE the static-export trick so their
   own static declarations are left untouched. */
#include "common.h"
#include "hosts.h"
#include "addresslist.h"
#include "mcontext.h"
#include "socketpuller.h"
#include "goodiplist.h"
#include "logs.h"
#include "domainstatistic.h"
#include "mmgr.h"

/* ---- stubs -------------------------------------------------------------- */

BOOL Ipv6_Enabled = FALSE;

/* Succeeds with a real UDP socket so SocketPuller_Add/FD_SET work. */
SOCKET TryBindLocal(BOOL Ipv6, int StartPort, Address_Type *Address)
{
    SOCKET s;

    (void)Ipv6; (void)StartPort;

    memset(Address, 0, sizeof(*Address));
    Address->family = AF_INET;
    Address->Addr.Addr4.sin_family = AF_INET;
    Address->Addr.Addr4.sin_port = htons((unsigned short)StartPort);
    Address->Addr.Addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    return s;
}

int GetAddressLength(sa_family_t Family)
{
    (void)Family;
    return sizeof(struct sockaddr_in);
}

/* ModuleContext_Init always fails -> drives Hosts_SocketLoop into EXIT_1. */
int ModuleContext_Init(ModuleContext *c, int ItemLength)
{
    (void)c; (void)ItemLength;
    return -1;
}

void ModuleContext_Free(ModuleContext *c)
{
    (void)c;
}

int MsgContext_SendBack(MsgContext *MsgCtx)
{
    (void)MsgCtx;
    return 0;
}

int MsgContext_SendBackRefusedMessage(MsgContext *MsgCtx)
{
    (void)MsgCtx;
    return 0;
}

void MsgContext_ReleaseSocket(MsgContext *MsgCtx)
{
    (void)MsgCtx;
}

void ShowNormalMessage(IHeader *h, char Protocol)
{
    (void)h; (void)Protocol;
}

void ShowRefusingMessage(IHeader *h, const char *Message)
{
    (void)h; (void)Message;
}

int DomainStatistic_Add(IHeader *h, StatisticType Type)
{
    (void)h; (void)Type;
    return 0;
}

int StaticHosts_GetCName(const char *Domain, char *Buffer)
{
    (void)Domain;
    strcpy(Buffer, "1.2.3.4");
    return 0;
}

BOOL StaticHosts_TypeExisting(const char *Domain, HostsRecordType Type)
{
    (void)Domain; (void)Type;
    return FALSE;
}

HostsUtilsTryResult StaticHosts_Try(MsgContext *MsgCtx, int BufferLength)
{
    (void)MsgCtx; (void)BufferLength;
    return HOSTSUTILS_TRY_NONE;
}

int DynamicHosts_GetCName(const char *Domain, char *Buffer)
{
    (void)Domain;
    strcpy(Buffer, "1.2.3.4");
    return 0;
}

BOOL DynamicHosts_TypeExisting(const char *Domain, HostsRecordType Type)
{
    (void)Domain; (void)Type;
    return FALSE;
}

HostsUtilsTryResult DynamicHosts_Try(MsgContext *MsgCtx, int BufferLength)
{
    (void)MsgCtx; (void)BufferLength;
    return HOSTSUTILS_TRY_NONE;
}

BOOL ConfigGetBoolean(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return FALSE;
}

/* ---- further link stubs (code paths not exercised by this test) ------ */

BOOL MsgContext_IsFromTCP(const MsgContext *MsgCtx)
{
    (void)MsgCtx;
    return FALSE;
}

int HostsUtils_GenerateQuery(char *RequestBuffer, int BufferLength,
                             SOCKET Socket, Address_Type *BackAddress,
                             BOOL RequestTcp, uint16_t Identifier,
                             const char *Name, DNSRecordType Type)
{
    (void)RequestBuffer; (void)BufferLength; (void)Socket;
    (void)BackAddress; (void)RequestTcp; (void)Identifier;
    (void)Name; (void)Type;
    return -1;
}

int HostsUtils_CombineRecursedResponse(MsgContext *Buffer, int Bufferlength,
                                       char *RecursedEntity, int EntityLength,
                                       const char *RecursedDomain)
{
    (void)Buffer; (void)Bufferlength; (void)RecursedEntity;
    (void)EntityLength; (void)RecursedDomain;
    return -1;
}

int MMgr_Send(const char *Buffer, int BufferLength)
{
    (void)Buffer; (void)BufferLength;
    return -1;
}

int StaticHosts_Init(ConfigFileInfo *ConfigInfo) { (void)ConfigInfo; return 0; }
int DynamicHosts_Init(ConfigFileInfo *ConfigInfo) { (void)ConfigInfo; return 0; }
int GoodIpList_Init(ConfigFileInfo *ConfigInfo) { (void)ConfigInfo; return 0; }

int FatalErrorDecideding(int ErrorNum)
{
    (void)ErrorNum;
    return 0;
}

int SafeRealloc(void **Memory_ptr, size_t NewBytes)
{
    void *New = realloc(*Memory_ptr, NewBytes);
    if( New != NULL )
    {
        *Memory_ptr = New;
        return 0;
    }
    return -1;
}

/* ---- expose the private declarations of hosts.c ----------------------- */
#define static
#include "hosts.c"
#undef static

static int Checks = 0;
static int Failures = 0;

static void expect(const char *what, int cond)
{
    ++Checks;
    if( cond )
    {
        printf("  [ ok ] %s\n", what);
    } else {
        ++Failures;
        printf("  [FAIL] %s\n", what);
    }
}

int main(void)
{
    int ret;

    printf("== hosts.c EXIT_1 double-free/double-close regression tests ==\n\n");

    expect("state starts clean",
           PullerReady == FALSE &&
           InnerSocket == INVALID_SOCKET &&
           OuterSocket == INVALID_SOCKET);

    /* Hosts_SocketLoop: TryBindLocal OK -> SocketPuller_Init OK ->
       ModuleContext_Init fails -> EXIT_1 (Puller.Free + state clearing). */
    ret = Hosts_SocketLoop(NULL);

    expect("Hosts_SocketLoop returns the ModuleContext init failure (-431)",
           ret == -431);
    expect("PullerReady is cleared after EXIT_1", PullerReady == FALSE);
    expect("InnerSocket is marked closed after EXIT_1",
           InnerSocket == INVALID_SOCKET);
    expect("OuterSocket is marked closed after EXIT_1",
           OuterSocket == INVALID_SOCKET);

    /* Hosts_Cleanup() must now be a complete no-op: no double free of the
       puller (guarded by PullerReady), no double close of the sockets, no
       join of a non-existent thread.  Under ASan a double-free here aborts. */
    Hosts_Cleanup();
    expect("Hosts_Cleanup leaves Hosts_Thread NULL", Hosts_Thread == NULL_THREAD);
    expect("Hosts_Cleanup leaves PullerReady FALSE", PullerReady == FALSE);
    expect("Hosts_Cleanup leaves InnerSocket INVALID", InnerSocket == INVALID_SOCKET);
    expect("Hosts_Cleanup leaves OuterSocket INVALID", OuterSocket == INVALID_SOCKET);

    /* Calling Hosts_Cleanup() again must also be safe (atexit idempotence). */
    Hosts_Cleanup();
    expect("a second Hosts_Cleanup is still safe", PullerReady == FALSE);

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
