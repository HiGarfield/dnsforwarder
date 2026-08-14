/* ModuleContext_Sweep() must release the TCP client socket hold for a query
 * that is abandoned as timed-out, exactly like every other drop path
 * (MsgContext_SendBack, the Filter_Out / no-module paths in MMgr_Send, and the
 * module rollbacks).
 *
 * The TCP socket ownership is a reference count kept in the frontend:
 * TcpSocketInFlight[s] is bumped when a query is dispatched from client socket
 * s and dropped by TcpFrontend_ReleaseSocket() once the module thread is done
 * with it. TcpFrontend_ClientGone() closes s only after the count reaches zero,
 * so until then the descriptor is held open for potential later answers.
 *
 * ModuleContext_Sweep() used to delete the timed-out entry without releasing
 * the hold, so a TCP client query that the upstream silently dropped left
 * TcpSocketInFlight[s] pinned at 1 forever. TcpFrontend_ClientGone() then
 * refused to close s (it only marked it Gone), and the daemon leaked one
 * descriptor per timed-out TCP query until it could no longer accept
 * connections.
 *
 * This test registers a TCP query, forces it past the 2-second sweep deadline,
 * and checks that the recording stub saw exactly one release for that socket.
 * The pre-fix code never released it, so the assertion would fail there.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mcontext.h"
#include "iheader.h"
#include "dnsgenerator.h"

extern int g_ReleaseCount;
extern int g_LastSocket;

#define ENTITY_OFFSET   ((int)sizeof(IHeader))

static void BuildQuery(char *Buffer, int Id, const char *Domain, int IsTcp, int Socket)
{
    IHeader *h = (IHeader *)Buffer;
    DnsGenerator g;

    memset(Buffer, 0, SOCKET_CONTEXT_LENGTH);

    if( DnsGenerator_Init(&g,
                          Buffer + ENTITY_OFFSET,
                          SOCKET_CONTEXT_LENGTH - ENTITY_OFFSET,
                          NULL,
                          0,
                          FALSE
                          )
       != 0 )
    {
        fprintf(stderr, "DnsGenerator_Init failed\n");
        exit(2);
    }

    g.SetIdentifier(&g, (uint16_t)Id);
    if( g.Question(&g, Domain, DNS_TYPE_A, DNS_CLASS_IN) != 0 )
    {
        fprintf(stderr, "Question failed\n");
        exit(2);
    }

    h->EntityLength = g.Length(&g);

    /* A TCP client context is recognized by BackAddress.family == AF_UNSPEC
     * (see MsgContext_IsFromTCP). UDP carries a real address family. */
    h->BackAddress.family = IsTcp ? AF_UNSPEC : AF_INET;
    h->SendBackSocket = Socket;
    h->Parent = NULL;
    h->RequestTcp = IsTcp ? TRUE : FALSE;
    h->EDNSEnabled = FALSE;
    strcpy(h->Domain, Domain);
    h->HashValue = 0;
    strcpy(h->Agent, "t");
}

int main(void)
{
    ModuleContext c;
    char *Buffer;
    MsgContext *Stored;

    g_ReleaseCount = 0;
    g_LastSocket = -1;

    if( ModuleContext_Init(&c, SOCKET_CONTEXT_LENGTH) != 0 )
    {
        fprintf(stderr, "ModuleContext_Init failed\n");
        return 2;
    }

    Buffer = malloc(SOCKET_CONTEXT_LENGTH);
    if( Buffer == NULL )
    {
        return 2;
    }

    /* A TCP client query that has already exceeded the 2-second sweep
     * deadline. */
    BuildQuery(Buffer, 0x1111, "leak.example.com", 1, 7);
    Stored = c.Add(&c, (MsgContext *)Buffer);
    if( Stored == NULL )
    {
        fprintf(stderr, "Add failed\n");
        return 2;
    }
    ((IHeader *)Stored)->Timestamp = time(NULL) - 10;

    c.Sweep(&c, NULL, NULL);

    if( g_ReleaseCount != 1 )
    {
        fprintf(stderr,
                "FAIL: expected 1 ReleaseSocket call for a swept TCP entry, "
                "got %d\n",
                g_ReleaseCount);
        return 1;
    }
    if( g_LastSocket != 7 )
    {
        fprintf(stderr,
                "FAIL: ReleaseSocket called with socket %d, expected 7\n",
                g_LastSocket);
        return 1;
    }

    /* A UDP entry must never release a per-client socket: its SendBackSocket is
     * the shared server socket, so MsgContext_ReleaseSocket is a no-op there. */
    g_ReleaseCount = 0;
    g_LastSocket = -1;
    BuildQuery(Buffer, 0x2222, "udp.example.com", 0, 9);
    Stored = c.Add(&c, (MsgContext *)Buffer);
    if( Stored == NULL )
    {
        fprintf(stderr, "Add failed (udp)\n");
        return 2;
    }
    ((IHeader *)Stored)->Timestamp = time(NULL) - 10;

    c.Sweep(&c, NULL, NULL);

    if( g_ReleaseCount != 0 )
    {
        fprintf(stderr,
                "FAIL: a UDP entry must not release a socket, got %d\n",
                g_ReleaseCount);
        return 1;
    }

    free(Buffer);
    ModuleContext_Free(&c);

    printf("ModuleContext_Sweep releases the TCP socket hold for timed-out queries\n");
    return 0;
}
