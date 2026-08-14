/* Recording stub for the TCP socket-ownership release.
 *
 * Unlike test/tcpfrontend_stub.c (a plain no-op), this stub counts how many
 * times TcpFrontend_ReleaseSocket() is called and remembers the last socket it
 * was handed, so a unit test can assert that ModuleContext_Sweep() actually
 * releases the hold it took when the query was dispatched. main.c reads the two
 * globals below.
 */

#include "tcpfrontend.h"

int g_ReleaseCount = 0;
int g_LastSocket   = -1;

void TcpFrontend_ReleaseSocket(SOCKET s)
{
    g_ReleaseCount++;
    g_LastSocket = (int)s;
}
