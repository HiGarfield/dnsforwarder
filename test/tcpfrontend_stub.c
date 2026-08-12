/* Test stub for the TCP socket-ownership release.
 *
 * The dnsparser unit tests only exercise the message parser and the message
 * context, never a live TCP client connection, so the frontend's
 * TcpFrontend_ReleaseSocket() (which lives in tcpfrontend.c alongside the whole
 * frontend) is irrelevant here. Provide a no-op definition so iheader.c links
 * without pulling in the entire frontend and its dependencies. */
#include "tcpfrontend.h"

void TcpFrontend_ReleaseSocket(SOCKET s)
{
    (void)s;
}
