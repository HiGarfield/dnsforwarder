/*
 * LD_PRELOAD helper for test/tcpfrontend_listen_fail/run.sh.
 *
 * Makes the very first listen() call of the process fail with EOPNOTSUPP and
 * lets every subsequent call through. dnsforwarder calls listen() only from
 * TcpFrontend_Init(), so this reliably breaks exactly the first TCPLocal
 * interface without touching anything else.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

int listen(int Socket, int Backlog)
{
    static int (*Real)(int, int) = NULL;
    static int Called = 0;

    if( Real == NULL )
    {
        Real = (int (*)(int, int))dlsym(RTLD_NEXT, "listen");
    }

    if( Called++ == 0 )
    {
        errno = EOPNOTSUPP;
        return -1;
    }

    if( Real == NULL )
    {
        errno = ENOSYS;
        return -1;
    }

    return Real(Socket, Backlog);
}
