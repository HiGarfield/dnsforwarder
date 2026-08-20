/*
 * Minimal stub definitions for symbols pulled in by the production object files
 * when they are compiled into a small regression test, but which would otherwise
 * be provided by the full daemon (frontends, logging, configuration, timers,
 * good-IP-list).  These are intentionally no-ops: the regression tests exercise
 * only the unit under test and never take a real code path that depends on the
 * behaviour of these routines.
 */
#include <stdarg.h>
#include "common.h"
#include "ipchunk.h"

void TcpFrontend_ReleaseSocket(SOCKET s)
{
    (void)s;
}

/* goodiplist.c: HostsUtils_Generate only calls GoodIpList_Get for the
   HOSTS_TYPE_GOOD_IP_LIST branch, which the regression tests never reach. */
const char *GoodIpList_Get(const void *Data)
{
    (void)Data;
    return NULL;
}

/* Logging: the production logs.c pulls in configuration routines that are not
   linked into these unit tests.  Provide a trivial Log_Print that discards its
   output. */
void Log_Print(const char *Type, const char *format, ...)
{
    (void)Type;
    (void)format;
}
