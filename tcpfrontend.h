#ifndef TCPFRONTEND_H_INCLUDED
#define TCPFRONTEND_H_INCLUDED

#include "readconfig.h"

void TcpFrontend_StartWork(void);

int TcpFrontend_Init(ConfigFileInfo *ConfigInfo, BOOL StartWork);

/* Released by the module worker thread once it has finished using a TCP
   client socket for one dispatched query (it owns the send back via
   MsgContext_SendBack). The frontend owns the socket's lifecycle and may
   close it only once every in-flight dispatch has been released. A no-op for
   UDP, where the descriptor is the shared server socket. */
void TcpFrontend_ReleaseSocket(SOCKET s);

#endif /* TCPFRONTEND_H_INCLUDED */
