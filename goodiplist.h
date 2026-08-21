#ifndef GOODIPLIST_H_INCLUDED
#define GOODIPLIST_H_INCLUDED

#include "readconfig.h"

int GoodIpList_Init(ConfigFileInfo *ConfigInfo);

/* Copy the 4 bytes of the currently-fastest IPv4 address of `List` into
   Address (must hold at least 4 bytes).  Returns 0 on success, -1 if the
   list does not exist, is empty, or Address is NULL.  The copy happens while
   holding ListLock, so the measurement task (ThreadJod) cannot swap the list
   elements out from under the caller. */
int GoodIpList_Get(const char *List, void *Address);

#endif /* GOODIPLIST_H_INCLUDED */
