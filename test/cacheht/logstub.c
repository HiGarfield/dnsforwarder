/* Minimal logging stubs so cacheht.c can be linked in a standalone test
 * without dragging in the whole project (config + iheader + dns stack). */
#include "common.h"

struct _ConfigFileInfo;

int Log_Init(struct _ConfigFileInfo *ConfigInfo, BOOL PrintScreen, BOOL Debug)
{
    (void)ConfigInfo; (void)PrintScreen; (void)Debug;
    return 0;
}

BOOL Log_Inited(void) { return 1; }

BOOL Log_DebugOn(void) { return 0; }   /* keep DEBUG output quiet */

void Log_Print(const char *Type, const char *format, ...)
{
    (void)Type; (void)format;
}
