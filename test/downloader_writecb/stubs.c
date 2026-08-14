/* Minimal stub definitions for the external symbols referenced by
 * downloader.c.  Only WriteFileCallback() is exercised by the test, but the
 * whole translation unit is linked, so every symbol it references must exist.
 * These stubs are intentionally no-ops / trivial so the unit test links
 * without pulling in the entire daemon. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

void Log_Print(const char *Type, const char *format, ...)
{
    (void)Type; (void)format;
}

BOOL ConfigGetBoolean(void *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return FALSE;
}

const char *ConfigGetRawString(void *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return NULL;
}

int32_t ConfigGetInt32(void *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return 0;
}

const char *DNSGetTypeName(int Type)
{
    (void)Type;
    return "UNK";
}

int GetAllAnswers(const void *MsgCtx, char *Buffer, int BufferLength)
{
    (void)MsgCtx; (void)Buffer; (void)BufferLength;
    return 0;
}

int CopyAFile(const char *Src, const char *Dst, BOOL Append)
{
    (void)Src; (void)Dst; (void)Append;
    return 0;
}

SOCKET TryBindLocal(BOOL Ipv6, int Port, void *Addr)
{
    (void)Ipv6; (void)Port; (void)Addr;
    return INVALID_SOCKET;
}

char *GetLocalPathFromURL(const char *URL, char *Out, int OutLen)
{
    (void)URL;
    if( OutLen > 1 ) { Out[0] = '\0'; }
    return Out;
}

void *SafeMalloc(size_t n)
{
    return malloc(n);
}

void SafeFree(void *p)
{
    free(p);
}
