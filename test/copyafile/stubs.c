/* Minimal stub definitions for the external symbols referenced by utils.c that
 * are not provided by libc. Only CopyAFile() is exercised by the test, but the
 * whole translation unit is linked, so every symbol it references must exist.
 * These stubs are trivial no-ops so the unit test links without the daemon. */
#include <stdarg.h>
#include <stdio.h>
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
