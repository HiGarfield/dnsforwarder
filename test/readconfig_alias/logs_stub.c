/* Minimal stubs for logging/DNS symbols so the alias-resolution unit test can
   be linked without pulling in the whole DNS stack (logs.c -> dnsparser.c ->
   dnscache.c ...). The test does not exercise logging paths. */
#include <stdarg.h>
#include "dnsparser.h"
#include "logs.h"

void Log_Print(const char *Type, const char *format, ...)
{
    (void)Type;
    (void)format;
}

const char *DNSGetTypeName(uint16_t Num)
{
    (void)Num;
    return "";
}

char *GetAllAnswers(char *DNSBody, int DNSBodyLength, char *Buffer, int BufferLength)
{
    (void)DNSBody;
    (void)DNSBodyLength;
    (void)Buffer;
    (void)BufferLength;
    return NULL;
}
