#ifndef LOGS_H_INCLUDED
#define LOGS_H_INCLUDED

#include "readconfig.h"
#include "common.h"
#include "iheader.h"

#define PRINTON     Log_Inited()

#define DEBUGSECTION    if( Log_DebugOn() )

int Log_Init(ConfigFileInfo *ConfigInfo, BOOL PrintScreen, BOOL Debug);

BOOL Log_Inited(void);

BOOL Log_DebugOn(void);

void Log_Print(const char *Type, const char *format, ...);

/* Variadic macros are a C99 feature; the named form below is a GCC/Clang
   extension that -pedantic-errors still rejects, so suppress that one warning
   locally.  The macros expand to a plain Log_Print() call. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#define ERRORMSG(ARGS...)   Log_Print("ERROR", ##ARGS)
#define WARNING(ARGS...)    Log_Print("WARN", ##ARGS)
#define INFO(ARGS...)       Log_Print("INFO", ##ARGS)
#define DEBUG(ARGS...)      DEBUGSECTION \
                            Log_Print("DEBUG", ##ARGS);
#pragma GCC diagnostic pop

void ShowRefusingMessage(IHeader *h, const char *Message);

void ShowTimeOutMessage(const IHeader *h, char Protocol);

void ShowErrorMessage(IHeader *h, char Protocol);

void ShowNormalMessage(IHeader *h, char Protocol);

void ShowBlockedMessage(IHeader *h, const char *Message);

void ShowSocketError(const char *Prompts, int ErrorNum);

#endif /* LOGS_H_INCLUDED */
