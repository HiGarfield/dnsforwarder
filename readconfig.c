#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "readconfig.h"
#include "utils.h"
#include "readline.h"
#include "logs.h"

#define DUP_STRING(i, s)    ((Info)->StrBuffer.Add(&((Info)->StrBuffer), (s), NULL))

int ConfigInitInfo(ConfigFileInfo *Info)
{
    Info->fp = NULL;

    if( StringList_Init(&(Info->StrBuffer), NULL, NULL) != 0 )
    {
        return -14;
    }

    if( StringChunk_Init(&(Info->Options), NULL) != 0 )
    {
        return -19;
    }

    return 0;
}

int ConfigOpenFile(ConfigFileInfo *Info, const char *File)
{
    Info->fp = fopen(File, "r");
    if( Info->fp == NULL )
        return -56;
    else
        return 0;
}

int ConfigCloseFile(ConfigFileInfo *Info)
{
    return fclose(Info->fp);
}

int ConfigAddOption(ConfigFileInfo *Info,
                    const char *KeyName,
                    MultilineStrategy Strategy,
                    OptionType Type,
                    VType Initial
                    )
{
    ConfigOption New = {0};

    New.Type = Type;
    New.Status = STATUS_DEFAULT_VALUE;
    New.Strategy = Strategy;

    switch( Type )
    {
        case TYPE_INT32:
            New.Holder.INT32 = Initial.INT32;
            break;

        case TYPE_BOOLEAN:
            New.Holder.boolean = Initial.boolean;
            break;

        case TYPE_PATH:
        case TYPE_STRING:
            if( StringList_Init(&(New.Holder.str), Initial.str, ",") != 0 )
            {
                return -2;
            }

            New.Delimiters = ",";
            break;

        default:
            break;
    }

    return StringChunk_Add(&(Info->Options), KeyName, (const char *)&New, sizeof(ConfigOption));
}

int ConfigAddAlias(ConfigFileInfo *Info,
                   const char *Target,
                   const char *Alias,
                   const char *Prepending,
                   const char *StringDelimiters
                   )
{
    ConfigOption New = {0};

    New.Type = TYPE_ALIAS;

    New.Holder.Aliasing.Target = DUP_STRING(Info, Target);
    if( New.Holder.Aliasing.Target == NULL )
    {
        return -97;
    }

    if( Prepending != NULL )
    {
        New.Holder.Aliasing.Prepending = DUP_STRING(Info, Prepending);
        if( New.Holder.Aliasing.Prepending == NULL )
        {
            return -98;
        }
    } else {
        New.Holder.Aliasing.Prepending = NULL;
    }

    if( StringDelimiters != NULL )
    {
        New.Delimiters = DUP_STRING(Info, StringDelimiters);
    } else {
        New.Delimiters = NULL;
    }

    return StringChunk_Add(&(Info->Options),
                           Alias,
                           (const char *)&New,
                           sizeof(ConfigOption)
                           );
}

/* Cap the alias chain length. A cyclic alias (A -> B -> A, or A -> A) used to
   recurse forever and crash via stack overflow; this bounds the resolution. */
#define MAX_ALIAS_DEPTH    64

/* **Prepending and **StringDelimiters should be NULL before this is called */
static ConfigOption *GetOptionOfAInfoImpl(ConfigFileInfo *Info,
                                          const char *KeyName,
                                          const char **Prepending,
                                          const char **StringDelimiters,
                                          int Depth
                                          )
{
    ConfigOption *Option;

    if( Depth > MAX_ALIAS_DEPTH )
        return NULL;

    if( StringChunk_Match_NoWildCard(&(Info->Options), KeyName, NULL, (void **)&Option, NULL, NULL) == TRUE )
    {
        if( Option->Type == TYPE_ALIAS )
        {
            if( Prepending != NULL )
            {
                *Prepending = Option->Holder.Aliasing.Prepending;
            }

            if( StringDelimiters != NULL )
            {
                *StringDelimiters = Option->Delimiters;
            }

            return GetOptionOfAInfoImpl(Info,
                                        Option->Holder.Aliasing.Target,
                                        Prepending,
                                        StringDelimiters,
                                        Depth + 1
                                        );
        } else {
            return Option;
        }
    } else {
        return NULL;
    }
}

static ConfigOption *GetOptionOfAInfo(ConfigFileInfo *Info,
                                      const char *KeyName,
                                      const char **Prepending,
                                      const char **StringDelimiters
                                      )
{
    return GetOptionOfAInfoImpl(Info, KeyName, Prepending, StringDelimiters, 0);
}

int ConfigSetStringDelimiters(ConfigFileInfo *Info,
                              const char *KeyName,
                              const char *Delimiters
                              )
{
    ConfigOption *Option;

    Option = GetOptionOfAInfo(Info, KeyName, NULL, NULL);
    if( Option == NULL )
    {
        return -147;
    }

    if( Option->Type != TYPE_STRING )
    {
        return -148;
    }

    Option->Delimiters = DUP_STRING(Info, Delimiters);
    if( Option->Delimiters == NULL )
    {
        return -130;
    }

    return 0;
}

static BOOL GetBooleanValueFromString(const char *str)
{
    if( isdigit((unsigned char)*str) )
    {
        if( *str == '0' )
            return FALSE;
        else
            return TRUE;
    } else {
        char Dump[8];

        strncpy(Dump, str, sizeof(Dump));
        Dump[sizeof(Dump) - 1] = '\0';

        StrToLower(Dump);

        if( strcmp(Dump, "false") == 0 || strcmp(Dump, "no") == 0 )
            return FALSE;
        else if( strcmp(Dump, "true") == 0 || strcmp(Dump, "yes") == 0 )
            return TRUE;
    }

    return FALSE;
}

static void ParseBoolean(ConfigOption *Option, const char *Value)
{
    switch (Option->Strategy)
    {
        case STRATEGY_APPEND_DISCARD_DEFAULT:
            if( Option->Status == STATUS_DEFAULT_VALUE )
            {
                Option->Strategy = STRATEGY_APPEND;
            }
            /* fall through */

        case STRATEGY_DEFAULT:
        case STRATEGY_REPLACE:

            Option->Holder.boolean = GetBooleanValueFromString(Value);

            Option->Status = STATUS_SPECIAL_VALUE;
            break;

        case STRATEGY_APPEND:
            {
                BOOL SpecifiedValue;

                SpecifiedValue = GetBooleanValueFromString(Value);
                Option->Holder.boolean |= SpecifiedValue;

                Option->Status = STATUS_SPECIAL_VALUE;
            }
            break;

        default:
            break;

    }
}

static void ParseInt32(ConfigOption *Option, const char *KeyName, const char *Value)
{
    switch (Option->Strategy)
    {
        case STRATEGY_APPEND_DISCARD_DEFAULT:
            if( Option->Status == STATUS_DEFAULT_VALUE )
            {
                Option->Strategy = STRATEGY_APPEND;
            }
            /* fall through */

        case STRATEGY_DEFAULT:
        case STRATEGY_REPLACE:
            if( sscanf(Value, "%d", &(Option->Holder.INT32)) == 1 )
            {
                Option->Status = STATUS_SPECIAL_VALUE;
            } else {
                ERRORMSG("Ignoring invalid integer value for %s: %s\n",
                         KeyName, Value);
            }
            break;

        case STRATEGY_APPEND:
            {
                int32_t SpecifiedValue = 0;

                if( sscanf(Value, "%d", &SpecifiedValue) == 1 )
                {
                    Option->Holder.INT32 += SpecifiedValue;
                    Option->Status = STATUS_SPECIAL_VALUE;
                } else {
                    ERRORMSG("Ignoring invalid integer value for %s: %s\n",
                             KeyName, Value);
                }
            }
            break;

        default:
            break;
    }
}

static void ParseString(ConfigOption *Option,
                        const char *Delimiters,
                        const char *Value,
                        ReadLineStatus ReadStatus,
                        BOOL Trim,
                        FILE *fp,
                        char *Buffer,
                        int BufferLength
                        )
{
    switch( Option->Strategy )
    {
        case STRATEGY_APPEND_DISCARD_DEFAULT:
            if( Option->Status == STATUS_DEFAULT_VALUE )
            {
                Option->Strategy = STRATEGY_APPEND;
            }
            /* fall through */

        case STRATEGY_DEFAULT:
        case STRATEGY_REPLACE:
            Option->Holder.str.Clear(&(Option->Holder.str));
            /* fall through */

        case STRATEGY_APPEND:
            if( Option->Holder.str.Add(&(Option->Holder.str),
                                       Value,
                                       Delimiters
                                       )
                == NULL )
            {
                return;
            }
            Option->Status = STATUS_SPECIAL_VALUE;
            break;

        default:
            return;
            break;
    }

    /* NOTE: multi-line continuation was previously implemented as a
       `while( ReadStatus != READ_DONE )' loop that kept calling ReadLine and
       appending every following physical line to the current option's value.
       That was wrong: ConfigRead() above already calls ReadLine_GoToNextLine()
       to skip the remainder of any over-long line, so by the time we get here
       the file position points at the *next* independent config entry. The
       old loop therefore swallowed every subsequent line (and silently
       dropped the options those lines defined) whenever a TYPE_STRING/PATH
       option's value line exceeded the read buffer.

       A value spanning multiple physical lines is not a supported format in
       this project (multi-valued options use repeated keys, gathered by
       ConfigGetStringList). Drop the continuation loop entirely; the single
       value parsed above is the whole value. */

    if( Trim )
    {
        Option->Holder.str.TrimAll(&(Option->Holder.str), NULL);
    }
}

static char *TrimPath(char *Path)
{
    char *LastCharacter = StrRNpbrk(Path, "\"");

    if( LastCharacter != NULL )
    {
        char *FirstLetter;

        *(LastCharacter + 1) = '\0';

        FirstLetter = StrNpbrk(Path, "\"\t ");
        if( FirstLetter != NULL )
        {
            memmove(Path, FirstLetter, strlen(FirstLetter) + 1);
            return Path;
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }
}

int ConfigRead(ConfigFileInfo *Info)
{
    int             NumOfRead   =   0;

    char            Buffer[2048];

    char            *KeyName;
    ConfigOption    *Option;

    const char      *Prepending;
    const char      *StringDelimiters;

    while(TRUE){
        char            *ValuePos;
        ReadLineStatus  ReadStatus;

        ReadStatus = ReadLine(Info->fp, Buffer, sizeof(Buffer));
        if( ReadStatus == READ_FAILED_OR_END )
            return NumOfRead;

        if( ReadStatus == READ_TRUNCATED )
        {
            /* The line is longer than the read buffer, so Buffer holds only a
               fragment. Do not parse the fragment as a config entry; skip the
               rest of this (too long) line and continue with the next one. */
            ERRORMSG("Config line too long (>= %u bytes), skipped.\n",
                     (unsigned)(sizeof(Buffer) - 1));
            ReadLine_GoToNextLine(Info->fp);
            continue;
        }

        ValuePos = SplitNameAndValue(Buffer, " \t=");
        if( ValuePos == NULL )
            continue;

        KeyName = Buffer;

        Prepending = NULL;
        StringDelimiters = NULL;
        Option = GetOptionOfAInfo(Info,
                                  KeyName,
                                  &Prepending,
                                  &StringDelimiters
                                  );

        if( Option == NULL )
        {
            continue;
        }

        if( Prepending != NULL )
        {
            switch( Option->Type )
            {
                case TYPE_INT32:
                    ParseInt32(Option, KeyName, Prepending);
                    break;

                case TYPE_BOOLEAN:
                    ParseBoolean(Option, Prepending);
                    break;

                case TYPE_PATH:
                    StringDelimiters = "";
                    /* fall through */

                case TYPE_STRING:
                    ParseString(Option,
                                StringDelimiters == NULL ?
                                    Option->Delimiters : StringDelimiters,
                                Prepending,
                                READ_DONE,
                                FALSE,
                                Info->fp,
                                NULL,
                                0
                                );
                    break;

                default:
                    break;
            }
        }

        switch( Option->Type )
        {
            case TYPE_INT32:
                ParseInt32(Option, KeyName, ValuePos);
                break;

            case TYPE_BOOLEAN:
                ParseBoolean(Option, ValuePos);
                break;

            case TYPE_PATH:
                if( ReadStatus != READ_DONE )
                {
                    break;
                }

                if( TrimPath(ValuePos) == NULL )
                {
                    break;
                }

                ExpandPath(ValuePos, sizeof(Buffer) - (ValuePos - Buffer));
                StringDelimiters = "";
                /* fall through */

            case TYPE_STRING:
                ParseString(Option,
                            StringDelimiters == NULL ?
                                Option->Delimiters : StringDelimiters,
                            ValuePos,
                            ReadStatus,
                            TRUE,
                            Info->fp,
                            Buffer,
                            sizeof(Buffer)
                            );
                break;

            default:
                break;
        }
        ++NumOfRead;
    }

    return NumOfRead;
}

const char *ConfigGetRawString(ConfigFileInfo *Info, const char *KeyName)
{
    ConfigOption *Option = GetOptionOfAInfo(Info, KeyName, NULL, NULL);

    if( Option != NULL )
    {
        StringListIterator  sli;

        if( StringListIterator_Init(&sli, &(Option->Holder.str)) != 0 )
        {
            return NULL;
        }

        /* cppcheck-v2.11 shows false possitive */
        return sli.Next(&sli);
    } else {
        return NULL;
    }
}

StringList *ConfigGetStringList(ConfigFileInfo *Info, const char *KeyName)
{
    ConfigOption *Option = GetOptionOfAInfo(Info, KeyName, NULL, NULL);

    if( Option != NULL )
    {
        if( Option->Holder.str.Count(&(Option->Holder.str)) == 0 )
        {
            return NULL;
        } else {
            return &(Option->Holder.str);
        }
    } else {
        return NULL;
    }
}

int32_t ConfigGetNumberOfStrings(ConfigFileInfo *Info, const char *KeyName)
{
    ConfigOption *Option = GetOptionOfAInfo(Info, KeyName, NULL, NULL);

    if( Option != NULL )
    {
        return Option->Holder.str.Count(&(Option->Holder.str));
    } else {
        return 0;
    }
}

int32_t ConfigGetInt32(ConfigFileInfo *Info, const char *KeyName)
{
    ConfigOption *Option = GetOptionOfAInfo(Info, KeyName, NULL, NULL);

    if( Option != NULL )
    {
        return Option->Holder.INT32;
    } else {
        return 0;
    }
}

BOOL ConfigGetBoolean(ConfigFileInfo *Info, const char *KeyName)
{
    ConfigOption *Option = GetOptionOfAInfo(Info, KeyName, NULL, NULL);

    if( Option != NULL )
    {
        return Option->Holder.boolean;
    } else {
        return FALSE;
    }
}

/* Won't change the Option's status */
void ConfigSetDefaultValue(ConfigFileInfo *Info, VType Value, const char *KeyName)
{
    ConfigOption *Option = GetOptionOfAInfo(Info, KeyName, NULL, NULL);

    if( Option != NULL )
    {
        switch( Option->Type )
        {
            case TYPE_INT32:
                Option->Holder.INT32 = Value.INT32;
                break;

            case TYPE_BOOLEAN:
                Option->Holder.boolean = Value.boolean;
                break;

            case TYPE_PATH:
            case TYPE_STRING:
                Option->Holder.str.Clear(&(Option->Holder.str));
                Option->Holder.str.Add(&(Option->Holder.str),
                                       Value.str,
                                       Option->Delimiters
                                       );
                break;

            default:
                break;
        }
    }
}

void ConfigFree(ConfigFileInfo *Info)
{
    int32_t Start = 0;
    ConfigOption *Option;

    while( StringChunk_Enum_NoWildCard(&(Info->Options),
                                       &Start,
                                       (void **)&Option)
           != NULL )
    {
        if( Option != NULL )
        {
            switch( Option->Type )
            {
                case TYPE_INT32:
                    break;

                case TYPE_BOOLEAN:
                    break;

                case TYPE_PATH:
                case TYPE_STRING:
                    Option->Holder.str.Free(&(Option->Holder.str));
                    break;

                default:
                    break;
            }
        }
    }

    Info->StrBuffer.Free(&(Info->StrBuffer));
    StringChunk_Free(&(Info->Options), TRUE);
}
