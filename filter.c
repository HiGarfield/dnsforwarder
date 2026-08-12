#include <stdio.h>
#include <stdlib.h>
#include "filter.h"
#include "stringchunk.h"
#include "bst.h"
#include "common.h"
#include "logs.h"
#include "readline.h"
#include "domainstatistic.h"
#include "rwlock.h"

static Bst          *DisabledTypes = NULL;

static StringChunk  *DisabledDomain = NULL;
static RWLock       DisabledDomainLock = NULL_RWLOCK;

static ConfigFileInfo *CurrConfigInfo = NULL;

static int TypeCompare(const int *_1, const int *_2)
{
    return *_1 - *_2;
}

static int InitBst(Bst **t, int (*CompareFunc)(const void *, const void *))
{
    *t = malloc(sizeof(Bst));
    if( *t == NULL )
    {
        return -93;
    }

    if( Bst_Init(*t, sizeof(int), CompareFunc) != 0 )
    {
        free(*t);
        *t = NULL;
        return -102;
    }

    return 0;
}

static int LoadDomainsFromList(StringChunk *List, StringList *Domains)
{
    const char *Str;

    StringListIterator  sli;

    if( List == NULL || Domains == NULL )
    {
        return 0;
    }

    if( StringListIterator_Init(&sli, Domains) != 0 )
    {
        return -1;
    }

    Str = sli.Next(&sli);
    while( Str != NULL )
    {
        StringChunk_Add_Domain(List, Str, NULL, 0);
        Str = sli.Next(&sli);
    }

    return 0;
}

static int FilterDomain_Init(StringChunk **List, ConfigFileInfo *ConfigInfo)
{
    StringList *dd = ConfigGetStringList(ConfigInfo, "DisabledDomain");

    if( dd == NULL )
    {
        return 0;
    }

    if( InitChunk(List) != 0 )
    {
        return -120;
    }

    LoadDomainsFromList(*List, dd);

    return 0;
}

static int LoadDomainsFromFile(StringChunk *List, const char *FilePath)
{
    FILE *fp;
    char    Domain[512];

    if( List == NULL || FilePath == NULL )
    {
        return 0;
    }

    fp = fopen(FilePath, "r");
    if( fp == NULL )
    {
        return -118;
    }

    while( TRUE )
    {
        ReadLineStatus  Status;

        Status = ReadLine(fp, Domain, sizeof(Domain));
        if( Status == READ_FAILED_OR_END )
        {
            break;
        }

        if( Status == READ_DONE )
        {
            StringChunk_Add_Domain(List, Domain, NULL, 0);
        } else {
            ReadLine_GoToNextLine(fp);
        }
    }

    fclose(fp);

    return 0;
}

static int FilterDomain_InitFromFile(StringChunk **List, ConfigFileInfo *ConfigInfo)
{
    StringList *FilePaths = ConfigGetStringList(ConfigInfo, "DisabledList");
    const char *FilePath;
    StringListIterator sli;

    if( FilePaths == NULL )
    {
        return 0;
    }

    if( StringListIterator_Init(&sli, FilePaths) != 0 )
    {
        return -116;
    }

    if( InitChunk(List) != 0 )
    {
        return -117;
    }

    while( (FilePath = sli.Next(&sli)) != NULL )
    {
        LoadDomainsFromFile(*List, FilePath);
    }

    return 0;
}

static void FilterType_Cleanup(void)
{
    if(DisabledTypes != NULL)
    {
        DisabledTypes->Free(DisabledTypes);
        free(DisabledTypes);
    }

    RWLock_Destroy(DisabledDomainLock);
}

static int FilterType_Init(ConfigFileInfo *ConfigInfo)
{
    StringList *DisableType_Str =
        ConfigGetStringList(ConfigInfo, "DisabledType");

    const char *OneTypePendingToAdd_Str;
    int OneTypePendingToAdd;

    StringListIterator  sli;

    if( DisableType_Str == NULL )
    {
        return 0;
    }

    if( InitBst(&DisabledTypes,
                (int (*)(const void *, const void *))TypeCompare
             ) != 0 )
    {
        return -146;
    }

    if( StringListIterator_Init(&sli, DisableType_Str) != 0 )
    {
        return -2;
    }

    OneTypePendingToAdd_Str = sli.Next(&sli);
    while( OneTypePendingToAdd_Str != NULL )
    {
        /* Initialise first so a failed parse never feeds an uninitialised
           value into the BST (which would silently disable/enable a random
           DNS record type). */
        OneTypePendingToAdd = 0;
        if( sscanf(OneTypePendingToAdd_Str, "%d", &OneTypePendingToAdd) == 1 )
        {
            DisabledTypes->Add(DisabledTypes, &OneTypePendingToAdd);
        } else {
            ERRORMSG("Ignoring invalid DisabledType entry: %s\n",
                     OneTypePendingToAdd_Str);
        }

        OneTypePendingToAdd_Str = sli.Next(&sli);
    }

    /* `ConfigGetStringList()` hands out a borrowed reference to the list
       stored inside `ConfigInfo`; releasing it here would destroy the
       option and leave `ConfigFree()` with a dangling holder. */

    return 0;
}

static void DisabledDomain_Cleanup(void)
{
    if( DisabledDomain != NULL )
    {
        StringChunk_Free(DisabledDomain, TRUE);
        SafeFree(DisabledDomain);
    }
}

static int DisabledDomain_Init(ConfigFileInfo *ConfigInfo)
{
    StringChunk    *TempDisabledDomain = NULL;

    if( FilterDomain_Init(&TempDisabledDomain, ConfigInfo) != 0 )
    {
        INFO("Loading DisabledDomain failed.\n");
        return -1;
    } else {
        INFO("Loading DisabledDomain completed.\n");
    }

    if( FilterDomain_InitFromFile(&TempDisabledDomain, ConfigInfo) != 0 )
    {
        StringChunk_Free(TempDisabledDomain, TRUE);
        SafeFree(TempDisabledDomain);
        INFO("Loading DisabledList failed.\n");
        return -1;
    } else {
        INFO("Loading DisabledList completed.\n");
    }

    RWLock_WrLock(DisabledDomainLock);
    DisabledDomain_Cleanup();
    DisabledDomain = TempDisabledDomain;
    RWLock_UnWLock(DisabledDomainLock);

    return 0;
}

int Filter_Init(ConfigFileInfo *ConfigInfo)
{
    CurrConfigInfo = ConfigInfo;

    if( FilterType_Init(ConfigInfo) != 0 )
    {
        INFO("Setting DisabledType failed.\n");
    } else {
        INFO("Setting DisabledType succeeded.\n");
    }

    RWLock_Init(DisabledDomainLock);

    atexit(FilterType_Cleanup);

    DisabledDomain_Init(ConfigInfo);
    atexit(DisabledDomain_Cleanup);

    return 0;
}

int Filter_Update(void)
{
    if ( ConfigGetBoolean(CurrConfigInfo, "ReloadDisabledList") )
    {
        DisabledDomain_Init(CurrConfigInfo);
    }
    return 0;
}

static BOOL IsDisabledType(int Type)
{
    if( DisabledTypes != NULL &&
        DisabledTypes->Search(DisabledTypes, &Type, NULL) != NULL )
    {
        return TRUE;
    } else {
        return FALSE;
    }
}

static BOOL IsDisabledDomain(const char *Domain, uint32_t HashValue)
{
    int ret;

    /* Take the lock before checking DisabledDomain. A reload
       (DisabledDomain_Init) swaps the pointer under the write lock, so a
       check made without the lock could read a freed/ NULL container and then
       dereference it below (use-after-free / NULL deref). */
    RWLock_RdLock(DisabledDomainLock);

    if (DisabledDomain == NULL)
    {
        RWLock_UnRLock(DisabledDomainLock);
        return FALSE;
    }

    ret = StringChunk_Domain_Match(DisabledDomain, Domain, &HashValue, NULL, NULL, NULL);
    RWLock_UnRLock(DisabledDomainLock);

    return ret;
}

BOOL Filter_Out(MsgContext *MsgCtx)
{
    IHeader *h = (IHeader *)MsgCtx;

    if(IsDisabledType(h->Type) || IsDisabledDomain(h->Domain, h->HashValue) )
    {
        MsgContext_SendBackRefusedMessage(MsgCtx);
        ShowRefusingMessage(h, "Disabled type or domain");
        DomainStatistic_Add(h, STATISTIC_TYPE_REFUSED);

        return TRUE;
    } else {
        return FALSE;
    }
}
