/* Regression test for the GetFromInternet_MultiFiles() state-reversal bug:
   when only SOME of the URLs succeed, the merged (partial) temp file must NOT
   overwrite the existing target file, and the function must report failure. */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "downloader.h"

static int g_Errors = 0;
static int g_Successes = 0;

static void OnError(int Code, const char *URL, const char *File)
{
    (void)Code; (void)URL; (void)File;
    ++g_Errors;
}

static void OnSuccess(const char *URL, const char *File)
{
    (void)URL; (void)File;
    ++g_Successes;
}

static void WriteFileText(const char *Path, const char *Text)
{
    FILE *fp = fopen(Path, "w");
    if( fp != NULL )
    {
        fputs(Text, fp);
        fclose(fp);
    }
}

static int FileEquals(const char *Path, const char *Expected)
{
    FILE *fp = fopen(Path, "r");
    char  Buf[1024];
    int   N;

    if( fp == NULL )
    {
        return 0;
    }
    N = (int)fread(Buf, 1, sizeof(Buf) - 1, fp);
    fclose(fp);
    Buf[N] = '\0';
    return strcmp(Buf, Expected) == 0;
}

int main(void)
{
    char SrcA[MAX_PATH];
    char SrcB[MAX_PATH];
    char Target[MAX_PATH];
    char Cwd[MAX_PATH];

    GetCurrentDirectoryA(sizeof(Cwd), Cwd);
    sprintf(SrcA,  "%s\\dl_src_a.txt",  Cwd);
    sprintf(SrcB,  "%s\\dl_src_b.txt",  Cwd);
    sprintf(Target,"%s\\dl_target.txt", Cwd);

    /* Build absolute file:// URLs for the valid sources. */
    char URLA[2 * MAX_PATH];
    char URLB[2 * MAX_PATH];
    sprintf(URLA, "file://%s", SrcA);
    sprintf(URLB, "file://%s", SrcB);

    int Ok = 1;

    /* ---- Scenario 1: partial failure ----
       Only some URLs succeed => target must NOT be overwritten, and the
       function must report failure. */
    WriteFileText(SrcA,   "AAAA");
    WriteFileText(Target, "ORIGINAL-CONTENT");
    g_Errors = 0; g_Successes = 0;

    {
        const char *URLs[3];
        URLs[0] = URLA;
        URLs[1] = "file://C:\\this_file_does_not_exist_xyz.txt"; /* fails */
        URLs[2] = NULL;

        int Ret = GetFromInternet_MultiFiles(URLs, Target, 0, 3, OnError, OnSuccess);
        printf("Scenario1 Returned %d, Errors=%d, Successes=%d\n", Ret, g_Errors, g_Successes);

        if( Ret == 0 )
        {
            printf("FAIL: MultiFiles returned success on partial failure\n");
            Ok = 0;
        }
        if( !FileEquals(Target, "ORIGINAL-CONTENT") )
        {
            printf("FAIL: target overwritten with partial content\n");
            Ok = 0;
        }
    }

    /* ---- Scenario 2: all succeed ----
       Every URL succeeds => target must be overwritten with merged content. */
    WriteFileText(SrcA,   "AAAA");
    WriteFileText(SrcB,   "BBBB");
    WriteFileText(Target, "ORIGINAL-CONTENT");
    g_Errors = 0; g_Successes = 0;

    {
        const char *URLs[3];
        URLs[0] = URLA;
        URLs[1] = URLB;
        URLs[2] = NULL;

        int Ret = GetFromInternet_MultiFiles(URLs, Target, 0, 3, OnError, OnSuccess);
        printf("Scenario2 Returned %d, Errors=%d, Successes=%d\n", Ret, g_Errors, g_Successes);

        if( Ret != 0 )
        {
            printf("FAIL: MultiFiles returned failure on full success\n");
            Ok = 0;
        }
        if( !FileEquals(Target, "AAAA\nBBBB\n") )
        {
            printf("FAIL: target not merged correctly (got unexpected content)\n");
            Ok = 0;
        }
    }

    /* Cleanup */
    remove(SrcA);
    remove(SrcB);
    remove(Target);

    if( Ok )
    {
        printf("PASS\n");
        return 0;
    }
    return 1;
}
