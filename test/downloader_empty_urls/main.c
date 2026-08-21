/* Regression test for the GetFromInternet_MultiFiles() empty-URL-list bug
   found in the Round-3 review.

   Bug: with an empty URL list (URLs[0] == NULL) the merge loop never ran, so
   the temp file stayed empty while AllSucceeded remained TRUE; the function
   then renamed the EMPTY temp file over the existing target, silently wiping
   it.  A NULL URL list crashed the loop (dereferencing URLs[0]).

   Fix: both NULL and empty lists fail up front, leaving the target file
   untouched and reporting failure.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

static int Checks = 0;
static int Failures = 0;

static void expect(const char *what, int cond)
{
    ++Checks;
    if( cond )
    {
        printf("  [ ok ] %s\n", what);
    } else {
        ++Failures;
        printf("  [FAIL] %s\n", what);
    }
}

int main(void)
{
    const char *Target = "/tmp/dnsforwarder_dl_empty_target.txt";
    const char *Empty[] = { NULL };
    int ret;

    printf("== GetFromInternet_MultiFiles empty-URL-list regression tests ==\n\n");

    /* ---- NULL URL list ---- */
    printf("NULL URL list\n");
    WriteFileText(Target, "ORIGINAL-CONTENT");
    g_Errors = 0;
    g_Successes = 0;

    ret = GetFromInternet_MultiFiles(NULL, Target, 0, 3, OnError, OnSuccess);
    expect("a NULL URL list reports failure", ret != 0);
    expect("the target file is left untouched",
           FileEquals(Target, "ORIGINAL-CONTENT"));

    /* ---- empty URL list ---- */
    printf("Empty URL list\n");
    WriteFileText(Target, "ORIGINAL-CONTENT");
    g_Errors = 0;
    g_Successes = 0;

    ret = GetFromInternet_MultiFiles(Empty, Target, 0, 3, OnError, OnSuccess);
    expect("an empty URL list reports failure", ret != 0);
    expect("the target file is still untouched",
           FileEquals(Target, "ORIGINAL-CONTENT"));
    expect("no download was attempted",
           g_Errors == 0 && g_Successes == 0);

    remove(Target);

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
