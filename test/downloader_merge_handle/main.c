/* Regression test for the FILE-handle leak in GetFromInternet_MultiFiles()
   (downloader.c) when the record-separator write fails.

   Bug: the merge loop did

       if( fputc('\n', fp) == EOF || fclose(fp) != 0 )
           break;

   `||` short-circuits: when fputc() fails (e.g. the disk fills up exactly as
   the separator is written) fclose(fp) is skipped and the FILE * -- and its
   underlying descriptor -- leak.  A daemon that refreshes its URL lists on a
   failing disk then loses one descriptor per merge run until it hits EMFILE.

   Fix: close the file on every path:

       if( fputc('\n', fp) == EOF )
       {   fclose(fp); break;   }
       if( fclose(fp) != 0 )
           break;

   The test forces fputc() to fail deterministically: it sets RLIMIT_FSIZE so
   the temp file (exactly at the limit after the file:// copy) cannot take the
   newline, and ignores SIGXFSZ so the write returns EFBIG instead of killing
   the process.  It then runs the merge loop many times and counts open file
   descriptors: the buggy build leaks one fd per run, the fixed build does not.

   Build note: downloader.c is compiled with -DNODOWNLOAD (GetFromInternet_Base
   becomes a stub) because the test only exercises the file:// path.
 */
#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "downloader.h"

/* ---- stubs for symbols downloader.c references ------------------------- */
#include <stdarg.h>
void Log_Print(const char *Type, const char *format, ...)
{
    (void)Type; (void)format;
}

void *SafeMalloc(size_t n)
{
    return malloc(n);
}

void SafeFree(void *p)
{
    free(p);
}

/* Parse "file:///abs/path" into "/abs/path". */
char *GetLocalPathFromURL(const char *URL, char *Out, int OutLen)
{
    const char *p = URL;
    if( strncmp(p, "file://", 7) == 0 )
    {
        p += 7;
    }
    if( OutLen > 0 )
    {
        snprintf(Out, (size_t)OutLen, "%s", p);
    }
    return Out;
}

/* Real copy (mirrors utils.c CopyAFile) so the file:// URL populates the
   temp file with exactly Limit bytes. */
int CopyAFile(const char *Src, const char *Dst, BOOL Append)
{
    FILE *S = fopen(Src, "r");
    FILE *D;
    int c;
    int Ret = 0;

    if( S == NULL )
    {
        return -1;
    }
    D = fopen(Dst, Append ? "a" : "w");
    if( D == NULL )
    {
        fclose(S);
        return -1;
    }
    while( (c = fgetc(S)) != EOF )
    {
        if( fputc(c, D) == EOF )
        {
            Ret = -1;
            break;
        }
    }
    if( fclose(S) != 0 )
    {
        Ret = -1;
    }
    if( fclose(D) != 0 )
    {
        Ret = -1;
    }
    return Ret;
}
/* ------------------------------------------------------------------------ */

static int Checks = 0;
static int Failures = 0;

#define CHECK(cond, msg) do { \
    ++Checks; \
    if( !(cond) ) { \
        printf("FAIL: %s\n", msg); \
        ++Failures; \
    } else { \
        printf("PASS: %s\n", msg); \
    } \
} while(0)

static void OnError(int Code, const char *URL, const char *File)
{
    (void)Code; (void)URL; (void)File;
}

static void OnSuccess(const char *URL, const char *File)
{
    (void)URL; (void)File;
}

static int CountFds(void)
{
    DIR *d = opendir("/proc/self/fd");
    int n = 0;

    if( d == NULL )
    {
        return -1;
    }
    while( readdir(d) != NULL )
    {
        ++n;
    }
    closedir(d);
    /* readdir's "." / ".." entries are not counted by opendir on Linux, so
       every entry is a real descriptor; but be conservative and return the
       raw count. */
    return n;
}

int main(void)
{
    char Src[128];
    char Dst[128];
    char Url[256];
    const char *URLs[2];
    struct rlimit Lim;
    struct sigaction Sa;
    struct stat St;
    long Limit = 4096;
    int i, Before, After;

    printf("== downloader merge-loop FILE-handle leak test ==\n\n");

    memset(&Sa, 0, sizeof(Sa));
    Sa.sa_handler = SIG_IGN;
    sigemptyset(&Sa.sa_mask);
    if( sigaction(SIGXFSZ, &Sa, NULL) != 0 )
    {
        printf("FAIL: cannot ignore SIGXFSZ\n");
        return 2;
    }

    if( getrlimit(RLIMIT_FSIZE, &Lim) != 0 )
    {
        printf("FAIL: getrlimit\n");
        return 3;
    }
    if( Lim.rlim_cur == RLIM_INFINITY || (rlim_t)Limit < Lim.rlim_cur )
    {
        Lim.rlim_cur = (rlim_t)Limit;
        Lim.rlim_max = (rlim_t)Limit;
        if( setrlimit(RLIMIT_FSIZE, &Lim) != 0 )
        {
            printf("FAIL: setrlimit RLIMIT_FSIZE (%s)\n", strerror(errno));
            return 4;
        }
    }

    snprintf(Src, sizeof(Src), "/tmp/dnsf_dl_merge_src_%ld", (long)getpid());
    snprintf(Dst, sizeof(Dst), "/tmp/dnsf_dl_merge_dst_%ld", (long)getpid());
    snprintf(Url, sizeof(Url), "file://%s", Src);

    /* Start with a small source file (64 bytes): the warm-up merge below must
       commit successfully, so it must NOT trip RLIMIT_FSIZE.  It is grown to
       exactly Limit bytes afterwards, when the temp file copy then sits at the
       size limit and the separator newline is the byte that trips EFBIG. */
    {
        FILE *fp = fopen(Src, "w");
        char  Line[4096];
        size_t Left = 64;

        if( fp == NULL )
        {
            printf("FAIL: cannot create source file\n");
            return 5;
        }
        memset(Line, 'x', sizeof(Line));
        while( Left > 0 )
        {
            size_t n = Left > sizeof(Line) ? sizeof(Line) : Left;
            if( fwrite(Line, 1, n, fp) != n )
            {
                printf("FAIL: cannot fill source file\n");
                fclose(fp);
                return 6;
            }
            Left -= n;
        }
        if( fclose(fp) != 0 )
        {
            printf("FAIL: close source file\n");
            return 7;
        }
    }

    URLs[0] = Url;
    URLs[1] = NULL;

    /* Warm-up run: proves the merge loop still commits on the normal path
       (fits under RLIMIT_FSIZE).  The run must also report success: after the
       Round-9 fix, a separator write that fails (EFBIG, disk full) must NOT be
       committed silently, and this warm-up does not hit that condition. */
    if( GetFromInternet_MultiFiles(URLs, Dst, 0, 1, OnError, OnSuccess) != 0 )
    {
        printf("FAIL: warm-up merge run returned an error\n");
        return 8;
    }
    /* The merge appends a one-byte '\n' record separator after each URL's
       data, so the committed target holds 64 + 1 = 65 bytes. */
    if( stat(Dst, &St) != 0 || St.st_size != 65 )
    {
        printf("FAIL: merged target has wrong size (got %lld, want 65)\n",
               (long long)(St.st_size != 0 ? St.st_size : -1));
        return 9;
    }

    /* Grow the source to exactly Limit bytes so the failing runs below trip
       EFBIG on the separator newline. */
    {
        FILE *fp = fopen(Src, "a");
        char  Line[4096];
        size_t Left = (size_t)Limit - 64;

        if( fp == NULL )
        {
            printf("FAIL: cannot grow source file\n");
            return 9;
        }
        memset(Line, 'y', sizeof(Line));
        while( Left > 0 )
        {
            size_t n = Left > sizeof(Line) ? sizeof(Line) : Left;
            if( fwrite(Line, 1, n, fp) != n )
            {
                printf("FAIL: cannot grow source file\n");
                fclose(fp);
                return 9;
            }
            Left -= n;
        }
        if( fclose(fp) != 0 )
        {
            printf("FAIL: close grown source file\n");
            return 9;
        }
    }

    Before = CountFds();
    if( Before < 0 )
    {
        printf("FAIL: cannot count fds\n");
        return 10;
    }

    for( i = 0; i < 50; ++i )
    {
        GetFromInternet_MultiFiles(URLs, Dst, 0, 1, OnError, OnSuccess);
    }

    After = CountFds();
    if( After < 0 )
    {
        printf("FAIL: cannot count fds after the loop\n");
        return 11;
    }

    printf("fds before=%d after=%d (50 merge runs)\n", Before, After);
    /* The buggy build leaks one descriptor per failing run (+50).  ASan may
       open a handful of descriptors of its own, so allow a small tolerance. */
    CHECK(After - Before < 10,
          "no FILE-handle leak across 50 failing merge runs");

    unlink(Src);
    unlink(Dst);

    {
        char Temp[160];
        snprintf(Temp, sizeof(Temp), "%s.tmp", Dst);
        unlink(Temp);
    }

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
#else /* _WIN32 */
int main(void)
{
    printf("POSIX-only test, skipped.\n");
    return 0;
}
#endif /* _WIN32 */
