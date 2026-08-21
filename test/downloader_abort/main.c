/* Regression test for the shutdown hang caused by downloader.c's infinite
   retry loop (RetryTimes < 0) and for the Downloader_Abort() /
   Downloader_AbortReset() interrupt mechanism.

   Bug: GetHostsFromInternet_Thread() (dynamichosts.c) calls
   GetFromInternet_MultiFiles() with RetryTimes == -1 ("retry forever").
   When the download keeps failing, GetFromInternet_SingleFile()'s loop
   `while( RetryTimes != 0 )' never exits: -1 != 0 is always true.  The
   reload thread then never clears Reloading, and DynamicHosts_Cleanup()'s
   `while( Reloading ) SLEEP(10)' spins forever -- the process hangs at
   shutdown (e.g. a Hosts URL configured on a machine with no network, where
   GetFromInternet_Base() fails instantly and forever).

   Fix: a process-global Downloader_Aborted flag, checked at the top of the
   retry loop and again right before the retry sleep.  DynamicHosts_Cleanup()
   calls Downloader_Abort() before it starts spinning on Reloading, so the
   stuck retry loop observes the flag and returns.

   Part 1 (runtime): run GetFromInternet_SingleFile() with RetryTimes == -1
   in a helper thread.  Wait until the retry loop is provably live (at least
   one error callback has fired), then call Downloader_Abort() and assert the
   call returns promptly.  The pre-fix build never returns and the test fails
   via its internal timeout.

   Part 2 (runtime): the abort flag persists until Downloader_AbortReset(),
   so a download started without a reset must return immediately without
   attempting anything (ErrorCount stays 0).

   Part 3 (runtime): Downloader_AbortReset() clears the flag, so a fresh
   finite-retry download afterwards runs normally: exactly RetryTimes error
   callbacks and a non-zero return.

   Part 4 (structural, in run.sh): source scans of downloader.c and
   dynamichosts.c assert the abort guard sits in the retry loop and that
   DynamicHosts_Cleanup() aborts before spinning on Reloading.

   Build note: downloader.c is compiled without DOWNLOAD_LIBCURL /
   DOWNLOAD_WGET, so it forces NODOWNLOAD and GetFromInternet_Base() is the
   stub that always returns -1 -- the download always fails, exactly like a
   machine with no network.
*/
#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

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

int CopyAFile(const char *Src, const char *Dst, BOOL Append)
{
    /* Never reached in this test (no file:// URL is used). */
    (void)Src; (void)Dst; (void)Append;
    return -1;
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

static volatile int ErrorCount = 0;
static volatile int DownloadRet = 0;
static volatile int ThreadFinished = 0;

static void OnError(int Code, const char *URL, const char *File)
{
    (void)Code; (void)URL; (void)File;
    ++ErrorCount;
}

static void OnSuccess(const char *URL, const char *File)
{
    (void)URL; (void)File;
}

static void *RetryForever(void *Unused)
{
    (void)Unused;
    DownloadRet = GetFromInternet_SingleFile("http://127.0.0.1:1/dnsf-abort-test",
                                             "/tmp/dnsf_abort_dst",
                                             TRUE,
                                             0,       /* RetryInterval */
                                             -1,      /* RetryTimes: forever */
                                             OnError,
                                             OnSuccess);
    ThreadFinished = 1;
    return NULL;
}

int main(void)
{
    pthread_t Tid;
    char Dst[128];
    int i;

    snprintf(Dst, sizeof(Dst), "/tmp/dnsf_abort_dst_%ld", (long)getpid());

    printf("== downloader infinite-retry abort test ==\n\n");

    /* Part 1: an infinite-retry download must return promptly once
       Downloader_Abort() is called. */
    if( pthread_create(&Tid, NULL, RetryForever, NULL) != 0 )
    {
        printf("FAIL: pthread_create\n");
        return 2;
    }

    /* Wait until the retry loop is provably live (at least one failed
       attempt has completed). */
    for( i = 0; i < 200 && ErrorCount == 0; ++i )
    {
        usleep(5000);
    }
    CHECK(ErrorCount > 0, "retry loop is live (at least one error callback)");
    if( ErrorCount == 0 )
    {
        printf("FAIL: retry loop never started; nothing to abort\n");
        pthread_cancel(Tid);
        pthread_join(Tid, NULL);
        return 1;
    }

    Downloader_Abort();

    /* The fixed build returns almost immediately; allow 2 s. */
    for( i = 0; i < 400 && !ThreadFinished; ++i )
    {
        usleep(5000);
    }
    CHECK(ThreadFinished,
          "infinite-retry download returns after Downloader_Abort()");
    if( !ThreadFinished )
    {
        printf("FAIL: the retry loop ignored the abort flag and is still running\n");
        ++Failures;
        /* Do NOT pthread_join a stuck thread: that would hang the test
           itself.  main() returns and the process exit reaps it. */
        return 1;
    }
    CHECK(DownloadRet != 0, "aborted download reports failure (non-zero return)");
    pthread_join(Tid, NULL);

    /* Part 2: the abort flag persists until Downloader_AbortReset(), so a
       new download must bail out without attempting anything. */
    {
        int Ret;
        ErrorCount = 0;
        Ret = GetFromInternet_SingleFile("http://127.0.0.1:1/dnsf-abort-test",
                                         Dst, TRUE, 0, 5, OnError, OnSuccess);
        CHECK(Ret != 0, "download with RetryTimes=5 returns immediately while aborted");
        CHECK(ErrorCount == 0, "no download attempt is made while aborted");
    }

    /* Part 3: AbortReset() restores normal behaviour. */
    Downloader_AbortReset();
    {
        int Ret;
        ErrorCount = 0;
        Ret = GetFromInternet_SingleFile("http://127.0.0.1:1/dnsf-abort-test",
                                         Dst, TRUE, 0, 2, OnError, OnSuccess);
        CHECK(Ret != 0, "download after AbortReset() fails normally (non-zero return)");
        CHECK(ErrorCount == 2, "exactly RetryTimes error callbacks after AbortReset()");
    }

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
