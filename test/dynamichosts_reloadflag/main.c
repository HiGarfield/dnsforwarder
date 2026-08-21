/* Regression test for the dynamichosts.c reload/teardown races found in the
   Round-2 review:

   Bug #1: GetHostsFromInternet_Thread() left the Reloading flag set on the
   failed-download path, so DynamicHosts_Cleanup()'s `while(Reloading) SLEEP(10)`
   wait loop spun forever and the whole process hung at shutdown.

   Bug #2: the read paths (DynamicHosts_GetCName/TypeExisting/Try) checked
   `MainDynamicContainer == NULL` OUTSIDE the read lock; cleanup takes the
   write lock before freeing the container, so the container could be freed
   between the unlocked check and the lock acquisition (use-after-free at
   shutdown).  The check must happen inside the critical section.

   The static declarations of dynamichosts.c are exposed (via the #define
   static trick) so the test can observe the Reloading / ToExit / container
   state and drive the reload thread function directly.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* Headers used by dynamichosts.c -- included BEFORE the static-export trick
   so their own static declarations are left untouched. */
#include "common.h"
#include "dynamichosts.h"
#include "hostscontainer.h"
#include "hostsutils.h"
#include "timedtask.h"
#include "logs.h"

/* Accurate millisecond sleep.  Do NOT use the SLEEP() macro here: it expands
   to `usleep(ms) x 1000', and on kernels where usleep() is rounded up to the
   timer tick (~3.4 ms per call on HZ=100/250 boxes) SLEEP(300) actually takes
   ~3.6 s and SLEEP(10) ~3.4 s, blowing the test's timing budget and making
   run.sh's `timeout` kill it at random.  A single nanosleep() is exact. */
static void Msleep(int ms)
{
    struct timespec Ts;

    Ts.tv_sec = ms / 1000;
    Ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while( nanosleep(&Ts, &Ts) != 0 && errno == EINTR )
    {
    }
}

/* ---- stubs for the download / post-download / host-lookup steps ----
   These use the real production symbol names (and are deliberately NOT
   static, matching the non-static declarations in the headers) because
   dynamichosts.c is compiled into this test binary. */

static int  StubDownloadResult = 1; /* 1 = download failed (Bug #1 repro) */
static volatile int StubAbortCalls = 0; /* set by the Downloader_Abort stub */

/* Stubs for the shutdown-interrupt mechanism that DynamicHosts_Cleanup()
   now invokes: the real downloader aborts a retry loop stuck on a failing
   download (RetryTimes < 0); here we only count the calls so the test can
   assert the cleanup aborts BEFORE waiting on Reloading. */
void Downloader_Abort(void)
{
    ++StubAbortCalls;
}

void Downloader_AbortReset(void)
{
}

int GetFromInternet_MultiFiles(const char **URLs,
                                      const char *File,
                                      int RetryInterval,
                                      int RetryTimes,
                                      void (*ErrorCallBack)(int ErrorCode, const char *URL, const char *File),
                                      void (*SuccessCallBack)(const char *URL, const char *File)
                                      )
{
    (void)URLs;
    (void)File;
    (void)RetryInterval;
    (void)RetryTimes;

    /* Simulate a download that takes 300 ms: long enough for the main thread
       to observe Reloading == TRUE and start the cleanup wait, but short
       enough for the timeout-wrapped test to finish quickly. */
    Msleep(300);

    return StubDownloadResult;
}

int Filter_Update(void)
{
    return 0;
}

void IpMiscMapping_Update(void)
{
}

int Modules_Update(void)
{
    return 0;
}

/* Host lookup stubs: the test only checks the locked NULL path (Bug #2) and
   that the non-NULL path is reachable; it does not exercise hostsutils.c. */
int HostsUtils_GetCName(const char *Domain, char *Buffer, HostsContainer *Container)
{
    (void)Domain;
    (void)Container;
    strcpy(Buffer, "1.2.3.4");
    return 0;
}

BOOL HostsUtils_TypeExisting(HostsContainer *Container,
                                    const char *Domain,
                                    HostsRecordType Type)
{
    (void)Container;
    (void)Domain;
    (void)Type;
    return TRUE;
}

HostsUtilsTryResult HostsUtils_Try(MsgContext *MsgCtx,
                                          int BufferLength,
                                          HostsContainer *Container)
{
    (void)MsgCtx;
    (void)BufferLength;
    (void)Container;
    return HOSTSUTILS_TRY_OK;
}

/* Stubs for the DynamicHosts_Init path, which this test never calls but the
   link step still needs. */
int TimedTask_Add(BOOL Persistent,
                         BOOL Asynchronous,
                         int Milliseconds,
                         TaskFunc Func,
                         void *Arg1,
                         void *Arg2,
                         BOOL Immediate)
{
    (void)Persistent;
    (void)Asynchronous;
    (void)Milliseconds;
    (void)Func;
    (void)Arg1;
    (void)Arg2;
    (void)Immediate;
    return 0;
}

const char *ConfigGetRawString(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info;
    (void)KeyName;
    return NULL;
}

StringList *ConfigGetStringList(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info;
    (void)KeyName;
    return NULL;
}

int32_t ConfigGetInt32(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info;
    (void)KeyName;
    return 0;
}

/* ---- expose dynamichosts.c statics ---- */
#define static

#include "dynamichosts.c"

#undef static

/* ---- test harness ---- */

static int CheckCount = 0;
static int FailCount = 0;

#define CHECK(cond, msg)                                                \
    do {                                                                \
        ++CheckCount;                                                   \
        if( !(cond) ) {                                                 \
            ++FailCount;                                                \
            fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);   \
        } else {                                                        \
            printf("PASS: %s\n", (msg));                                \
        }                                                               \
    } while( 0 )

static void *ReloadThreadEntry(void *Unused)
{
    (void)Unused;
    GetHostsFromInternet_Thread(NULL, NULL);
    return NULL;
}

int main(void)
{
    char *Urls[] = {"http://127.0.0.1/nonexistent-hosts", NULL};
    char CNameBuffer[256];
    pthread_t Reloader;

    /* Scratch hosts file used by the real DynamicHosts_Load(). */
    FILE *HostsFile = fopen("/tmp/dnsforwarder_dynhosts_test.hosts", "w");
    if( HostsFile == NULL )
    {
        fprintf(stderr, "cannot create scratch hosts file\n");
        return 1;
    }
    fprintf(HostsFile, "1.2.3.4 example.com\n");
    fclose(HostsFile);

    RWLock_Init(HostsLock);
    HostsURLs = Urls;
    File = "/tmp/dnsforwarder_dynhosts_test.hosts";
    HostsRetryInterval = 1;
    *Script = 0;
    ToExit = FALSE;
    Reloading = FALSE;

    /* ---- Case 1: failed download must clear Reloading (Bug #1) ---- */
    StubDownloadResult = 1;
    GetHostsFromInternet_Thread(NULL, NULL);
    CHECK(Reloading == FALSE,
          "failed-download path clears the Reloading flag");

    /* ---- Case 2: successful reload calls DynamicHosts_Load and clears
       Reloading ---- */
    StubDownloadResult = 0;
    MainDynamicContainer = NULL;
    GetHostsFromInternet_Thread(NULL, NULL);
    CHECK(Reloading == FALSE,
          "successful reload clears the Reloading flag");
    CHECK(MainDynamicContainer != NULL,
          "successful reload loads the hosts container");

    /* ---- Case 3: ToExit early-out clears Reloading ---- */
    ToExit = TRUE;
    Reloading = FALSE;
    GetHostsFromInternet_Thread(NULL, NULL);
    CHECK(Reloading == FALSE,
          "ToExit early-out clears the Reloading flag");
    ToExit = FALSE;

    /* ---- Case 4: NULL container read paths (Bug #2: the NULL check must
       live inside the read lock so cleanup cannot free the container between
       the check and the lock acquisition) ---- */
    MainDynamicContainer = NULL;
    CHECK(DynamicHosts_GetCName("example.com", CNameBuffer) == -198,
          "GetCName on a NULL container returns -198 without crashing");
    CHECK(DynamicHosts_TypeExisting("example.com", HOSTS_TYPE_A) == FALSE,
          "TypeExisting on a NULL container returns FALSE");
    CHECK(DynamicHosts_Try(NULL, 0) == HOSTSUTILS_TRY_NONE,
          "Try on a NULL container returns HOSTSUTILS_TRY_NONE");

    /* ---- Case 5: non-NULL container read path stays reachable ---- */
    {
        int rc;
        DynamicHosts_Load();
        CHECK(MainDynamicContainer != NULL,
              "DynamicHosts_Load re-populates the container");
        rc = DynamicHosts_GetCName("example.com", CNameBuffer);
        CHECK(rc == 0 && strcmp(CNameBuffer, "1.2.3.4") == 0,
              "GetCName on a loaded container reaches the lookup");
    }

    /* ---- Case 6 (end-to-end, concurrency): a failed download in flight
       while cleanup starts must NOT hang the process.  Before the fix the
       failed path left Reloading set, so DynamicHosts_Cleanup() spun forever
       and run.sh's `timeout` had to kill the test. ---- */
    StubDownloadResult = 1;
    MainDynamicContainer = NULL;
    Reloading = FALSE;
    ToExit = FALSE;

    if( pthread_create(&Reloader, NULL, ReloadThreadEntry, NULL) != 0 )
    {
        fprintf(stderr, "cannot create reload thread\n");
        return 1;
    }

    /* Wait until the reload thread has announced itself (Reloading == TRUE)
       so the cleanup below really races against an in-flight download. */
    {
        int Waited = 0;
        while( Reloading == FALSE && Waited < 5000 )
        {
            Msleep(10);
            Waited += 10;
        }
        CHECK(Reloading == TRUE, "reload thread announced itself (Reloading==TRUE)");
    }

    DynamicHosts_Cleanup();
    CHECK(TRUE, "DynamicHosts_Cleanup returned (no shutdown hang)");
    CHECK(StubAbortCalls > 0,
          "cleanup aborted the downloader before waiting on Reloading");

    pthread_join(Reloader, NULL);
    CHECK(Reloading == FALSE, "Reloading is FALSE after the thread finished");

    printf("\n%d checks, %d failure(s)\n", CheckCount, FailCount);

    return FailCount == 0 ? 0 : 1;
}
