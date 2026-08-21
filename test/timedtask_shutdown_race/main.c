/* Regression test for the TimedTask_Add() vs TimedTask_Cleanup() TOCTOU.

   Bug: TimedTask_Add() wrote the TaskInfo to the self-pipe with a bare
   write() and never consulted TimedTask_ToExit.  TimedTask_Cleanup() sets
   that flag under TimedTask_ExitMutex and then closes WriteTo; an Add
   racing with shutdown could therefore write() a descriptor that had just
   been closed.  Once the kernel recycles the descriptor number (another
   open() in the same process), the TaskInfo bytes land in a completely
   unrelated file or socket -- silent corruption, no error anywhere.

   Fix: TimedTask_Add() checks TimedTask_ToExit under the same mutex
   (Cleanup sets the flag before it closes the pipe), so an Add that
   observes the flag can never write to the closed descriptor.  Cleanup()
   also no longer destroys the mutex, so a late Add can still lock it
   safely instead of locking a destroyed pthread_mutex_t (undefined
   behaviour).

   The test drives the real module: it inits TimedTask, proves a normal Add
   works, runs TimedTask_Cleanup() directly, then force-reuses the closed
   write-end descriptor number for a scratch file and calls TimedTask_Add()
   again.  With the fix the Add is rejected (-53) and the scratch file stays
   empty; the buggy code wrote sizeof(TaskInfo) bytes of garbage into it.

   The static declarations of timedtask.c are exposed (via the #define
   static trick) so the test can read WriteTo / TimedTask_ToExit /
   TimedTask_Initialised and call TimedTask_Cleanup() directly.
 */
#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

/* ---- expose the private declarations of timedtask.c ------------------ */
#define static
#include "../../timedtask.c"
#undef static

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

static int NeverRun(void *Unused1, void *Unused2)
{
    (void)Unused1;
    (void)Unused2;
    printf("FAIL: a task scheduled after shutdown actually ran\n");
    ++Failures;
    return 0;
}

int main(void)
{
    char Path[64];
    char PathB[64];
    int A = -1, B = -1;
    int OldWrite;
    int rc;
    struct stat st;

    printf("== TimedTask Add-vs-Cleanup TOCTOU regression test ==\n\n");

    if( TimedTask_Init() != 0 )
    {
        printf("FAIL: TimedTask_Init\n");
        return 2;
    }

    /* Normal operation: a plain Add must still be accepted and delivered. */
    rc = TimedTask_Add(FALSE, FALSE, 10, NeverRun, NULL, NULL, TRUE);
    CHECK(rc == 0, "a normal TimedTask_Add succeeds while the module is live");

    OldWrite = (int)WriteTo;

    /* Run the real shutdown path, exactly as atexit would. */
    TimedTask_Cleanup();

    /* Stop the atexit-registered Cleanup from running a second time (it
       would free the queue twice).  After Cleanup completed, the resources
       it guards are gone, so a second pass must bail out early. */
    TimedTask_Initialised = FALSE;

    CHECK(TimedTask_ToExit == TRUE,
          "TimedTask_Cleanup left the exit flag set");

    /* Force the kernel to recycle the closed write-end descriptor number.
       pipe() hands out the read end first, so the first open() below gets
       the old read-end number and the second open() (if needed) gets the
       old write-end number -- the descriptor an unfixed TimedTask_Add would
       write() into. */
    snprintf(Path, sizeof(Path), "/tmp/dnsf_tt_race_%ld", (long)getpid());
    snprintf(PathB, sizeof(PathB), "/tmp/dnsf_tt_race_%ld_b", (long)getpid());

    A = open(Path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if( A < 0 )
    {
        printf("FAIL: cannot create scratch file A (%s)\n", strerror(errno));
        return 3;
    }
    if( A == OldWrite )
    {
        B = A;
    } else {
        B = open(PathB, O_CREAT | O_RDWR | O_TRUNC, 0600);
        if( B < 0 )
        {
            printf("FAIL: cannot create scratch file B (%s)\n", strerror(errno));
            return 4;
        }
        CHECK(B == OldWrite,
              "the reopened descriptor number matches the old write end");
    }

    if( fstat(B, &st) != 0 )
    {
        printf("FAIL: fstat on scratch file (%s)\n", strerror(errno));
        return 5;
    }
    CHECK(st.st_size == 0, "scratch file starts empty");

    /* The critical call: after shutdown began, Add must be rejected WITHOUT
       touching the descriptor that now aliases the old WriteTo. */
    rc = TimedTask_Add(FALSE, FALSE, 10, NeverRun, NULL, NULL, TRUE);
    CHECK(rc == -53, "TimedTask_Add is rejected after cleanup began");

    if( fstat(B, &st) != 0 )
    {
        printf("FAIL: fstat on scratch file after Add (%s)\n", strerror(errno));
        return 6;
    }
    CHECK(st.st_size == 0,
          "no TaskInfo bytes were written into the reused descriptor");

    if( B != A )
    {
        close(A);
    }
    close(B);
    unlink(Path);
    unlink(PathB);

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
