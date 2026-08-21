/* Regression test for timedtask.c POSIX self-pipe partial-read bug.
 *
 * Bug: the worker read a TaskInfo from the self-pipe with a single read() that
 * only checked for <0. On a short read (signal interruption, or the 1-byte
 * wake-up byte written by TimedTask_Cleanup) the TaskInfo was only partially
 * filled and then enqueued, handing a corrupted task (stale function pointer /
 * arguments) to the scheduler.
 *
 * Fix: TimedTask_ReadOneTask() loops until the whole TaskInfo is assembled and
 * returns 0 (discard) on a short read / EAGAIN / EOF instead of enqueueing
 * garbage.  In production the read end is created with O_NONBLOCK (see
 * TimedTask_Init), so this test mirrors that by setting the same flag on the
 * pipe it creates.
 *
 * This test links timedtask.c with TIMEDTASK_UNITTEST defined so it can call
 * TimedTask_ReadOneTask() directly.
 */
#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include "../../common.h"
#include "../../timedtask.h"

/* Mirror of TaskInfo as declared in timedtask.c (POSIX layout). */
typedef struct _TestTaskInfo {
    void            *Task;
    void            *Arg1;
    void            *Arg2;
    struct timeval  TimeOut;
    struct timeval  LeftTime;
    BOOL            Persistent;
    BOOL            Asynchronous;
} TestTaskInfo;

static int failures = 0;

#define CHECK(cond, msg) do { \
    if( !(cond) ) { \
        printf("FAIL: %s\n", msg); \
        ++failures; \
    } else { \
        printf("PASS: %s\n", msg); \
    } \
} while(0)

static void fill_task(TestTaskInfo *t, int tag)
{
    memset(t, 0xCD, sizeof(*t));          /* poison with a non-zero pattern */
    t->Task = (void *)(size_t)(0x1000 + tag);
    t->Arg1 = (void *)(size_t)(0x2000 + tag);
    t->Arg2 = (void *)(size_t)(0x3000 + tag);
    t->TimeOut.tv_sec = 11 + tag;
    t->TimeOut.tv_usec = 22 + tag;
    t->LeftTime.tv_sec = 33 + tag;
    t->LeftTime.tv_usec = 44 + tag;
    t->Persistent = (tag % 2);
    t->Asynchronous = !(tag % 2);
}

static int tasks_equal(const TestTaskInfo *a, const TestTaskInfo *b)
{
    return a->Task == b->Task &&
           a->Arg1 == b->Arg1 &&
           a->Arg2 == b->Arg2 &&
           a->TimeOut.tv_sec == b->TimeOut.tv_sec &&
           a->TimeOut.tv_usec == b->TimeOut.tv_usec &&
           a->LeftTime.tv_sec == b->LeftTime.tv_sec &&
           a->LeftTime.tv_usec == b->LeftTime.tv_usec &&
           a->Persistent == b->Persistent &&
           a->Asynchronous == b->Asynchronous;
}

int main(void)
{
    int fds[2];
    TestTaskInfo want, got;
    int r;
    int Flags;

    if( pipe(fds) != 0 )
    {
        perror("pipe");
        return 2;
    }

    /* Mirror production: the read end is O_NONBLOCK so a partial record yields
       EAGAIN instead of blocking forever. */
    Flags = fcntl(fds[0], F_GETFL, 0);
    if( Flags < 0 || fcntl(fds[0], F_SETFL, Flags | O_NONBLOCK) != 0 )
    {
        perror("fcntl");
        return 2;
    }

    /* ---- Case 1: a lone 1-byte wake-up byte must be discarded (return 0) ---- */
    {
        char dummy = 0;
        if( write(fds[1], &dummy, 1) != 1 )
        {
            perror("write");
            return 2;
        }
        memset(&got, 0xAB, sizeof(got));   /* pre-fill with a different poison */
        r = TimedTask_ReadOneTask(fds[0], &got);
        CHECK(r == 0,
              "short read (1-byte wake-up) is discarded, not enqueued (ret==0)");
    }

    /* ---- Case 2: a complete TaskInfo must be reassembled (return 1) ---- */
    fill_task(&want, 7);
    if( write(fds[1], &want, sizeof(want)) != (int)sizeof(want) )
    {
        perror("write");
        return 2;
    }
    memset(&got, 0xAB, sizeof(got));
    r = TimedTask_ReadOneTask(fds[0], &got);
    CHECK(r == 1, "complete TaskInfo is recognised (ret==1)");
    CHECK(tasks_equal(&want, &got),
          "reassembled TaskInfo matches the written one (no truncation/corruption)");

    /* ---- Case 3: EOF (writer closed) after a partial write -> return 0 ---- */
    {
        char dummy = 0;
        if( write(fds[1], &dummy, 1) != 1 )
        {
            perror("write");
            return 2;
        }
        close(fds[1]);                      /* trigger EOF after the 1 byte */
        memset(&got, 0xAB, sizeof(got));
        r = TimedTask_ReadOneTask(fds[0], &got);
        CHECK(r == 0,
              "partial read followed by EOF is discarded (ret==0, no crash)");
    }

    close(fds[0]);

    if( failures == 0 )
    {
        printf("\nALL TESTS PASSED: timedtask partial-read bug fixed.\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}

#else /* _WIN32 */

#include <stdio.h>
int main(void)
{
    /* The partial-read bug only exists on the POSIX self-pipe path; the Win32
       message-queue path is unaffected, so this test is a no-op there. */
    printf("SKIP: POSIX self-pipe partial-read test (Win32 path uses MsgQue).\n");
    return 0;
}

#endif /* _WIN32 */
