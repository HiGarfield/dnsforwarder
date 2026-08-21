/* End-to-end regression test for the TimedTask shutdown deadlock.
 *
 * Bug: TimedTask_Cleanup() (atexit) woke the worker with a single 1-byte
 * write to the self-pipe.  With a blocking read end, TimedTask_ReadOneTask()
 * consumed that byte and then blocked forever waiting for the rest of a
 * TaskInfo that never comes, so Cleanup()'s JOIN_THREAD() hung the whole
 * process at shutdown.
 *
 * Fix: the read end is created with O_NONBLOCK and ReadOneTask() treats
 * EAGAIN/EWOULDBLOCK like a short read (discard, return 0).  The worker then
 * loops, sees TimedTask_ToExit and terminates; JOIN_THREAD completes.
 *
 * This test runs the real TimedTask worker, lets a persistent task execute a
 * few times, then simply returns from main() so atexit() fires
 * TimedTask_Cleanup().  Run it under a `timeout` wrapper: a hang means the
 * bug is back.
 */
#ifndef _WIN32

#include <stdio.h>
#include <unistd.h>
#include "../../timedtask.h"

static volatile int Counter = 0;

static int TestTask(void *Unused1, void *Unused2)
{
    (void)Unused1;
    (void)Unused2;
    ++Counter;
    return 0;
}

int main(void)
{
    int i;

    if( TimedTask_Init() != 0 )
    {
        printf("FAIL: TimedTask_Init failed\n");
        return 2;
    }

    /* A persistent, synchronous task that runs on the worker thread. */
    if( TimedTask_Add(TRUE, FALSE, 20, TestTask, NULL, NULL, TRUE) != 0 )
    {
        printf("FAIL: TimedTask_Add failed\n");
        return 3;
    }

    /* Let the worker run the task a few times (20 ms period). */
    for( i = 0; i < 50; ++i )
    {
        usleep(20000);
        if( Counter > 3 )
        {
            break;
        }
    }

    if( Counter == 0 )
    {
        printf("FAIL: persistent task never ran (worker broken)\n");
        return 4;
    }

    printf("task ran %d time(s); returning to trigger atexit shutdown...\n",
           (int)Counter);

    /* Returning from main() runs the atexit handlers.  TimedTask_Cleanup()
       joins the worker; if the fix regressed, this call never returns and
       the `timeout` wrapper kills us. */
    return 0;
}

#else /* _WIN32 */

#include <stdio.h>
int main(void)
{
    /* Win32 path uses a message queue with an event wake-up; the hang does
       not exist there, so this test is a no-op. */
    printf("SKIP: POSIX self-pipe shutdown test (Win32 path uses MsgQue).\n");
    return 0;
}

#endif /* _WIN32 */
