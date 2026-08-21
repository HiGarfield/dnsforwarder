#include "timedtask.h"
#include "linkedqueue.h"
#include "pipes.h"
#include "logs.h"
#include <errno.h>

#ifdef _WIN32
#include "winmsgque.h"
#else
#include <fcntl.h> /* fcntl(), O_NONBLOCK */
#endif /* _WIN32 */

typedef struct _TaskInfo{
    TaskFunc    Task;

    void    *Arg1;
    void    *Arg2;

#ifdef _WIN32
    DWORD   TimeOut;
    DWORD   LeftTime;
#else /* _WIN32 */
    struct timeval  TimeOut;
    struct timeval  LeftTime;
#endif /* _WIN32 */

    BOOL    Persistent;
    BOOL    Asynchronous;
} TaskInfo;

static LinkedQueue  TimeQueue;

#ifdef _WIN32
static WinMsgQue    MsgQue;
#else /* _WIN32 */
static PIPE_HANDLE  WriteTo, ReadFrom;
#endif /* _WIN32 */

/* Signal for the worker thread to exit; set by TimedTask_Cleanup. */
/* Signalled by TimedTask_Cleanup() and polled by the worker thread. Accessed
   only under TimedTask_ExitMutex so the write in Cleanup() and the reads in the
   worker do not race (a plain BOOL guarded by a POSIX mutex/pthread_mutex_t).
   The actual wake-up of the worker is done with the self-pipe, not by this
   flag. */
static BOOL             TimedTask_ToExit = FALSE;
/* Protects TimedTask_ToExit; initialised in TimedTask_Init and deliberately
   NOT destroyed in TimedTask_Cleanup: TimedTask_Add() is a public API that
   any thread may call, and locking a destroyed mutex is undefined behaviour.
   The process is exiting anyway, so the OS reclaims the (heap-free) mutex. */
static MutexHandle      TimedTask_ExitMutex;
/* Becomes TRUE only after every resource TimedTask_Cleanup touches has been
   successfully created.  Guarding Cleanup with it prevents the atexit-registered
   shutdown from operating on half-initialised state (e.g. a pthread_mutex_t that
   CREATE_MUTEX failed to init, or the ReadFrom/WriteTo pipe fds that are still
   the uninitialised value 0) which would be undefined behaviour / close stdin. */
static BOOL             TimedTask_Initialised = FALSE;
/* Joinable handle of the worker thread (kept joinable, not detached). */
static ThreadHandle     TimedTask_Worker = NULL_THREAD;

#ifndef _WIN32
static int Tv_Comapre(const struct timeval *one, const struct timeval *two)
{
    if( one->tv_sec == two->tv_sec )
    {
        return one->tv_usec - two->tv_usec;
    } else {
        return one->tv_sec - two->tv_sec;
    }
}

static int Tv_Subtract(struct timeval *Minuend,
                       const struct timeval *Subtrahend
                       )
{
    if( Tv_Comapre(Minuend, Subtrahend) <= 0 )
    {
        Minuend->tv_sec = 0;
        Minuend->tv_usec = 0;
        return 0;
    } else {
        if( Minuend->tv_usec >= Subtrahend->tv_usec )
        {
            Minuend->tv_usec -= Subtrahend->tv_usec;
            Minuend->tv_sec -= Subtrahend->tv_sec;
        } else {
            Minuend->tv_sec -= (1 + Subtrahend->tv_sec);
            Minuend->tv_usec = 1000000 - Subtrahend->tv_usec + Minuend->tv_usec;
        }
        return 1;
    }
}
#endif /* _WIN32 */

#ifdef _WIN32
static void TimeTask_ReduceTime(const DWORD tv)
{
    LinkedQueueIterator i;
    TaskInfo *ti;

    if( LinkedQueueIterator_Init(&i, &TimeQueue) != 0 )
    {
        /** TODO: Show fatal error */
        return;
    }

    while( (ti = i.Next(&i)) != NULL )
    {
        if( tv > ti->LeftTime )
        {
            ti->LeftTime = 0;
        } else {
            ti->LeftTime -= tv;
        }
    }
}
#else /* _WIN32 */
static void TimeTask_ReduceTime(const struct timeval *tv)
{
    LinkedQueueIterator i;
    TaskInfo *ti;

    if( tv == NULL )
    {
        /** TODO: Show fatal error */
        return;
    }

    if( LinkedQueueIterator_Init(&i, &TimeQueue) != 0 )
    {
        /** TODO: Show fatal error */
        return;
    }

    while( (ti = i.Next(&i)) != NULL )
    {
        Tv_Subtract(&(ti->LeftTime), tv);
    }
}
#endif /* _WIN32 */

static int TimeTask_ReallyAdd(TaskInfo *i)
{
    return TimeQueue.Add(&TimeQueue, i);
}

#ifndef _WIN32
/* Read exactly one TaskInfo from the self-pipe. Returns:
 *   1  -> a complete TaskInfo was read into *Out (safe to enqueue)
 *   0  -> only a partial/short read happened (e.g. a 1-byte wake-up byte,
 *        or the pipe was closed); *Out is NOT complete and must be discarded
 *   -1 -> a fatal read error occurred
 * READ_PIPE is a raw read(2) on a stream pipe and may return fewer bytes than
 * requested (short read), so we loop until the whole structure is assembled.
 * Without this loop a single read() that fills only part of *Out would leave
 * the rest uninitialised and hand a corrupted task to TimeTask_ReallyAdd().
 * The read end of the pipe is created with O_NONBLOCK (see TimedTask_Init):
 * when only the 1-byte wake-up written by TimedTask_Cleanup() is available,
 * the loop must terminate instead of blocking forever waiting for a full
 * record -- otherwise Cleanup()'s JOIN_THREAD would hang the whole process
 * at shutdown.  EAGAIN/EWOULDBLOCK therefore counts as "nothing more is
 * available right now" and is treated like a short read (return 0). */
#ifndef TIMEDTASK_UNITTEST
static
#endif /* TIMEDTASK_UNITTEST */
int TimedTask_ReadOneTask(int fd, void *Out)
{
    char   *Cur = (char *)Out;
    size_t  Got = 0;

    while( Got < sizeof(TaskInfo) )
    {
        ssize_t r = READ_PIPE(fd, Cur + Got, sizeof(TaskInfo) - Got);
        if( r > 0 )
        {
            Got += (size_t)r;
        } else if( r == 0 ) {
            /* EOF / pipe closed: no more data. */
            break;
        } else if( errno == EINTR ) {
            /* Interrupted: retry the read. */
            continue;
        } else if( errno == EAGAIN || errno == EWOULDBLOCK ) {
            /* Non-blocking pipe, nothing more available right now: the
               record (if any) is incomplete, discard it. */
            break;
        } else {
            return -1;
        }
    }

    return (Got == sizeof(TaskInfo)) ? 1 : 0;
}
#endif /* _WIN32 */

static void
#ifdef WIN32
WINAPI
#endif
TimeTask_RunTack(void *i)
{
    TaskInfo *Info = (TaskInfo *)i;

    Info->Task(Info->Arg1, Info->Arg2);

    if( Info->Persistent )
    {
        BOOL KeepRunning;

        /* Consult the exit flag under the mutex before re-posting: once
           TimedTask_Cleanup has set it, the worker is about to free the queue
           and close the pipe. Re-posting a persistent *asynchronous* task here
           would WRITE_PIPE() into an already-closed (or recycled) fd and/or
           hand a dangling TaskInfo to a freed queue -- a use-after-free and
           possible cross-socket data corruption at shutdown. Bail out instead
           so the task dies quietly. */
        GET_MUTEX(TimedTask_ExitMutex);
        KeepRunning = !TimedTask_ToExit;
        RELEASE_MUTEX(TimedTask_ExitMutex);

        if( !KeepRunning )
        {
            return;
        }

        Info->LeftTime = Info->TimeOut;
        if( Info->Asynchronous )
        {
#ifdef _WIN32
            if( MsgQue.Post(&MsgQue, Info) != 0 )
            {
                /** TODO: Show fatal error */
            }
#else /* _WIN32 */
            if( WRITE_PIPE(WriteTo, Info, sizeof(TaskInfo)) < 0 )
            {
                /** TODO: Show fatal error */
            }
#endif /* _WIN32 */
        } else {
            if( TimeTask_ReallyAdd(Info) != 0 )
            {
                /** TODO: Show fatal error */
            }
        }
    }

    LinkedQueue_FreeNode(i);
}

/* Only the particular one thread execute the function */
static void
#ifdef WIN32
WINAPI
#endif
TimeTask_Work(void *Unused)
{
#ifdef _WIN32
    static TaskInfo *i = NULL;
    static DWORD *tv = NULL;
    DWORD BeforeWaiting = 0;
    DWORD ElapsedTime = 0;

    while( TRUE )
    {
        static TaskInfo *New;
        BOOL WantExit;

        GET_MUTEX(TimedTask_ExitMutex);
        WantExit = TimedTask_ToExit;
        RELEASE_MUTEX(TimedTask_ExitMutex);

        if( WantExit )
        {
            break;
        }

        i = TimeQueue.Get(&TimeQueue);
        if( i == NULL )
        {
            tv = NULL;
        } else {
            tv = &(i->LeftTime);
            BeforeWaiting = *tv;
        }

        New = MsgQue.Wait(&MsgQue, tv);
        if( tv != NULL )
        {
            ElapsedTime = BeforeWaiting - *tv;
        }

        if( New == NULL )
        {
            /* Run the task */
            TimeTask_ReduceTime(ElapsedTime);

            /* Make analyzer happy. Shouldn't be both NULL. */
            if( i == NULL )
            {
                continue;
            }

            if( i->Asynchronous )
            {
                ThreadHandle t;
                CREATE_THREAD(TimeTask_RunTack, i, t);
                DETACH_THREAD(t);
            } else {
                TimeTask_RunTack(i);
            }

        } else {
            int r;

            if( i != NULL )
            {
                r = TimeTask_ReallyAdd(i);
                LinkedQueue_FreeNode(i);
                if( r != 0 )
                {
                    /** TODO: Show fatal error */
                    break;
                }
            }

            /* Receive a new task from other thread */
            if( tv != NULL )
            {
                TimeTask_ReduceTime(ElapsedTime);
            }

            r = TimeTask_ReallyAdd(New);
            WinMsgQue_FreeMsg(New);
            if( r != 0 )
            {
                /** TODO: Show fatal error */
                break;
            }
        }
    }
#else /* _WIN32 */
    static fd_set   ReadSet, ReadySet;

    static TaskInfo *i = NULL;
    static struct timeval   *tv = NULL;
    static struct timeval   Elapsed = {0, 0};

    FD_ZERO(&ReadSet);
    FD_SET(ReadFrom, &ReadSet);

    while( TRUE )
    {
        BOOL WantExit;

        GET_MUTEX(TimedTask_ExitMutex);
        WantExit = TimedTask_ToExit;
        RELEASE_MUTEX(TimedTask_ExitMutex);

        if( WantExit )
        {
            break;
        }

        i = TimeQueue.Get(&TimeQueue);

        if( i == NULL )
        {
            tv = NULL;
        } else {
            tv = &(i->LeftTime);
            Elapsed = *tv;
        }

        ReadySet = ReadSet;
        switch( select(ReadFrom + 1, &ReadySet, NULL, NULL, tv) )
        {
        case SOCKET_ERROR:
            /** TODO: Show fatal error */
            /* A transient select() error (e.g. EINTR from a signal delivery,
               or a momentarily bad descriptor) must not wedge the worker: the
               old code spun forever here and, because it never re-checked
               TimedTask_ToExit, made TimedTask_Cleanup()'s JOIN_THREAD hang
               the whole process on shutdown. Fall through to the loop's exit
               check and retry instead. */
            break;

        case 0:
            /* Run the task */
            if( i == NULL || tv == NULL )
            {
                /* No task but select timed out: cannot happen unless the
                   queue was empty, in which case there is nothing to do. */
                break;
            }
            Tv_Subtract(&Elapsed, tv);
            TimeTask_ReduceTime(&Elapsed);

            if( i->Asynchronous )
            {
                ThreadHandle t;
                CREATE_THREAD(TimeTask_RunTack, i, t);
                DETACH_THREAD(t);
            } else {
                TimeTask_RunTack(i);
            }

            break;

        default:
            /* Receive a new task from other thread */
            if( tv != NULL )
            {
                Tv_Subtract(&Elapsed, tv);
                TimeTask_ReduceTime(&Elapsed);
            }

            {
                static TaskInfo ni;
                int r = TimedTask_ReadOneTask(ReadFrom, &ni);

                /* A partial/short read (e.g. a lone 1-byte wake-up byte from
                   TimedTask_Cleanup, or a signal-interrupted read) MUST be
                   discarded, never enqueued as a (corrupted) task. A complete
                   read is safe to add. */
                if( r == 1 )
                {
                    if( TimeTask_ReallyAdd(&ni) != 0 )
                    {
                        /** TODO: Show fatal error */
                        break;
                    }
                } else if( r < 0 ) {
                    /** TODO: Show fatal error */
                    break;
                }
            }

            if( i != NULL )
            {
                int r = TimeTask_ReallyAdd(i);
                LinkedQueue_FreeNode(i);
                if( r != 0 )
                {
                    /** TODO: Show fatal error */
                    break;
                }
            }

            break;
        }
    }
#endif /* _WIN32 */
}

int TimedTask_Add(BOOL Persistent,
                 BOOL Asynchronous,
                 int Milliseconds,
                 TaskFunc Func,
                 void *Arg1,
                 void *Arg2,
                 BOOL Immediate
                 )
{
    TaskInfo i;

    if( Func == NULL )
    {
        return -33;
    }

    i.Task = Func;
    i.Arg1 = Arg1;
    i.Arg2 = Arg2;
    i.Persistent = Persistent;
    i.Asynchronous = Asynchronous;
#ifdef _WIN32
    i.TimeOut = Milliseconds;
#else /* _WIN32 */
    i.TimeOut.tv_usec = (Milliseconds % 1000) * 1000;
    i.TimeOut.tv_sec = Milliseconds / 1000;
#endif /* _WIN32 */
    if( Immediate )
    {
#ifdef _WIN32
        i.LeftTime = 0;
#else /* _WIN32 */
        i.LeftTime.tv_sec = 0;
        i.LeftTime.tv_usec = 0;
#endif /* _WIN32 */
    } else {
        i.LeftTime = i.TimeOut;
    }

#ifdef _WIN32
    if( MsgQue.Post(&MsgQue, &i) != 0 )
    {
        return -212;
    }
#else /* _WIN32 */
    /* Serialize the shutdown check with TimedTask_Cleanup().  Cleanup sets
       TimedTask_ToExit under the same mutex and only afterwards closes
       WriteTo, so an Add that observes ToExit here can never write() to a
       descriptor Cleanup has already closed -- a TOCTOU that could, after fd
       reuse, target an unrelated open file/socket.  The mutex is released
       before the (potentially blocking) pipe write so a full pipe cannot
       wedge the worker, which takes the same mutex at the top of its loop. */
    GET_MUTEX(TimedTask_ExitMutex);
    if( TimedTask_ToExit )
    {
        RELEASE_MUTEX(TimedTask_ExitMutex);
        return -53;
    }
    RELEASE_MUTEX(TimedTask_ExitMutex);

    if( WRITE_PIPE(WriteTo, &i, sizeof(TaskInfo)) < 0 )
    {
        return -53;
    }
#endif /* _WIN32 */

    return 0;
}

static int Compare(const void *One, const void *Two)
{
    const TaskInfo *o = One, *t = Two;
#ifdef _WIN32
    return o->LeftTime - t->LeftTime;
#else /* _WIN32 */
    return Tv_Comapre(&(o->LeftTime), &(t->LeftTime));
#endif /* _WIN32 */
}

static void TimedTask_Cleanup(void)
{
    /* If Init never finished (or never ran), the resources below are either
       uninitialised or partially created; touching them would be UB.  Bail out
       without touching anything. */
    if( !TimedTask_Initialised )
    {
        return;
    }

    /* Signal the worker to exit and wait for it to terminate so it does
       not touch the queue/pipe after we free them. */
    GET_MUTEX(TimedTask_ExitMutex);
    TimedTask_ToExit = TRUE;
    RELEASE_MUTEX(TimedTask_ExitMutex);

#ifdef _WIN32
    /* Posting a message sets the internal event and wakes the worker
       even when it is blocked inside MsgQue.Wait(). */
    MsgQue.Post(&MsgQue, NULL);
#else /* _WIN32 */
    {
        /* Write a wake-up byte so select() returns even when idle. */
        char Dummy = 0;
        (void)WRITE_PIPE(WriteTo, &Dummy, sizeof(Dummy));
    }
#endif /* _WIN32 */

    if( TimedTask_Worker != NULL_THREAD )
    {
        JOIN_THREAD(TimedTask_Worker);
        TimedTask_Worker = NULL_THREAD;
    }

    TimeQueue.Free(&TimeQueue);
#ifdef _WIN32
    WinMsgQue_Destroy(&MsgQue);
#else /* _WIN32 */
    close(ReadFrom);
    close(WriteTo);
#endif /* _WIN32 */

    /* Do NOT destroy TimedTask_ExitMutex.  TimedTask_Add() is a public API
       that any module thread may call; after this handler runs (it is the
       last atexit handler) a detached thread could still be alive and would
       lock() a destroyed mutex -- undefined behaviour.  The process is
       exiting and the OS reclaims the (heap-free) pthread_mutex_t, so
       leaving it undestroyed is the safe choice, matching the shutdown
       convention in tcpfrontend.c / udpfrontend.c. */
}

int TimedTask_Init(void)
{
    ThreadHandle t = NULL_THREAD;

    if( LinkedQueue_Init(&TimeQueue,
                         sizeof(TaskInfo),
                         Compare
                         ) != 0
       )
    {
        return -20;
    }

    if( CREATE_MUTEX(TimedTask_ExitMutex) != 0 )
    {
        TimeQueue.Free(&TimeQueue);
        return -248;
    }

#ifdef _WIN32
    if( WinMsgQue_Init(&MsgQue, sizeof(TaskInfo)) != 0 )
    {
        DESTROY_MUTEX(TimedTask_ExitMutex);
        TimeQueue.Free(&TimeQueue);
        return -247;
    }
#else /* _WIN32 */
    if( !CREATE_PIPE_SUCCEEDED(CREATE_PIPE(&ReadFrom, &WriteTo)) )
    {
        DESTROY_MUTEX(TimedTask_ExitMutex);
        TimeQueue.Free(&TimeQueue);
        return -25;
    }

    /* Make the read end of the self-pipe non-blocking.  TimedTask_Cleanup()
       wakes the worker by writing a single byte; if the pipe stayed blocking,
       TimedTask_ReadOneTask() would read that byte and then block forever
       waiting for the rest of a TaskInfo that never comes, so Cleanup()'s
       JOIN_THREAD() would hang the whole process at shutdown.  With O_NONBLOCK
       the follow-up read() fails with EAGAIN, the short read is discarded and
       the worker re-checks the exit flag and terminates. */
    {
        int Flags = fcntl(ReadFrom, F_GETFL, 0);
        if( Flags < 0 || fcntl(ReadFrom, F_SETFL, Flags | O_NONBLOCK) != 0 )
        {
            close(ReadFrom);
            close(WriteTo);
            DESTROY_MUTEX(TimedTask_ExitMutex);
            TimeQueue.Free(&TimeQueue);
            return -25;
        }
    }
#endif /* _WIN32 */

#ifdef _WIN32
    CREATE_THREAD(TimeTask_Work, NULL, t);
#else /* _WIN32 */
    /* pthread_create() leaves *thread unspecified on failure; initialising t
       to NULL_THREAD and re-checking is not guaranteed to detect it, so check
       the return value explicitly.  A failed spawn must not leave a garbage
       ThreadHandle behind that Cleanup() would later JOIN_THREAD(). */
    if( pthread_create(&t,
                       NULL,
                       (void *(*)(void *))TimeTask_Work,
                       NULL
                       ) != 0
       )
    {
        t = NULL_THREAD;
    }
#endif /* _WIN32 */
    TimedTask_Worker = t;

    /* Only now are all the resources Cleanup touches fully initialised.
       Register the shutdown hook last so a failed init (above) never leaves
       atexit pointing at half-built state. */
    TimedTask_Initialised = TRUE;
    atexit(TimedTask_Cleanup);

    return 0;
}
