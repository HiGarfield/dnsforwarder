#include "timedtask.h"
#include "linkedqueue.h"
#include "pipes.h"
#include "logs.h"

#ifdef _WIN32
#include "winmsgque.h"
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
static volatile BOOL    TimedTask_ToExit = FALSE;
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

        if( TimedTask_ToExit )
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
        if( TimedTask_ToExit )
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
            while( TRUE )
            {
                SLEEP(32767);
            }
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

                if( READ_PIPE(ReadFrom, &ni, sizeof(TaskInfo)) < 0 )
                {
                    /** TODO: Show fatal error */
                    break;
                }

                if( TimeTask_ReallyAdd(&ni) != 0 )
                {
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
    /* Signal the worker to exit and wait for it to terminate so it does
       not touch the queue/pipe after we free them. */
    TimedTask_ToExit = TRUE;

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
}

int TimedTask_Init(void)
{
    ThreadHandle t;

    if( LinkedQueue_Init(&TimeQueue,
                         sizeof(TaskInfo),
                         Compare
                         ) != 0
       )
    {
        return -20;
    }

    atexit(TimedTask_Cleanup);

#ifdef _WIN32
    if( WinMsgQue_Init(&MsgQue, sizeof(TaskInfo)) != 0 )
    {
        return -247;
    }
#else /* _WIN32 */
    if( !CREATE_PIPE_SUCCEEDED(CREATE_PIPE(&ReadFrom, &WriteTo)) )
    {
        return -25;
    }
#endif /* _WIN32 */

    CREATE_THREAD(TimeTask_Work, NULL, t);
    TimedTask_Worker = t;

    return 0;
}
