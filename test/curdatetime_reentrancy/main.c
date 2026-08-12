/*
 * Regression test: GetCurDateAndTime() must not use the process-wide
 * `struct tm' handed out by localtime().
 *
 * Every thread of the daemon formats its log timestamp through
 * GetCurDateAndTime(), and Log_Print() does so *before* taking the print
 * lock. With plain localtime() the threads share one broken-down time
 * (and the library's lazily initialised timezone state), so timestamps
 * could be overwritten mid-format by another thread.
 *
 * Two independent checks:
 *
 *   1. Deterministic, single-threaded: hold on to the `struct tm' that
 *      localtime() returns for a fixed instant, call GetCurDateAndTime()
 *      for the current time, and verify the held structure is untouched.
 *      A GetCurDateAndTime() built on localtime() clobbers it.
 *
 *   2. Concurrent: many threads format timestamps at the same time and
 *      every result must be a well-formed "YYYY/MM/DD HH:MM:SS" close to
 *      now. Under ThreadSanitizer (see run.sh) this also flags the race
 *      itself.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "../../utils.h"

#define THREADS         8
#define ITERATIONS      4000

static int Failures = 0;
static int Checks = 0;

static void Check(const char *Name, int Condition)
{
    ++Checks;
    if( Condition )
    {
        printf("  [ ok ] %s\n", Name);
    } else {
        printf("  [FAIL] %s\n", Name);
        ++Failures;
    }
}

/* ------------------------------------------------------------------ */

static void Test_DoesNotClobberLocaltime(void)
{
    /* 2001-09-09 01:46:40 UTC, an instant that cannot be "now". */
    time_t Fixed = (time_t)1000000000;
    struct tm *Shared;
    struct tm Snapshot;
    char Buffer[32];

    printf("GetCurDateAndTime() and the shared localtime() buffer\n");

    Shared = localtime(&Fixed);
    if( Shared == NULL )
    {
        printf("  [SKIP] localtime() failed\n");
        return;
    }
    Snapshot = *Shared;

    if( GetCurDateAndTime(Buffer, sizeof(Buffer)) == NULL )
    {
        printf("  [SKIP] GetCurDateAndTime() failed\n");
        return;
    }

    Check("the struct tm returned by localtime() is left alone",
          Shared->tm_year == Snapshot.tm_year &&
          Shared->tm_mon == Snapshot.tm_mon &&
          Shared->tm_mday == Snapshot.tm_mday &&
          Shared->tm_hour == Snapshot.tm_hour &&
          Shared->tm_min == Snapshot.tm_min &&
          Shared->tm_sec == Snapshot.tm_sec);

    /* And the timestamp it produced really is the current time, not the
       fixed instant above. */
    {
        time_t Now = time(NULL);
        struct tm NowTm;
        char Expected[32];

#ifdef _WIN32
        NowTm = *localtime(&Now);
#else
        localtime_r(&Now, &NowTm);
#endif
        strftime(Expected, sizeof(Expected), "%Y/", &NowTm);
        Check("the produced timestamp belongs to the current year",
              strncmp(Buffer, Expected, strlen(Expected)) == 0);
    }
}

/* ------------------------------------------------------------------ */

typedef struct {
    int Bad;
    int Empty;
} ThreadResult;

static void *Worker(void *Arg)
{
    ThreadResult *Result = (ThreadResult *)Arg;
    int n;

    Result->Bad = 0;
    Result->Empty = 0;

    for( n = 0; n < ITERATIONS; ++n )
    {
        char Buffer[32];
        int Year, Month, Day, Hour, Minute, Second;

        memset(Buffer, 0x7F, sizeof(Buffer));

        if( GetCurDateAndTime(Buffer, sizeof(Buffer)) == NULL )
        {
            ++Result->Bad;
            continue;
        }

        if( Buffer[0] == '\0' )
        {
            ++Result->Empty;
            continue;
        }

        if( sscanf(Buffer, "%d/%d/%d %d:%d:%d",
                   &Year, &Month, &Day, &Hour, &Minute, &Second) != 6 )
        {
            ++Result->Bad;
            continue;
        }

        if( Year < 2000 || Year > 3000 ||
            Month < 1 || Month > 12 ||
            Day < 1 || Day > 31 ||
            Hour < 0 || Hour > 23 ||
            Minute < 0 || Minute > 59 ||
            Second < 0 || Second > 61 )
        {
            ++Result->Bad;
        }
    }

    return NULL;
}

static void Test_ConcurrentFormatting(void)
{
    pthread_t Threads[THREADS];
    ThreadResult Results[THREADS];
    int Bad = 0;
    int Empty = 0;
    int n;

    printf("Concurrent timestamp formatting\n");

    for( n = 0; n < THREADS; ++n )
    {
        if( pthread_create(&(Threads[n]), NULL, Worker, &(Results[n])) != 0 )
        {
            printf("  [SKIP] could not create thread %d\n", n);
            while( --n >= 0 )
            {
                pthread_join(Threads[n], NULL);
            }
            return;
        }
    }

    for( n = 0; n < THREADS; ++n )
    {
        pthread_join(Threads[n], NULL);
        Bad += Results[n].Bad;
        Empty += Results[n].Empty;
    }

    printf("  (%d threads x %d timestamps, %d malformed, %d empty)\n",
           THREADS, ITERATIONS, Bad, Empty);

    Check("every concurrently formatted timestamp is well-formed", Bad == 0);
    Check("no concurrently formatted timestamp came out empty", Empty == 0);
}

int main(void)
{
    printf("== GetCurDateAndTime() reentrancy tests ==\n\n");

    Test_DoesNotClobberLocaltime();
    Test_ConcurrentFormatting();

    printf("\n%d checks, %d failure(s)\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
