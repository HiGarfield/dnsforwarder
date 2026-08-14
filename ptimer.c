#include <limits.h>
#include "ptimer.h"

int PTimer_Start(PTimer *t)
{
#ifdef _WIN32
    #ifdef _WIN64
    t->c = GetTickCount64();
    return 0;
    #else
    t->c = GetTickCount();
    return 0;
    #endif /* _WIN64 */
#else
    return clock_gettime(CLOCK_REALTIME, &(t->c));
#endif /* _WIN32 */
}

unsigned long PTimer_End(const PTimer *t)
{
#ifdef _WIN32
    #ifdef _WIN64
    return (unsigned long)(GetTickCount64() - t->c);
    #else
    return (unsigned long)(GetTickCount() - t->c);
    #endif /* _WIN64 */
#else
    struct timespec e;
    unsigned long ms;

    if( clock_gettime(CLOCK_REALTIME, &e) != 0 )
    {
        return ULONG_MAX;
    }

    if( e.tv_nsec >= t->c.tv_nsec )
    {
        ms = (e.tv_nsec - t->c.tv_nsec) / 1000000;
    } else {
        --e.tv_sec;
        /*ms = ((1000000000 + e.tv_nsec) - t->c.tv_nsec) / 1000000;*/
        ms = ((1000000000 - t->c.tv_nsec) + e.tv_nsec) / 1000000;
    }

    if( e.tv_sec < t->c.tv_sec )
    {
        return ULONG_MAX;
    }

    ms += (e.tv_sec - t->c.tv_sec) * 1000;

    return ms;
#endif /* _WIN32 */
}
