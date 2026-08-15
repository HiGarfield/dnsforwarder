#ifndef TIMEDTASK_H_INCLUDED
#define TIMEDTASK_H_INCLUDED

#include "common.h"

typedef int (*TaskFunc)(void *Arg1, void *Arg2);

int TimedTask_Init(void);

int TimedTask_Add(BOOL Persistent,
                  BOOL Asynchronous,
                  int Milliseconds,
                  TaskFunc Func,
                  void *Arg1,
                  void *Arg2,
                  BOOL Immediate
                  );

/* Test-only hook: when building the unit test, expose the self-pipe reader so
   the partial-read (short-read) fix can be verified in isolation. */
#ifdef TIMEDTASK_UNITTEST
#ifndef _WIN32
int TimedTask_ReadOneTask(int fd, void *Out);
#endif /* _WIN32 */
#endif /* TIMEDTASK_UNITTEST */

#endif /* TIMEDTASK_H_INCLUDED */
