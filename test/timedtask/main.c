#include <stdio.h>
#include <time.h>
#include "../../timedtask.h"

void p(void *t, void *u)
{
    printf("%ld : %s\n", time(NULL), (const char *)t);
}

void j2(void *a, void *b)
{
    printf("%ld : %s\n", time(NULL), "Job 2 start .");
    SLEEP(4000);
    printf("%ld : %s\n", time(NULL), "Job 2 end .");
}

int main(void)
{
    TimedTask_Init();

    printf("-->Job 1, Executing every 2 seconds.\n");
    TimedTask_Add(TRUE, FALSE, 2000, p, "Job 1 .", NULL, FALSE);

    printf("-->Job 2, Executing every 3 seconds.\n");
    TimedTask_Add(TRUE, TRUE, 3000, j2, NULL, NULL, FALSE);

    SLEEP(10000);

    printf("-->Job 3, Executing after 5 seconds.\n");
    TimedTask_Add(TRUE, FALSE, 5000, p, "Job 3 .", NULL, TRUE);

    SLEEP(9999);
    return 0;
}
