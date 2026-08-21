/* Regression test for the ExpandPath() silent-failure bug (Round-7 review):

   The POSIX wordexp branch expanded the path and then copied it into the
   caller's buffer only when it fit; when the expansion was too large for
   BufferLength it skipped the copy but still returned 0, so the caller
   (e.g. ExpandPathTo / GetLocalPathFromURL) believed the unexpanded path
   had been expanded and kept using it.

   Fix: mirror the _WIN32 branch and report the oversized expansion as an
   error (-1), leaving the caller's buffer untouched.

   Part 1: a plain path expands successfully and returns 0.
   Part 2: an expansion that overflows a small BufferLength must return -1
   (skipped when the environment cannot produce a long expansion).
   Part 3 (structural, in run.sh): the POSIX branch must contain the
   "> BufferLength" failure check and return -1.
*/
#ifndef _WIN32

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "utils.h"

int main(void)
{
    char buf[1024];

    /* Part 1: plain path, no expansion -> success. */
    strcpy(buf, "/tmp/expandpath_overflow_test");
    if( ExpandPath(buf, sizeof(buf)) != 0 )
    {
        printf("FAIL: ExpandPath on a plain path returned failure\n");
        return 1;
    }
    printf("PASS: plain path expands successfully\n");

    /* Part 2: "$PATH" usually expands to a string far longer than 8 bytes;
       with a tiny buffer the expansion must be reported as failure, not
       silently swallowed. */
    {
        const char *path = getenv("PATH");

        if( path == NULL || (int)strlen(path) < 8 )
        {
            printf("skip: PATH too short to exercise the overflow branch\n");
        } else {
            char before[64];

            strcpy(buf, "$PATH");
            strncpy(before, buf, sizeof(before) - 1);
            before[sizeof(before) - 1] = '\0';

            if( ExpandPath(buf, 8) == 0 )
            {
                printf("FAIL: oversized expansion reported success\n");
                return 1;
            }
            /* The failed call must not have touched the buffer. */
            if( strncmp(buf, before, sizeof(before)) != 0 )
            {
                printf("FAIL: failed ExpandPath modified the buffer\n");
                return 1;
            }
            printf("PASS: oversized expansion reported failure, buffer untouched\n");
        }
    }

    printf("\nAll checks passed.\n");
    return 0;
}
#else /* _WIN32 */
int main(void)
{
    printf("POSIX-only test, skipped.\n");
    return 0;
}
#endif /* _WIN32 */
