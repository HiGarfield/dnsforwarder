/* Regression test for CopyAFile() (utils.c) short/error write handling.
 *
 * Before the fix CopyAFile() ignored fputc()'s return value while copying and
 * always returned 0, so a failed write (e.g. destination disk full) produced a
 * silently truncated file reported as a successful copy. After the fix a failed
 * fputc()/fclose() makes CopyAFile() return a negative error code.
 *
 * We copy a small source file onto /dev/full, the Linux sink device that fails
 * every write with ENOSPC: the copy must report failure, not success. A normal
 * copy onto a tmpfile must still report success (regression).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

static void WriteSource(const char *Path, const char *Text)
{
    FILE *fp = fopen(Path, "w");
    if( fp != NULL )
    {
        fputs(Text, fp);
        fclose(fp);
    }
}

int main(void)
{
    int ok = 1;
    char Src[] = "/tmp/copyafile_src_XXXXXX";
    int  fd = mkstemp(Src);
    if( fd < 0 )
    {
        perror("mkstemp");
        return 2;
    }
    close(fd);

    WriteSource(Src, "hello-copyafile-content\n");

    /* --- Case 1: writing onto /dev/full must FAIL, not be reported as OK --- */
    {
        int ret = CopyAFile(Src, "/dev/full", FALSE);
        printf("Case1 (dst=/dev/full) ret=%d\n", ret);
        if( ret == 0 )
        {
            printf("FAIL: truncated copy onto /dev/full reported success\n");
            ok = 0;
        }
        else
        {
            printf("PASS: failed write correctly reported (ret=%d)\n", ret);
        }
    }

    /* --- Case 2: normal copy onto a tmpfile must succeed (regression) --- */
    {
        char Dst[] = "/tmp/copyafile_dst_XXXXXX";
        int  dfd = mkstemp(Dst);
        if( dfd < 0 )
        {
            perror("mkstemp dst");
            return 2;
        }
        close(dfd);

        int ret = CopyAFile(Src, Dst, FALSE);
        printf("Case2 (dst=tmpfile) ret=%d\n", ret);

        /* Verify the content was copied intact. */
        char Buf[256] = {0};
        FILE *fp = fopen(Dst, "r");
        size_t n = (fp != NULL) ? fread(Buf, 1, sizeof(Buf) - 1, fp) : 0;
        if( fp != NULL ) fclose(fp);

        if( ret != 0 )
        {
            printf("FAIL: normal copy reported failure (ret=%d)\n", ret);
            ok = 0;
        }
        else if( n != strlen("hello-copyafile-content\n") ||
                 memcmp(Buf, "hello-copyafile-content\n", n) != 0 )
        {
            printf("FAIL: normal copy content mismatch\n");
            ok = 0;
        }
        else
        {
            printf("PASS: normal copy succeeded and content intact\n");
        }
        remove(Dst);
    }

    remove(Src);

    if( ok )
    {
        printf("PASS\n");
        return 0;
    }
    return 1;
}
