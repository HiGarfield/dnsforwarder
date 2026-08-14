/* Regression test for the short/error write handling of WriteFileCallback()
 * (the libcurl write callback in downloader.c).
 *
 * Before the fix the callback ignored fwrite()'s return value and always
 * returned Size * nmemb, so a short/erroring write (disk full, broken stream,
 * ...) was reported to libcurl as a fully successful store and the download
 * finished with a silently truncated (or empty) file. After the fix the
 * callback returns exactly the number of bytes fwrite() actually wrote; a
 * failed/short write therefore yields a return value strictly smaller than the
 * requested amount, which makes libcurl abort the transfer with
 * CURLE_WRITE_ERROR (so the truncated temp file is discarded, not committed).
 *
 * Case 1 drives WriteFileCallback() against a non-blocking pipe whose buffer
 * is already full: fwrite() returns 0 with ferror set, exactly the
 * "can't write any more" condition the fix must surface. Case 2/3 exercise the
 * normal full-write path (custom cookie stream and a real tmpfile) to prove
 * the fix does not break successful downloads.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "downloader.h"

/* stream that stores everything (normal, full-write path) */
static ssize_t cookie_write_keep(void *cookie, const char *data, size_t size)
{
    char *buf = (char *)cookie;
    memcpy(buf, data, size);
    return size;
}

static int cookie_close_noop(void *cookie)
{
    (void)cookie;
    return 0;
}

int main(void)
{
    int ok = 1;

    /* --- Case 1: write failure on a full non-blocking pipe --- */
    {
        int fds[2];
        if( pipe(fds) != 0 )
        {
            fprintf(stderr, "pipe failed: %s\n", strerror(errno));
            return 2;
        }
        fcntl(fds[1], F_SETFL, O_NONBLOCK);

        /* Fill the pipe so the next write() returns EAGAIN. */
        char fill[65536];
        memset(fill, 'x', sizeof(fill));
        while( write(fds[1], fill, sizeof(fill)) > 0 )
        {
            /* drain nothing: intentionally saturate the kernel buffer */
        }

        FILE *fp = fdopen(fds[1], "w");
        if( fp == NULL )
        {
            fprintf(stderr, "fdopen failed: %s\n", strerror(errno));
            return 2;
        }
        /* Unbuffered so fwrite() goes straight to write() and observes EAGAIN. */
        setvbuf(fp, NULL, _IONBF, 0);

        char payload[100];
        memset(payload, 'X', sizeof(payload));

        size_t asked = sizeof(payload);                 /* Size=1, nmemb=100 */
        size_t got   = WriteFileCallback(payload, 1, asked, fp);

        printf("Case1 (full pipe) asked=%zu got=%zu ferror=%d\n",
               asked, got, ferror(fp));

        fclose(fp);
        close(fds[0]);

        if( got == asked )
        {
            printf("FAIL: failed write reported as fully successful "
                   "(got == asked)\n");
            ok = 0;
        }
        else
        {
            printf("PASS: failure correctly propagated (got=%zu < asked)\n", got);
        }
    }

    /* --- Case 2: full write via cookie stream (regression) --- */
    {
        char sink[64];
        cookie_io_functions_t io = { NULL, cookie_write_keep, NULL,
                                      cookie_close_noop };
        FILE *fp = fopencookie(sink, "w", io);
        if( fp == NULL )
        {
            fprintf(stderr, "fopencookie failed: %s\n", strerror(errno));
            return 2;
        }

        char payload[64];
        memset(payload, 'Y', sizeof(payload));

        size_t asked = sizeof(payload);
        size_t got   = WriteFileCallback(payload, 1, asked, fp);

        fclose(fp);

        printf("Case2 (full write) asked=%zu got=%zu\n", asked, got);
        if( got != asked )
        {
            printf("FAIL: full write under-reported (got=%zu, asked=%zu)\n",
                   got, asked);
            ok = 0;
        }
        else
        {
            printf("PASS: full write correctly reported\n");
        }
    }

    /* --- Case 3: real tmpfile full write (integration regression) --- */
    {
        FILE *fp = tmpfile();
        if( fp == NULL )
        {
            fprintf(stderr, "tmpfile failed: %s\n", strerror(errno));
            return 2;
        }

        char payload[256];
        memset(payload, 'Z', sizeof(payload));

        size_t asked = sizeof(payload);
        size_t got   = WriteFileCallback(payload, 1, asked, fp);

        fclose(fp);

        printf("Case3 (tmpfile full write) asked=%zu got=%zu\n", asked, got);
        if( got != asked )
        {
            printf("FAIL: tmpfile full write under-reported (got=%zu)\n", got);
            ok = 0;
        }
        else
        {
            printf("PASS: tmpfile full write correctly reported\n");
        }
    }

    if( ok )
    {
        printf("PASS\n");
        return 0;
    }
    return 1;
}
