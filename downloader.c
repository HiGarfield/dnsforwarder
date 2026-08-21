#ifndef _WIN32
#ifndef DOWNLOAD_LIBCURL
#ifndef DOWNLOAD_WGET
#ifndef NODOWNLOAD
#define NODOWNLOAD
#endif /* NODOWNLOAD */
#endif /* DOWNLOAD_WGET */
#endif /*  DOWNLOAD_LIBCURL */
#endif /* _WIN32 */

#ifndef NODOWNLOAD
#ifdef _WIN32
#else
#include <limits.h>
#ifdef DOWNLOAD_LIBCURL
#include <curl/curl.h>
#endif /* DOWNLOAD_LIBCURL */
#ifdef DOWNLOAD_WGET
#include <stdlib.h>
#include <sys/wait.h>
#endif /* DOWNLOAD_WGET */
#endif
#include "common.h"
#include "utils.h"
#endif /* NODOWNLOAD */

#include <string.h>
#include "downloader.h"
#include "logs.h"

/* Set by Downloader_Abort() (invoked by DynamicHosts_Cleanup() at shutdown)
   so a download stuck in an infinite retry loop (RetryTimes < 0) observes it
   and returns instead of looping forever.  Without this, a persistently
   failing download keeps the detached hosts-reload thread inside
   GetFromInternet_SingleFile() for ever, Reloading stays TRUE and the
   cleanup's `while(Reloading) SLEEP(10)' spins forever, hanging process
   exit. */
static volatile BOOL Downloader_Aborted = FALSE;

void Downloader_Abort(void)
{
    Downloader_Aborted = TRUE;
}

void Downloader_AbortReset(void)
{
    Downloader_Aborted = FALSE;
}

int GetFromInternet_MultiFiles(const char   **URLs,
                               const char   *File,
                               int          RetryInterval,
                               int          RetryTimes,
                               void         (*ErrorCallBack)(int ErrorCode, const char *URL, const char *File),
                               void         (*SuccessCallBack)(const char *URL, const char *File)
                               )
{
    BOOL    AllSucceeded = TRUE;
    FILE    *fp;
    char    *TempFile;

    /* An empty URL list must not run the merge loop: the temp file would stay
       empty, AllSucceeded would remain TRUE, and rename() would then replace
       the existing target file with a zero-byte file.  Fail up front and leave
       the target untouched. */
    if( URLs == NULL || URLs[0] == NULL )
    {
        return -1;
    }

    TempFile = SafeMalloc(strlen(File) + sizeof(".tmp") + 1);
    if( TempFile == NULL )
    {
        ERRORMSG("Cannot create temp file %s\n", File);
        return -1;
    }

    strcpy(TempFile, File);
    strcat(TempFile, ".tmp");

    fp = fopen(TempFile, "w");
    if( fp != NULL )
    {
        fclose(fp);
    } else {
        ERRORMSG("Cannot create temp file %s\n", TempFile);
        SafeFree(TempFile);
        return -2;
    }

    while( *URLs != NULL && !Downloader_Aborted )
    {
        if( GetFromInternet_SingleFile(*URLs, TempFile, TRUE, RetryInterval, RetryTimes, ErrorCallBack, SuccessCallBack) != 0 )
        {
            /* A single failure means the merged result is incomplete, so the
               existing target file must NOT be overwritten with a partial one.
               We still try the remaining URLs to surface as many errors as
               possible, but the final commit is suppressed below. */
            AllSucceeded = FALSE;
        }

        /* An abort (shutdown) requested while a URL was being downloaded must
           also stop iterating over the remaining URLs. */
        if( Downloader_Aborted )
        {
            break;
        }

        fp = fopen(TempFile, "a+");
        if( fp == NULL )
        {
            break;
        }

        /* `fputc` returns EOF on failure; ignoring it would silently leave
           a record separator missing and join two unrelated entries. Check
           both the write and fclose() (the latter can fail when the buffered
           data is flushed to a now-full disk).  The file must be closed in
           every path: the old `fputc(...) == EOF || fclose(...) != 0`
           short-circuited and skipped fclose() when the write failed,
           leaking one FILE descriptor per failing merge run. */
        if( fputc('\n', fp) == EOF )
        {
            fclose(fp);
            break;
        }
        if( fclose(fp) != 0 )
        {
            break;
        }

        ++URLs;
    }

    if( AllSucceeded )
    {
        /* Commit the merged result atomically. Previously the code did
           remove(File) *before* rename(TempFile, File); if rename then
           failed (e.g. cross-device move, read-only target dir) the good
           target file was already deleted and the temp file left behind --
           a silent data-loss. rename() already overwrites the destination
           atomically on success, so there is no need to pre-remove it; on
           failure the original File is left intact and we just drop the
           leftover temp file instead of leaking it. */
        if( rename(TempFile, File) != 0 )
        {
            remove(TempFile);
        }
    } else {
        /* A partial/merged result must never replace the good target file, so
           the commit above is skipped. Discard the leftover temp file instead
           of leaving it on disk until the next (successful) run. */
        remove(TempFile);
    }

    SafeFree(TempFile);
    return AllSucceeded ? 0 : -1;
}

int GetFromInternet_SingleFile(const char   *URL,
                               const char   *File,
                               BOOL         Append,
                               int          RetryInterval,
                               int          RetryTimes,
                               void         (*ErrorCallBack)(int ErrorCode, const char *URL, const char *File),
                               void         (*SuccessCallBack)(const char *URL, const char *File)
                               )
{
    if( strncmp(URL, "file", 4) == 0 )
    {
        char LocalPath[384];

        if( GetLocalPathFromURL(URL, LocalPath, sizeof(LocalPath)) == NULL )
        {
            if( ErrorCallBack != NULL )
            {
                ErrorCallBack(0, URL, File);
            }

            return -1;
        }

        if( CopyAFile(LocalPath, File, Append) != 0 )
        {
            if( ErrorCallBack != NULL )
            {
                ErrorCallBack(0, URL, File);
            }

            return -1;
        }

        if( SuccessCallBack != NULL )
        {
            SuccessCallBack(URL, File);
        }

        return 0;
    } else {
        int Ret = -1;
        char *TempFile;
        TempFile = SafeMalloc(strlen(File) + sizeof(".tmp") + 1);
        if( TempFile == NULL )
        {
            return -1;
        }
        strcpy(TempFile, File);
        strcat(TempFile, ".tmp");

        while( RetryTimes != 0 && !Downloader_Aborted )
        {
            int DownloadState = 0;

            DownloadState = GetFromInternet_Base(URL, TempFile);
            if( DownloadState == 0 )
            {
                if( SuccessCallBack != NULL )
                {
                    SuccessCallBack(URL, File);
                }

                if( CopyAFile(TempFile, File, Append) != 0 )
                {
                    if( ErrorCallBack != NULL )
                    {
                        ErrorCallBack(0, URL, File);
                    }

                    Ret = -1;
                    break;
                } else {
                    Ret = 0;
                    break;
                }
            } else {
                if( RetryTimes > 0 )
                {
                    --RetryTimes;
                }

                if( ErrorCallBack != NULL )
                {
                    ErrorCallBack((-1) * DownloadState, URL, File);
                }

                /* Abort check BEFORE the retry sleep as well, so a shutdown
                   requested while a download is failing can still interrupt
                   the retry loop promptly instead of sleeping the full retry
                   interval first. */
                if( Downloader_Aborted )
                {
                    break;
                }

                SLEEP(RetryInterval * 1000);
            }
        }

        remove(TempFile);
        SafeFree(TempFile);
        return Ret;
    }
}

#ifdef DOWNLOAD_LIBCURL
size_t WriteFileCallback(void *Contents,
                         size_t Size,
                         size_t nmemb,
                         void *FileDes
                         )
{
    FILE *fp = (FILE *)FileDes;
    /* `fwrite` returns the number of *complete* items actually written, which
       can be fewer than `nmemb` (disk full, I/O error, ...). Returning
       `Size * nmemb` unconditionally would tell libcurl the whole payload was
       stored even when only part of it was, so the download finishes "success"
       with a silently truncated file -- and no retry. Report the true count;
       a short write makes it differ from the requested amount, which libcurl
       treats as an abort and surfaces as a transfer error. */
    size_t Written = fwrite(Contents, Size, nmemb, fp);
    /* Returning fewer bytes than requested makes libcurl abort the transfer
       with CURLE_WRITE_ERROR, so GetFromInternet_Base() reports failure and
       the partial temp file is discarded (not committed over the good target).
       A short write must never be reported as a full, successful store. */
    return Written * Size;
}
#endif /* DOWNLOAD_LIBCURL */

int GetFromInternet_Base(const char *URL, const char *File)
{
#ifndef NODOWNLOAD
#   ifdef _WIN32
    FILE        *fp;
    HINTERNET   webopen     =   NULL,
                webopenurl  =   NULL;
    DWORD       ReadedLength;
    char        Buffer[4096];
    int         ret = 0;
    int         TimeOut = 30000;

    webopen = InternetOpen("dnsforwarder", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if( webopen == NULL ){
        ret = -1 * (int)GetLastError();
        goto Exit_1;
    }

    /* Timeouts must be configured on the session handle BEFORE opening the
       URL, otherwise the connect/receive timeout never takes effect for this
       request and InternetOpenUrl may block indefinitely. */
    InternetSetOption(webopen, INTERNET_OPTION_CONNECT_TIMEOUT, &TimeOut, sizeof(TimeOut));
    InternetSetOption(webopen, INTERNET_OPTION_RECEIVE_TIMEOUT, &TimeOut, sizeof(TimeOut));

    webopenurl = InternetOpenUrl(webopen, URL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if( webopenurl == NULL ){
        ret = -1 * (int)GetLastError();
        goto Exit_2;
    }

    /* Reject HTTP error responses (4xx/5xx): InternetOpenUrl succeeds even for
       error pages, so without this check a "404 Not Found" body would be
       written out and could overwrite a valid hosts file. */
    {
        DWORD StatusCode  = 0;
        DWORD StatusSize  = sizeof(StatusCode);

        if( HttpQueryInfoA(webopenurl,
                           HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                           &StatusCode,
                           &StatusSize,
                           NULL
                           )
            && StatusCode >= 400 )
        {
            WARNING("HTTP status %lu for %s, download skipped.\n", StatusCode, URL);
            ret = -1;
            goto Exit_2;
        }
    }

    fp = fopen(File, "wb" );
    if( fp == NULL )
    {
        /* fopen() is a CRT call and reports failure via errno, not
           GetLastError(); the latter is left at whatever the last Win32 API
           set, often 0. Returning -1 * GetLastError() could therefore yield 0,
           which the caller treats as a SUCCESSFUL download and may overwrite
           the real hosts file with an empty temp. Use a fixed non-zero error
           code, matching the POSIX branches. */
        ret = -1;
        goto Exit_2;
    }

    while(1)
    {
        BOOL    ReadFlag;

        ReadedLength = 0;
        ReadFlag = InternetReadFile(webopenurl, Buffer, sizeof(Buffer), &ReadedLength);

        if( ReadFlag == FALSE ){
            ret = -1 * (int)GetLastError();
            goto Exit_3;
        }

        if( ReadedLength == 0 )
            break;

        /* `fwrite` returns the number of items written, which may be fewer
           than requested on a full/erroring disk. Ignoring the result would
           silently truncate the downloaded file while still reporting success
           at the end of the loop. Check it and bail out so the truncated temp
           file is discarded rather than committed over the good target. */
        if( fwrite(Buffer, 1, ReadedLength, fp) != ReadedLength )
        {
            ret = -1;
            goto Exit_3;
        }
    }

Exit_3:
    fclose(fp);
Exit_2:
    InternetCloseHandle(webopenurl);
Exit_1:
    InternetCloseHandle(webopen);

    return ret;
#   else /* _WIN32 */

#       ifdef DOWNLOAD_LIBCURL
    CURL *curl;
    CURLcode res;

    FILE *fp;

    fp = fopen(File, "w");
    if( fp == NULL )
    {
        return -1;
    }

    curl = curl_easy_init();
    if( curl == NULL )
    {
        fclose(fp);
        return -2;
    }

    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1l);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    if( res != CURLE_OK )
    {
        curl_easy_cleanup(curl);
        fclose(fp);
        return -3;
    } else {
        curl_easy_cleanup(curl);
        fclose(fp);
        return 0;
    }
#       endif /* DOWNLOAD_LIBCURL */
#       ifdef DOWNLOAD_WGET
    char Cmd[2048];
    int Written;

    /* `Cmd` is handed to a shell by `Execute()`. Quote both arguments and
       reject the ones that could escape the quoting, otherwise a crafted
       URL turns into arbitrary shell commands. `sprintf()` also used to
       overflow `Cmd` for long URLs or paths. */
    if( strchr(URL, '\'') != NULL || strchr(File, '\'') != NULL )
    {
        ERRORMSG("Refusing to fetch %s: a quotation mark is not allowed in "
                 "a URL or in a destination path.\n",
                 URL);
        return -1;
    }

    Written = snprintf(Cmd,
                       sizeof(Cmd),
                       "wget -t 2 -T 60 -q --no-check-certificate '%s' -O '%s'",
                       URL,
                       File
                       );
    if( Written < 0 || Written >= (int)sizeof(Cmd) )
    {
        ERRORMSG("Refusing to fetch %s: the resulting command is too long.\n",
                 URL);
        return -1;
    }

    return Execute(Cmd);
#       endif /* DOWNLOAD_WGET */
#   endif /* _WIN32 */
#else /* NODOWNLOAD */
    WARNING("No downloader implemented.\n");
    return -1;
#endif /* NODOWNLOAD */
}
