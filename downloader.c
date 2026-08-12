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

    while( *URLs != NULL )
    {
        if( GetFromInternet_SingleFile(*URLs, TempFile, TRUE, RetryInterval, RetryTimes, ErrorCallBack, SuccessCallBack) != 0 )
        {
            /* A single failure means the merged result is incomplete, so the
               existing target file must NOT be overwritten with a partial one.
               We still try the remaining URLs to surface as many errors as
               possible, but the final commit is suppressed below. */
            AllSucceeded = FALSE;
        }

        fp = fopen(TempFile, "a+");
        if( fp != NULL )
        {
            fputc('\n', fp);
            fclose(fp);
        } else {
            break;
        }

        ++URLs;
    }

    if( AllSucceeded )
    {
        remove(File);
        rename(TempFile, File);
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

        while( RetryTimes != 0 )
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

                SLEEP(RetryInterval * 1000);
            }
        }

        remove(TempFile);
        SafeFree(TempFile);
        return Ret;
    }
}

#ifdef DOWNLOAD_LIBCURL
static size_t WriteFileCallback(void *Contents,
                                size_t Size,
                                size_t nmemb,
                                void *FileDes
                                )
{
    FILE *fp = (FILE *)FileDes;
    fwrite(Contents, Size, nmemb, fp);
    return Size * nmemb;
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

        fwrite(Buffer, 1, ReadedLength, fp);
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
