#ifndef DOWNLOADER_H_INCLUDED
#define DOWNLOADER_H_INCLUDED

#include "common.h"

int GetFromInternet_MultiFiles(const char   **URLs,
                               const char   *File,
                               int          RetryInterval,
                               int          RetryTimes,
                               void         (*ErrorCallBack)(int ErrorCode, const char *URL, const char *File),
                               void         (*SuccessCallBack)(const char *URL, const char *File)
                               );

int GetFromInternet_SingleFile(const char   *URL,
                               const char   *File,
                               BOOL         Append,
                               int          RetryInterval,
                               int          RetryTimes,
                               void         (*ErrorCallBack)(int ErrorCode, const char *URL, const char *File),
                               void         (*SuccessCallBack)(const char *URL, const char *File)
                               );

int GetFromInternet_Base(const char *URL, const char *File);

#ifdef DOWNLOAD_LIBCURL
/* Exposed for unit testing the short-write behaviour of the libcurl write
   callback (it must report the exact number of bytes fwrite() stored, never
   the requested amount, so a short write aborts the transfer). */
size_t WriteFileCallback(void *Contents,
                         size_t Size,
                         size_t nmemb,
                         void *FileDes);
#endif /* DOWNLOAD_LIBCURL */

#endif /* DOWNLOADER_H_INCLUDED */

