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

/* Interrupt any download that is stuck in an infinite retry loop
   (RetryTimes < 0).  Set by DynamicHosts_Cleanup() at shutdown so the
   detached hosts-reload thread cannot hang the process exit: without it, a
   persistently failing download keeps the reload thread inside
   GetFromInternet_SingleFile() forever, Reloading stays TRUE and the
   cleanup's `while(Reloading) SLEEP(10)` spins forever.  Downloader_Abort()
   stops the current retry loop as soon as it checks the flag (before the
   next attempt, and before sleeping for the retry interval). */
void Downloader_Abort(void);

/* Clear the abort flag.  Only meaningful for tests and for re-enabling
   downloads after an (unusual) in-process teardown that does not exit. */
void Downloader_AbortReset(void);

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

