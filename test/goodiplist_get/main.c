/* Regression test for the GoodIpList_Get() out-of-lock pointer bug found in
   the Round-3 review.

   Bug: GoodIpList_Get() returned a pointer INTO ListInfo.List[0].sin_addr
   after releasing ListLock.  The measurement task (ThreadJod) rewrites that
   same array (moving the fastest IP to index 0 with memmove) while holding
   the lock, so the caller's unlocked read raced with the swap -- a data race
   and a potentially torn 4-byte address.

   Fix: the API now copies the 4 address bytes into a caller-provided buffer
   while the lock is still held; the caller (hostsutils.c) reads the copy.

   The static declarations of goodiplist.c are exposed (via the #define static
   trick) so the test can build the StringChunk state directly and drive
   GoodIpList_Get.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <arpa/inet.h>

/* Headers used by goodiplist.c -- included BEFORE the static-export trick so
   their own static declarations are left untouched. */
#include "common.h"
#include "readconfig.h"
#include "goodiplist.h"
#include "utils.h"
#include "timedtask.h"
#include "socketpuller.h"
#include "logs.h"
#include "ptimer.h"
#include "rwlock.h"

/* ---- minimal logging stubs (do NOT link test/stubs.c: it also defines
   GoodIpList_Get, which would collide with the real one here) ---- */
void Log_Print(const char *Type, const char *format, ...)
{
    (void)Type;
    (void)format;
}

BOOL Log_DebugOn(void)
{
    return FALSE;
}

/* ---- ConfigGetStringList: InitListsAndTimes/AddToLists are not called
   by this test, but the link step needs the symbol ---- */
StringList *ConfigGetStringList(ConfigFileInfo *Info, const char *KeyName)
{
    (void)Info; (void)KeyName;
    return NULL;
}

/* ---- TimedTask_Add: AddTask() is not called by this test, but the link
   step needs the symbol ---- */
int TimedTask_Add(BOOL Persistent,
                  BOOL Asynchronous,
                  int Milliseconds,
                  TaskFunc Func,
                  void *Arg1,
                  void *Arg2,
                  BOOL Immediate)
{
    (void)Persistent; (void)Asynchronous; (void)Milliseconds;
    (void)Func; (void)Arg1; (void)Arg2; (void)Immediate;
    return 0;
}

/* ---- expose the private declarations of goodiplist.c ------------------ */
#define static
#include "goodiplist.c"
#undef static

static int Checks = 0;
static int Failures = 0;

static void expect(const char *what, int cond)
{
    ++Checks;
    if( cond )
    {
        printf("  [ ok ] %s\n", what);
    } else {
        ++Failures;
        printf("  [FAIL] %s\n", what);
    }
}

static void BuildList(const char *Name, int IpCount, const char *ip0)
{
    ListInfo m;
    int i;

    memset(&m, 0, sizeof(m));
    m.List.DataLength = sizeof(struct sockaddr_in);
    m.List.Data = (char *)malloc(GOODIPLIST_MAX_IPS_PER_LIST *
                                 sizeof(struct sockaddr_in));
    m.List.Allocated = GOODIPLIST_MAX_IPS_PER_LIST;
    m.List.Used = 0;

    for( i = 0; i < IpCount; ++i )
    {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(53);
        if( i == 0 )
        {
            a.sin_addr.s_addr = inet_addr(ip0);
        } else {
            a.sin_addr.s_addr = htonl(0x0A000000u + (uint32_t)(i + 1));
        }
        Array_PushBack(&(m.List), &a, NULL);
    }

    StringChunk_Add(GoodIpList, Name, (const char *)&m, sizeof(ListInfo));
}

int main(void)
{
    char buf[16];

    printf("== GoodIpList_Get locked-copy regression tests ==\n\n");

    GoodIpList = (StringChunk *)malloc(sizeof(StringChunk));
    if( GoodIpList == NULL )
    {
        printf("out of memory\n");
        return 1;
    }
    expect("StringChunk_Init succeeds", StringChunk_Init(GoodIpList, NULL) == 0);
    RWLock_Init(ListLock);

    BuildList("list1", 2, "10.0.0.1");
    BuildList("empty", 0, "10.0.0.1");

    /* ---- a populated list returns the first element's address ---- */
    printf("Populated list\n");
    memset(buf, 0, sizeof(buf));
    expect("GoodIpList_Get('list1') succeeds", GoodIpList_Get("list1", buf) == 0);
    expect("... and copies exactly 10.0.0.1",
           memcmp(buf, "\x0a\x00\x00\x01", 4) == 0);

    /* ---- the result is a copy, not a pointer into the array ---- */
    printf("The result is a stable copy\n");
    {
        ListInfo *m = NULL;

        StringChunk_Match_NoWildCard(GoodIpList, "list1", NULL, (void **)&m, NULL, NULL);
        expect("the backing list is found", m != NULL && Array_GetUsed(&(m->List)) == 2);

        /* mutate the backing array directly (as ThreadJod would) */
        RWLock_WrLock(ListLock);
        ((struct sockaddr_in *)Array_GetBySubscript(&(m->List), 0))->sin_addr.s_addr =
            htonl(0x0B000001u);   /* 11.0.0.1 */
        RWLock_UnWLock(ListLock);

        expect("the earlier copy is unaffected by the array mutation",
               memcmp(buf, "\x0a\x00\x00\x01", 4) == 0);
    }

    /* ---- error paths ---- */
    printf("Error paths\n");
    expect("an empty list fails (-1)", GoodIpList_Get("empty", buf) == -1);
    expect("an unknown list fails (-1)", GoodIpList_Get("nosuch", buf) == -1);
    expect("a NULL output buffer fails (-1)", GoodIpList_Get("list1", NULL) == -1);
    expect("a NULL list name is handled (no crash)", GoodIpList_Get(NULL, buf) == -1);

    /* cleanup */
    GoodIpList_Cleanup();

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
