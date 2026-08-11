#include <string.h>
#include <limits.h>
#include "readconfig.h"
#include "goodiplist.h"
#include "utils.h"
#include "timedtask.h"
#include "socketpuller.h"
#include "logs.h"
#include "ptimer.h"
#include "rwlock.h"

#define GOODIPLIST_MAX_IPS_PER_LIST 64

typedef struct _ListInfo{
    int     Interval;
    Array   List;
    /* Backing store for List. The buffer is heap-allocated (see
       InitListsAndTimes) so that when this ListInfo is byte-copied into the
       StringChunk, List.Data keeps pointing at valid memory instead of the
       (now out-of-scope) stack buffer it was built on. A plain in-struct
       buffer would leave a dangling pointer after the copy. */
    char    Buffer[GOODIPLIST_MAX_IPS_PER_LIST * sizeof(struct sockaddr_in)];
} ListInfo;

static StringChunk  *GoodIpList = NULL;

/* Guards concurrent access to every ListInfo.List array. The list-measurement
   task (ThreadJod, run on the TimedTask thread) rewrites inf->List while a
   request-handling thread may call GoodIpList_Get() to read the same list.
   Without this lock the two threads race on the array contents (data race,
   detectable by helgrind). A single module-level lock is fine: the number of
   good-IP lists is small and access is read-mostly. */
static RWLock   ListLock;

/* The fastest returned */
static struct sockaddr_in *CheckAList(struct sockaddr_in *Ips, int Count)
{
    SocketPuller    p;
    int i;
    struct timeval  Time    =   {5, 0};
    struct sockaddr_in **Fastest = NULL;

    struct sockaddr_in *ret = NULL;

    if( SocketPuller_Init(&p, sizeof(struct sockaddr *)) != 0 )
    {
        return NULL;
    }

    for( i = 0; i != Count; ++i )
    {
        SOCKET  skt;
        struct sockaddr *a;

        skt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if( skt == INVALID_SOCKET )
        {
            continue;
        }

        if( SetSocketNonBlock(skt, TRUE) != 0 )
        {
            CLOSE_SOCKET(skt);
            continue;
        }

        a = (struct sockaddr *)&(Ips[i]);

        if( connect(skt, a, sizeof(struct sockaddr_in)) != 0 &&
            FatalErrorDecideding(GET_LAST_ERROR()) != 0
            )
        {
            CLOSE_SOCKET(skt);
            continue;
        }

        /* Store the address of the actual array element Ips[i], NOT &a.
           `a` is a single local pointer variable reused every iteration, so
           storing &a would make every SocketUnit alias the same local; after
           the loop it holds &Ips[Count-1], causing Select() to always report
           the last element as "fastest" regardless of which socket was ready
           and breaking the fastest-IP rebalancing in ThreadJod. */
        p.Add(&p, skt, &(Ips[i]), sizeof(struct sockaddr *));
    }

    if( p.Select(&p, &Time, (void **)&Fastest, FALSE, TRUE, NULL) == INVALID_SOCKET )
    {
        ret = NULL;
    }

    if( Fastest == NULL )
    {
        ret = NULL;
    } else {
        ret = *Fastest;
    }

    p.Free(&p);

    return ret;
}

static int ThreadJod(const char *Domain, ListInfo *inf)
{
    struct sockaddr_in *Fastest;
    PTimer  tm;
    int     Ret = 0;

    if( inf == NULL )
    {
        return -159;
    }

    /* Serialize with GoodIpList_Get() which may read inf->List concurrently
       from a request-handling thread. */
    RWLock_WrLock(ListLock);

    PTimer_Start(&tm);
    Fastest = CheckAList((struct sockaddr_in *)Array_GetRawArray(&(inf->List)),
                         Array_GetUsed(&(inf->List))
                         );

    if( Fastest != NULL )
    {
        struct sockaddr_in *First;
        struct sockaddr_in t;

        INFO("The fastest ip for `%s' is %s: %lums.\n",
             Domain,
             inet_ntoa(Fastest->sin_addr),
             PTimer_End(&tm)
             );

        First = Array_GetBySubscript(&(inf->List), 0);
        if( First == NULL )
        {
            Ret = -178;
            goto FINISH;
        }

        memcpy(&t, Fastest, sizeof(struct sockaddr_in));
        memcpy(Fastest, First, sizeof(struct sockaddr_in));
        memcpy(First, &t, sizeof(struct sockaddr_in));
    } else {
        INFO("Checking list `%s' timeout.\n", Domain);
    }

    Ret = 0;

FINISH:
    RWLock_UnWLock(ListLock);
    return Ret;
}

/* GoodIPList list1 1000 */
static int InitListsAndTimes(ConfigFileInfo *ConfigInfo)
{
    StringList  *l  =   ConfigGetStringList(ConfigInfo, "GoodIPList");
    StringListIterator  sli;

    const char  *Itr    =   NULL;

    if( l == NULL )
    {
        return -1;
    }

    if( StringListIterator_Init(&sli, l) != 0 )
    {
        return -2;
    }

    GoodIpList = SafeMalloc(sizeof(StringChunk));
    if( GoodIpList == NULL )
    {
        return -3;
    }
    if( StringChunk_Init(GoodIpList, NULL) != 0 )
    {
        SafeFree(GoodIpList);
        return -3;
    }

    while( (Itr = sli.Next(&sli)) != NULL )
    {
        ListInfo    m;
        char n[128];

        memset(&m, 0, sizeof(m));
        /* Point the Array at a heap buffer (NOT the in-structure Buffer). The
           whole ListInfo is byte-copied into the StringChunk, and memcpy does
           not relocate internal pointers: had we used m.Buffer (stack memory),
           the copy's List.Data would keep pointing at the soon-to-be-freed
           stack slot, turning every later GoodIpList_Get into a use-after-scope
           read. A heap pointer stays valid for the whole process lifetime. */
        m.List.DataLength = sizeof(struct sockaddr_in);
        /* Allocate a contiguous array of sockaddr_in, kept as a char* byte
           buffer (Array.Data is char*).  Receive the malloc result in a
           sockaddr_in* first so the allocation size matches the pointer type
           and static analysers (clang unix.MallocSizeof) stay quiet. */
        struct sockaddr_in *ipbuf =
            SafeMalloc(GOODIPLIST_MAX_IPS_PER_LIST * sizeof(struct sockaddr_in));
        if( ipbuf == NULL )
        {
            ERRORMSG("GoodIpList out of memory : %s\n", Itr);
            continue;
        }
        m.List.Data = (char *)ipbuf;
        m.List.Allocated = GOODIPLIST_MAX_IPS_PER_LIST;
        m.List.Used = 0;

        sscanf(Itr, "%127s%d", n, &(m.Interval));

        if( m.Interval <= 0 )
        {
            ERRORMSG("GoodIpList is invalid : %s\n", Itr);
            SafeFree(m.List.Data);
            continue;
        }

        StringChunk_Add(GoodIpList, n, (const char *)&m, sizeof(ListInfo));
    }

    INFO("Loading GoodIPList completed.\n");

    return 0;
}

/* GoodIPListAddIP list1 ip:port */
static int AddToLists(ConfigFileInfo *ConfigInfo)
{
    StringList  *l  =   ConfigGetStringList(ConfigInfo, "GoodIPListAddIP");
    StringListIterator  sli;

    const char  *Itr    =   NULL;

    if( l == NULL )
    {
        return -1;
    }

    if( StringListIterator_Init(&sli, l) != 0 )
    {
        return -2;
    }

    while( (Itr = sli.Next(&sli)) != NULL )
    {
        ListInfo    *m = NULL;
        char n[128], ip_str[LENGTH_OF_IPV4_ADDRESS_ASCII];
        int Port = 0;
        struct sockaddr_in  ip;

        memset(&ip, 0, sizeof(ip));

        /* Validate the format. A missing ":port" leaves Port uninitialized
         * and an unchecked sscanf does not zero it, yielding a random port. */
        if( sscanf(Itr, "%127s%*[^0123456789]%15[^:]:%d", n, ip_str, &Port) < 3 )
        {
            ERRORMSG("Invalid GoodIPListAddIP (expected 'list ip:port'): %s\n", Itr);
            continue;
        }

        ip.sin_port = htons(Port);
        ip.sin_family = AF_INET; /* IPv4 only */

        IPv4AddressToNum(ip_str, &(ip.sin_addr));

        if( StringChunk_Match_NoWildCard(GoodIpList,
                                         n,
                                         NULL,
                                         (void **)&m,
                                         NULL,
                                         NULL
                                         )
            == FALSE
            )
        {
            ERRORMSG("GoodIpList is not found : %s\n", Itr);
            continue;
        }

        if( Array_GetUsed(&(m->List)) >= GOODIPLIST_MAX_IPS_PER_LIST )
        {
            ERRORMSG("GoodIpList `%s' is full, ignoring `%s'\n", n, Itr);
            continue;
        }
        Array_PushBack(&(m->List), &ip, NULL);
    }

    INFO("Loading GoodIPListAddIP completed.\n");

    return 0;
}

static int AddTask(void)
{
    ListInfo *m;
    const char *Domain;

    int32_t Start = 0;

    Domain = StringChunk_Enum_NoWildCard(GoodIpList, &Start, (void **)&m);
    while( Domain != NULL )
    {
        if( m != NULL )
        {
            TimedTask_Add(TRUE,
                          FALSE,
                          m->Interval,
                          (TaskFunc)ThreadJod,
                          (void *)Domain,
                          (void *)m,
                          TRUE
                          );
        }

        Domain = StringChunk_Enum_NoWildCard(GoodIpList, &Start, (void **)&m);
    }

    return 0;
}

static void GoodIpList_Cleanup(void)
{
    if(GoodIpList != NULL)
    {
        RWLock_Destroy(ListLock);
        StringChunk_Free(GoodIpList, TRUE);
        SafeFree(GoodIpList);
    }
}

int GoodIpList_Init(ConfigFileInfo *ConfigInfo)
{
    RWLock_Init(ListLock);
    atexit(GoodIpList_Cleanup);

    /* The list-measurement task (ThreadJod) is started by AddTask() below and
       may begin running (it reads each ListInfo.List) before this function
       returns. Initialise the lists under the same write lock that ThreadJod
       takes, so its first read cannot race with these writes. */
    RWLock_WrLock(ListLock);
    if( InitListsAndTimes(ConfigInfo) != 0 )
    {
        RWLock_UnWLock(ListLock);
        return -1;
    }

    if( AddToLists(ConfigInfo) != 0 )
    {
        RWLock_UnWLock(ListLock);
        return -2;
    }
    RWLock_UnWLock(ListLock);

    AddTask();

    return 0;
}

const char *GoodIpList_Get(const char *List)
{
    ListInfo   *m = NULL;
    const char *Ret = NULL;

    RWLock_RdLock(ListLock);
    if( StringChunk_Match_NoWildCard(GoodIpList,
                                     List,
                                     NULL,
                                     (void **)&m,
                                     NULL,
                                     NULL
                                     )
       == TRUE &&
       m != NULL
       )
    {
        if( Array_GetUsed(&(m->List)) <= 0 )
        {
            Ret = NULL;
        } else {
            Ret = (const char *)&(((const struct sockaddr_in *)Array_GetBySubscript(&(m->List), 0))->sin_addr);
        }
    } else {
        Ret = NULL;
    }
    RWLock_UnRLock(ListLock);

    return Ret;
}
