/* Regression test for the shutdown race in ipmisc.c's atexit cleanup.

   Bug: atexit LIFO order runs IpMiscMapping_Cleanup() BEFORE
   Modules_Cleanup() stops the module worker threads (udpm.c / tcpm.c call
   IPMiscMapping_Process() on every request).  The old cleanup freed
   CurrIpMiscMapping WITHOUT taking IpMiscMappingLock and WITHOUT NULLing the
   pointer, then destroyed the lock, so a module worker that acquired the
   read lock afterwards could dereference the freed mapping (use-after-free)
   or lock a destroyed rwlock.

   Fix: IpMiscMapping_Cleanup() takes the write lock, frees the mapping and
   NULLs the pointer (any reader that follows sees NULL and returns
   IP_MISC_NOTHING); the lock itself is deliberately NOT destroyed -- it is
   reclaimed by the OS at process exit (same convention as dnscache.c /
   dynamichosts.c / domainstatistic.c).

   Part 1 (runtime): a worker thread keeps calling the real
   IPMiscMapping_Process() on a DNS answer that contains a blocked 1.2.3.4
   A record while IpMiscMapping_Cleanup() runs; the worker then performs one
   more call.  With the old cleanup that final call dereferences the freed
   mapping (ASan: heap-use-after-free) or locks a destroyed rwlock; with the
   fix the worker gets IP_MISC_NOTHING because the pointer was NULLed under
   the lock.

   Part 2 (structural, in run.sh): scan IpMiscMapping_Cleanup for the
   absence of RWLock_Destroy / lock-free frees and the presence of the write
   lock + NULL + shutdown-race rationale comment.
*/
#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ipmisc.c's headers -- included BEFORE the static-export trick so their
   own static declarations are left untouched. */
#include "common.h"
#include "ipmisc.h"
#include "utils.h"
#include "readline.h"
#include "logs.h"
#include "rwlock.h"
#include "stringlist.h"

/* Stubs for ConfigGet* / Log_* live in run.sh-generated conf_stub.c and
   logs_stub.c. */

/* ---- expose ipmisc.c statics ---- */
#define static
#include "ipmisc.c"
#undef static

/* ---- test harness ---- */

/* A fake MsgContext: IHeader immediately followed by the DNS entity, exactly
   like struct _MsgContext in iheader.h, so IHEADER_TAIL() lands on pkg. */
typedef struct {
    IHeader h;
    char    pkg[64];
} LocalCtx;

static LocalCtx Ctx;

static volatile int Stage = 0; /* 0 = starting, 1 = pre-cleanup done,
                                  2 = cleanup ran, 3 = post-cleanup done */
static volatile int CleanupSawNothing = 0;

static void Msleep(int ms)
{
    struct timespec Ts;

    Ts.tv_sec = ms / 1000;
    Ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while( nanosleep(&Ts, &Ts) != 0 )
    {
    }
}

/* A well-formed DNS response: question "a" IN A, one answer record with
   RDATA 1.2.3.4 (a name-compression pointer to offset 12). */
static void InitPacket(LocalCtx *lc)
{
    char *p = lc->pkg;

    memset(&lc->h, 0, sizeof(lc->h));
    p[0]=0x12; p[1]=0x34;           /* ID */
    p[2]=0x81; p[3]=0x80;           /* flags: response, RD, RA */
    p[4]=0x00; p[5]=0x01;           /* QDCOUNT */
    p[6]=0x00; p[7]=0x01;           /* ANCOUNT */
    p[8]=0x00; p[9]=0x00;           /* NSCOUNT */
    p[10]=0x00; p[11]=0x00;         /* ARCOUNT */
    p[12]=0x01; p[13]='a'; p[14]=0x00;  /* QNAME "a" */
    p[15]=0x00; p[16]=0x01;         /* QTYPE A */
    p[17]=0x00; p[18]=0x01;         /* QCLASS IN */
    p[19]=0xc0; p[20]=0x0c;         /* NAME: pointer to offset 12 */
    p[21]=0x00; p[22]=0x01;         /* TYPE A */
    p[23]=0x00; p[24]=0x01;         /* CLASS IN */
    p[25]=0x00; p[26]=0x00; p[27]=0x00; p[28]=0x3c; /* TTL */
    p[29]=0x00; p[30]=0x04;         /* RDLENGTH 4 */
    p[31]=1; p[32]=2; p[33]=3; p[34]=4;  /* 1.2.3.4 */
    lc->h.EntityLength = 35;
}

static void *MappingUser(void *Unused)
{
    int i, Ret;

    (void)Unused;

    /* Hammer the exact production access pattern: IPMiscMapping_Process()
       takes the read lock, dereferences CurrIpMiscMapping and calls
       ->Process. */
    for( i = 0; i < 50; ++i )
    {
        Ret = IPMiscMapping_Process((MsgContext *)&Ctx);
        if( Ret != IP_MISC_FILTERED_IP )
        {
            printf("FAIL: pre-cleanup Process returned %d (expected %d)\n",
                   Ret, IP_MISC_FILTERED_IP);
            exit(2);
        }
    }
    Stage = 1;

    /* Wait for the main thread to run IpMiscMapping_Cleanup(). */
    while( Stage != 2 )
    {
        Msleep(1);
    }

    /* One more call after cleanup: with the old cleanup this dereferences
       the freed mapping (IpMiscMapping_Cleanup freed it without the lock and
       without NULLing) or locks a destroyed rwlock; with the fix the pointer
       was NULLed under the write lock, so Process() returns IP_MISC_NOTHING. */
    Ret = IPMiscMapping_Process((MsgContext *)&Ctx);
    if( Ret == IP_MISC_NOTHING )
    {
        CleanupSawNothing = 1;
    }
    Stage = 3;
    return NULL;
}

int main(void)
{
    pthread_t Tid;
    IPMisc *m;
    int i;

    printf("== ipmisc shutdown cleanup race test ==\n\n");

    RWLock_Init(IpMiscMappingLock);

    /* Simulate a loaded IP mapping: block 1.2.3.4.  This must happen before
       the sanity check below, which exercises the real IPMiscMapping_Process
       path on the live mapping. */
    m = SafeMalloc(sizeof(IPMisc));
    if( m == NULL || IPMisc_Init(m) != 0 )
    {
        printf("FAIL: IPMisc_Init\n");
        return 2;
    }
    if( m->AddBlockFromString(m, "1.2.3.4") != 0 )
    {
        printf("FAIL: AddBlockFromString\n");
        return 2;
    }
    CurrIpMiscMapping = m;

    /* Sanity check the packet is recognised before we start the worker. */
    InitPacket(&Ctx);
    if( IPMiscMapping_Process((MsgContext *)&Ctx) != IP_MISC_FILTERED_IP )
    {
        printf("FAIL: test packet not recognised as a blocked IP\n");
        return 2;
    }
    printf("PASS: test packet is recognised as a blocked IP\n");

    if( pthread_create(&Tid, NULL, MappingUser, NULL) != 0 )
    {
        printf("FAIL: pthread_create\n");
        return 2;
    }

    for( i = 0; i < 5000 && Stage != 1; ++i )
    {
        Msleep(1);
    }
    if( Stage != 1 )
    {
        printf("FAIL: worker never reached the pre-cleanup phase\n");
        return 1;
    }
    printf("PASS: worker hammering the mapping before cleanup\n");

    /* Run the atexit body while the worker thread is still live. */
    IpMiscMapping_Cleanup();

    Stage = 2;
    for( i = 0; i < 5000 && Stage != 3; ++i )
    {
        Msleep(1);
    }
    if( Stage != 3 )
    {
        printf("FAIL: worker never finished the post-cleanup call\n");
        return 1;
    }
    pthread_join(Tid, NULL);

    /* The worker must have observed the NULLed pointer. */
    if( !CleanupSawNothing )
    {
        printf("FAIL: worker did not observe IP_MISC_NOTHING after cleanup\n");
        return 1;
    }
    printf("PASS: worker observed IP_MISC_NOTHING after cleanup\n");

    /* The lock must still be usable (a destroyed rwlock would corrupt it). */
    RWLock_RdLock(IpMiscMappingLock);
    RWLock_UnRLock(IpMiscMappingLock);
    printf("PASS: IpMiscMappingLock is still usable after cleanup\n");

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
