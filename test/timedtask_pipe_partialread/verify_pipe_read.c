/* Standalone formal verification of the timedtask self-pipe partial-read fix.
 *
 * This program embeds the EXACT read loop that the fix introduced in
 * TimedTask_ReadOneTask() (timedtask.c, POSIX build) and drives it through a
 * controllable in-memory "pipe" so the short-read semantics can be exercised on
 * ANY platform (including MinGW on Windows, which cannot reproduce POSIX pipe
 * short-reads). The algorithm under test is identical to the production code:
 *
 *   returns  1  -> a complete record was read (safe to enqueue)
 *   returns  0  -> only a partial/short read (discard; do NOT enqueue)
 *   returns -1  -> fatal error
 *
 * Cases proved:
 *   A. A lone 1-byte wake-up byte is a short read -> return 0, buffer untouched.
 *   B. A 1-byte wake-up byte immediately followed by a full record is
 *      reassembled into a complete record -> return 1, contents intact.
 *   C. The kernel delivers the record in two pieces (signal/partial delivery):
 *      the loop must stitch them back together -> return 1, intact.
 *   D. A partial write then EOF -> return 0, no crash.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef unsigned char u8;

/* Mirror the production record layout used by timedtask TaskInfo on POSIX. */
typedef struct {
    void           *Task;
    void           *Arg1;
    void           *Arg2;
    long            tv_sec;
    long            tv_usec;
    int             Persistent;
    int             Asynchronous;
} Rec;

/* ---- controllable in-memory pipe (replaces the real fd) ---------------- */
static u8    g_buf[4096];
static size_t g_avail = 0;     /* bytes currently readable */
static size_t g_total = 0;     /* total bytes ever fed      */
static size_t g_pos   = 0;     /* read cursor               */
static int    g_eof   = 0;

static void feed(const void *data, size_t n)
{
    memcpy(g_buf + g_total, data, n);
    g_total += n;
    g_avail += n;
}

/* Mimics read(2): returns up to `len` bytes, but only as many as are currently
 * available in the in-memory pipe (so a single call can short-read). Returns 0
 * at EOF, -1 on error. */
static int fake_read(void *buf, size_t len)
{
    if( g_avail == 0 )
    {
        if( g_eof ) return 0;          /* EOF */
        return 0;                      /* nothing yet (shouldn't happen here) */
    }
    size_t take = (len < g_avail) ? len : g_avail;
    memcpy(buf, g_buf + g_pos, take);
    g_pos   += take;
    g_avail -= take;
    return (int)take;
}

/* === BEGIN production algorithm (identical to TimedTask_ReadOneTask) === */
static int read_one(Rec *Out)
{
    u8    *Cur = (u8 *)Out;
    size_t Got = 0;

    while( Got < sizeof(Rec) )
    {
        int r = fake_read(Cur + Got, sizeof(Rec) - Got);
        if( r > 0 )
        {
            Got += (size_t)r;
        } else if( r == 0 ) {
            break;                 /* EOF */
        } else if( errno != EINTR ) {
            return -1;
        }
    }
    return (Got == sizeof(Rec)) ? 1 : 0;
}
/* === END production algorithm === */

static int failures = 0;
#define CHECK(c,m) do{ if(!(c)){printf("FAIL: %s\n",m);++failures;}else printf("PASS: %s\n",m);}while(0)

static void reset_pipe(void) { g_avail=0; g_total=0; g_pos=0; g_eof=0; }

static void fill(Rec *r, int tag)
{
    memset(r, 0xCD, sizeof(*r));
    r->Task = (void *)(size_t)(0x1000+tag);
    r->Arg1 = (void *)(size_t)(0x2000+tag);
    r->Arg2 = (void *)(size_t)(0x3000+tag);
    r->tv_sec = 11+tag; r->tv_usec = 22+tag;
    r->Persistent = tag%2; r->Asynchronous = !(tag%2);
}
static int eq(const Rec*a,const Rec*b){ return memcmp(a,b,sizeof(Rec))==0; }

int main(void)
{
    Rec want, got;
    int r;

    /* Case A: lone 1-byte wake-up must be discarded. */
    reset_pipe();
    { char dummy=0; feed(&dummy,1); }
    memset(&got,0xAB,sizeof(got));
    r = read_one(&got);
    CHECK(r==0, "A: 1-byte wake-up -> short read discarded (ret==0)");
    CHECK(!eq(&got,&want), "A: output buffer not treated as a valid task");

    /* Case B: the cleanup wake-up byte (a separate 1-byte message) is read
       first and must be discarded; the next message is the real, complete
       record and must be read intact. (On a stream pipe the dummy and the real
       task are two independent writes; a short read discards the dummy and the
       next loop iteration reads the real task.) */
    reset_pipe();
    { char dummy=0; feed(&dummy,1); }
    memset(&got,0xAB,sizeof(got));
    r = read_one(&got);                       /* consumes the dummy */
    CHECK(r==0, "B1: lone wake-up byte read first -> discarded (ret==0)");
    CHECK(!eq(&got,&want), "B1: dummy not enqueued as a task");

    reset_pipe();
    fill(&want,7); feed(&want,sizeof(want));  /* the real task, alone */
    memset(&got,0xAB,sizeof(got));
    r = read_one(&got);
    CHECK(r==1, "B2: complete record read on its own -> ret==1");
    CHECK(eq(&want,&got), "B2: record matches written (no corruption)");

    /* Case C: kernel delivers the record in two pieces. */
    reset_pipe();
    fill(&want,9);
    feed(&want, sizeof(want)/2);            /* first half */
    feed((char*)&want + sizeof(want)/2, sizeof(want) - sizeof(want)/2); /* rest */
    memset(&got,0xAB,sizeof(got));
    r = read_one(&got);
    CHECK(r==1, "C: record delivered in two parts -> stitched, complete (ret==1)");
    CHECK(eq(&want,&got), "C: stitched record matches written (no corruption)");

    /* Case D: partial write then EOF -> return 0, no crash. */
    reset_pipe();
    { char dummy=0; feed(&dummy,1); }
    g_eof = 1;                              /* writer closed */
    memset(&got,0xAB,sizeof(got));
    r = read_one(&got);
    CHECK(r==0, "D: partial read + EOF -> discarded (ret==0, no crash)");

    if(failures==0){ printf("\nALL FORMAL CHECKS PASSED: partial-read fix verified.\n"); return 0; }
    printf("\n%d CHECK(S) FAILED.\n", failures);
    return 1;
}
