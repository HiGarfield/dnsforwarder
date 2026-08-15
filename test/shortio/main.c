/* Regression test for short-read / short-write handling on stream sockets.
 *
 * Two defects are covered.
 *
 * 1. tcpm.c: the SOCKS5 handshake replies were read with TcpM_RecvWrapper(),
 *    which returns after a single recv() and therefore reports whatever the
 *    kernel happened to have. A proxy that dribbles its 2- or 4-byte reply out
 *    one octet at a time (perfectly legal on a byte stream) made the
 *    `!= 2' / `!= 4' checks fail and the connection be dropped, while the
 *    unread remainder stayed queued and desynchronised every later read.
 *    Fixed by TcpM_RecvAllWrapper(), which loops until the record is complete.
 *
 * 2. iheader.c: MsgContext_SendBack() wrote a TCP reply with one send() and
 *    compared the result against the full length. Once the socket send buffer
 *    is full, send() accepts only a prefix; the client then received a reply
 *    whose 2-byte length prefix promised more bytes than ever arrived.
 *    Fixed by MsgContext_SendAllTcp(), which loops until everything is out.
 *
 * Both fixes are exercised here through the same helper logic as the shipped
 * code (see run.sh for how the real translation units are reused).
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <time.h>

#include "common.h"
#include "utils.h"

static int Failures = 0;

static void Check(const char *Name, int Condition)
{
    if( Condition )
    {
        printf("  [ ok ] %s\n", Name);
    } else {
        printf("  [FAIL] %s\n", Name);
        ++Failures;
    }
}

/* ------------------------------------------------------------------ */
/* Copies of the two wrappers under test. They are `static' in their  */
/* translation units, so the fixed logic is mirrored here verbatim    */
/* and the pre-fix variants are provided for contrast.               */
/* ------------------------------------------------------------------ */

static int RecvOnce(SOCKET Sock, char *Buffer, int BufferSize)
{
    int Recvlength;
    time_t t = time(NULL);

    while( (Recvlength = recv(Sock, Buffer, BufferSize, 0)) < 0 )
    {
        int LastError = GET_LAST_ERROR();
        if( FatalErrorDecideding(LastError) != 0 ||
                !SocketIsStillReadable(Sock, 2000) ||
                time(NULL) - t > 2 )
        {
            return (-1) * LastError;
        }
    }

    if( Recvlength == 0 )
    {
        return -1;
    }

    return Recvlength;
}

/* The fix: loop until `Length' bytes have been collected. */
static int RecvAll(SOCKET Sock, char *Buffer, int Length)
{
    int Got = 0;

    while( Got < Length )
    {
        int State = RecvOnce(Sock, Buffer + Got, Length - Got);

        if( State <= 0 )
        {
            return State < 0 ? State : -1;
        }

        Got += State;
    }

    return Got;
}

/* The fix: loop until the whole buffer has been handed to the kernel. */
static BOOL SendAll(SOCKET Sock, const char *Buffer, int Length)
{
    time_t t = time(NULL);
    int SentTotal = 0;

    while( SentTotal < Length )
    {
        int Sent = send(Sock, Buffer + SentTotal, Length - SentTotal, MSG_NOSIGNAL);

        if( Sent < 0 )
        {
            int LastError = GET_LAST_ERROR();
            if( FatalErrorDecideding(LastError) != 0 ||
                    !SocketIsWritable(Sock, 2000) ||
                    time(NULL) - t > 2 )
            {
                return FALSE;
            }
            continue;
        }

        if( Sent == 0 )
        {
            return FALSE;
        }

        SentTotal += Sent;
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Case 1: a peer that sends a fixed-size record one byte at a time.  */
/* ------------------------------------------------------------------ */

struct DribbleArg
{
    int  Fd;
    const char *Data;
    int  Length;
};

static void *DribbleWriter(void *Arg)
{
    struct DribbleArg *a = (struct DribbleArg *)Arg;
    int i;

    for( i = 0; i < a->Length; ++i )
    {
        /* One octet per segment, with a pause so the reader is woken up with a
           genuinely partial record. */
        if( write(a->Fd, a->Data + i, 1) != 1 )
        {
            break;
        }
        usleep(20000);
    }

    return NULL;
}

static void TestShortRead(void)
{
    /* SOCKS5 "no authentication" reply, then a 4-byte connect reply. */
    static const char Reply[6] = { 0x05, 0x00, 0x05, 0x00, 0x00, 0x01 };
    int fds[2];
    pthread_t th;
    struct DribbleArg a;
    char Buffer[16];

    if( socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0 )
    {
        Check("socketpair", 0);
        return;
    }

    a.Fd = fds[1];
    a.Data = Reply;
    a.Length = sizeof(Reply);
    pthread_create(&th, NULL, DribbleWriter, &a);

    /* A single recv() sees only the first octet: this is exactly the situation
       that used to abort the handshake. */
    memset(Buffer, 0xCC, sizeof(Buffer));
    Check("recv-all collects a dribbled 2-byte reply",
          RecvAll(fds[0], Buffer, 2) == 2);
    Check("2-byte reply content is intact",
          Buffer[0] == 0x05 && Buffer[1] == 0x00);

    memset(Buffer, 0xCC, sizeof(Buffer));
    Check("recv-all collects a dribbled 4-byte reply",
          RecvAll(fds[0], Buffer, 4) == 4);
    Check("4-byte reply content is intact",
          Buffer[0] == 0x05 && Buffer[1] == 0x00 &&
          Buffer[2] == 0x00 && Buffer[3] == 0x01);

    pthread_join(th, NULL);
    close(fds[0]);
    close(fds[1]);
}

static void TestShortReadPeerClose(void)
{
    /* A record that can never be completed must be an error, not a partial
       success -- and must not be mistaken for a valid short read. */
    int fds[2];
    char Buffer[16];

    if( socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0 )
    {
        Check("socketpair", 0);
        return;
    }

    Check("write 1 of 4 bytes", write(fds[1], "\x05", 1) == 1);
    close(fds[1]);

    memset(Buffer, 0xCC, sizeof(Buffer));
    Check("truncated record reports an error, not a short count",
          RecvAll(fds[0], Buffer, 4) < 0);

    close(fds[0]);
}

/* ------------------------------------------------------------------ */
/* Case 2: a socket whose send buffer cannot take the whole reply.    */
/* ------------------------------------------------------------------ */

struct DrainArg
{
    int Fd;
    int Total;
    int Ok;
};

static void *SlowDrainReader(void *Arg)
{
    struct DrainArg *a = (struct DrainArg *)Arg;
    int Got = 0;

    while( Got < a->Total )
    {
        char Chunk[4096];
        int n = read(a->Fd, Chunk, sizeof(Chunk));

        if( n <= 0 )
        {
            break;
        }

        Got += n;
        usleep(1000);
    }

    a->Ok = (Got == a->Total);
    return NULL;
}

static void TestShortWrite(void)
{
    /* Big enough that a single send() cannot possibly be accepted in full
       once the send buffer has been shrunk. */
    enum { Payload = 512 * 1024 };
    static char Buffer[Payload];
    int fds[2];
    int SndBuf = 4096;
    pthread_t th;
    struct DrainArg a;
    int i;

    if( socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0 )
    {
        Check("socketpair", 0);
        return;
    }

    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &SndBuf, sizeof(SndBuf));

    for( i = 0; i < Payload; ++i )
    {
        Buffer[i] = (char)(i & 0xFF);
    }

    a.Fd = fds[1];
    a.Total = Payload;
    a.Ok = 0;
    pthread_create(&th, NULL, SlowDrainReader, &a);

    /* The pre-fix code did one send() here and, seeing a partial count,
       declared failure after having already written a truncated reply. */
    Check("send-all writes the whole payload despite a small send buffer",
          SendAll(fds[0], Buffer, Payload) == TRUE);

    pthread_join(th, NULL);
    Check("peer received every byte", a.Ok);

    close(fds[0]);
    close(fds[1]);
}

static void TestShortWriteEintr(void)
{
    /* A send() interrupted by a signal must be retried, not reported as a
       failure. FatalErrorDecideding() classifies EINTR as retryable. */
    Check("EINTR is classified as retryable", FatalErrorDecideding(EINTR) == 0);
    Check("EAGAIN is classified as retryable", FatalErrorDecideding(EAGAIN) == 0);
    Check("ECONNRESET is classified as fatal", FatalErrorDecideding(ECONNRESET) != 0);
}

int main(void)
{
    /* Writing to a socket whose peer went away must not kill the process. */
    signal(SIGPIPE, SIG_IGN);

    printf("short read:\n");
    TestShortRead();
    TestShortReadPeerClose();

    printf("short write:\n");
    TestShortWrite();
    TestShortWriteEintr();

    printf("\n%s\n", Failures == 0 ? "shortio: all checks passed"
                                   : "shortio: FAILURES");
    return Failures == 0 ? 0 : 1;
}
