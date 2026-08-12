/*
 * Regression test for the wild pointer returned by CheckAList (goodiplist.c).
 *
 * CheckAList() attaches a payload to every probing socket and, once select()
 * reports the first writable one, dereferences the payload handed back by
 * SocketPuller_Select():
 *
 *     ret = *Fastest;   / * struct sockaddr_in ** -> struct sockaddr_in * * /
 *
 * SocketPuller_Add() *copies* DataLength bytes from the address it is given,
 * so the payload must be `&pointer_to_Ips_i', not `&Ips[i]'. The buggy code
 * passed &Ips[i], which copied the first 8 bytes of the sockaddr_in value
 * (sin_family, sin_port, sin_addr). `*Fastest' then reinterpreted those bytes
 * as a pointer, producing a fabricated address such as 0x7f000001c3500002.
 * ThreadJod() dereferences that pointer and even memcpy()s 16 bytes into it,
 * so the bug corrupts memory / crashes the TimedTask thread.
 *
 * The test drives the real (static) CheckAList by including goodiplist.c and
 * asserts that the returned pointer is really an element of the array that was
 * passed in.
 *
 * Build & run: sh test/goodiplist_fastest/run.sh
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../goodiplist.c"

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

/* Start listening on 127.0.0.1 with a kernel-chosen port and return it. */
static SOCKET Listen(uint16_t *PortOut)
{
    SOCKET  s;
    struct sockaddr_in  a;
    socklen_t   l = sizeof(a);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if( s == INVALID_SOCKET )
    {
        return INVALID_SOCKET;
    }

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = 0;

    if( bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(s, 8) != 0 ||
        getsockname(s, (struct sockaddr *)&a, &l) != 0 )
    {
        CLOSE_SOCKET(s);
        return INVALID_SOCKET;
    }

    *PortOut = a.sin_port;
    return s;
}

static void SetAddr(struct sockaddr_in *a, const char *Ip, uint16_t NetPort)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = inet_addr(Ip);
    a->sin_port = NetPort;
}

int main(void)
{
    struct sockaddr_in  Ips[3];
    struct sockaddr_in  *Fastest;
    SOCKET  Server;
    uint16_t    Port = 0;

    Server = Listen(&Port);
    if( Server == INVALID_SOCKET )
    {
        printf("  [SKIP] cannot listen on 127.0.0.1\n");
        return 0;
    }

    /* Ips[0] and Ips[2] are unreachable (TEST-NET-1, RFC 5737): the connect
       either fails at once (then the socket is skipped) or stays pending for
       much longer than the local one, so Ips[1] is the only possible answer. */
    SetAddr(&(Ips[0]), "192.0.2.1", htons(53));
    SetAddr(&(Ips[1]), "127.0.0.1", Port);
    SetAddr(&(Ips[2]), "192.0.2.2", htons(53));

    Fastest = CheckAList(Ips, 3);

    Check("CheckAList found a fastest address", Fastest != NULL);
    Check("returned pointer is an element of the input array",
          Fastest == &(Ips[0]) || Fastest == &(Ips[1]) || Fastest == &(Ips[2]));
    Check("returned pointer is the reachable address",
          Fastest == &(Ips[1]));

    /* A single-element list must return that very element. */
    SetAddr(&(Ips[0]), "127.0.0.1", Port);
    Fastest = CheckAList(Ips, 1);
    Check("single-element list returns &Ips[0]", Fastest == &(Ips[0]));

    CLOSE_SOCKET(Server);

    printf("\ngoodiplist_fastest: %d failures\n", Failures);
    return Failures == 0 ? 0 : 1;
}
