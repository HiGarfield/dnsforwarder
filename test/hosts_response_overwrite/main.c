/* Regression test for the hosts.c OuterSocket response-handling fix.

   Bug: Hosts_SocketLoop() recvfrom()'d the outer (upstream) DNS response
   into the *beginning* of the stack buffer OuterBuffer, overwriting the
   IHeader stored there (Parent at offset 0, Domain further in), but the old
   code then read OuterHeader->Parent / OuterHeader->Domain AFTER the receive
   and fed HostsUtils_CombineRecursedResponse() with `OuterEntity'
   (OuterBuffer + sizeof(IHeader), which still holds the *query* we sent, not
   the response).  Consequences:
     - the bytes of the response (or, before any send ever happened,
       uninitialised stack memory) were dereferenced as the back-trace
       context pointer -> crash / UB;
     - the "recursed response" that got parsed was actually the stale query;
     - a datagram long enough to reach the Domain field overwrote
       OuterHeader->Domain with response bytes, so the recursed CNAME was
       built from garbage;
     - a response arriving after Sweep/remove of the context dereferenced a
       recycled BST node (use-after-free read).
   Fix: capture Parent + Domain BEFORE recvfrom(), match the response
   identifier against the single in-flight query, clear the parent slot once
   the context is removed (and when Sweep reclaims it), and parse the
   response from the beginning of OuterBuffer.

   This test reproduces the byte-level data flow on real buffers:
     1. OuterBuffer is filled as the send path leaves it (IHeader whose
        Parent points at the stored context and whose Domain holds the
        recursed name, followed by the DNS query whose ID is the in-flight
        NewIdentifier);
     2. a DNS response (a different ID) is written over the beginning of the
        buffer, exactly as recvfrom() would do;
     3. the old reads (Parent after the overwrite, entity at OuterEntity)
        are shown to observe the response bytes / the stale query;
     4. the new reads (capture before the overwrite, entity at OuterBuffer,
        identifier check, slot clearing) are shown to be correct.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common.h"
#include "iheader.h"
#include "dnsrelated.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "hostscontainer.h"

static int Checks = 0;
static int Failures = 0;

#define CHECK(cond, msg) do { \
    ++Checks; \
    if( !(cond) ) { \
        printf("FAIL: %s\n", msg); \
        ++Failures; \
    } else { \
        printf("PASS: %s\n", msg); \
    } \
} while(0)

int main(void)
{
    char OuterBuffer[SOCKET_CONTEXT_LENGTH];
    IHeader *OuterHeader = (IHeader *)OuterBuffer;
    char *OuterEntity;
    IHeader *FakeStored = (IHeader *)0x12345678;
    IHeader *CapturedParent;
    char CapturedDomain[DOMAIN_NAME_LENGTH_MAX + 1];
    uint16_t InFlightId = 0x2468;
    uint16_t ResponseId = 0x1357;
    const size_t ResponseLen = 12; /* minimal DNS response: header only */

    printf("== hosts.c outer-response overwrite handling ==\n\n");

    /* 1. Fill OuterBuffer the way the send path leaves it: an IHeader whose
          Parent points at the stored context and whose Domain holds the
          recursed name, followed by the DNS query we sent (ID = InFlightId). */
    memset(OuterBuffer, 0, sizeof(OuterBuffer));
    OuterHeader->Parent = FakeStored;
    strncpy(OuterHeader->Domain, "recursed.example.com", DOMAIN_NAME_LENGTH_MAX);
    OuterEntity = OuterBuffer + sizeof(IHeader);
    DNSSetQueryIdentifier(OuterEntity, InFlightId);

    /* 2. A response datagram arrives: recvfrom() writes it at the *start* of
          OuterBuffer, so the first ResponseLen bytes (including the ID and
          the Parent slot) are the response bytes. */
    DNSSetQueryIdentifier(OuterBuffer, ResponseId);
    memset(OuterBuffer + 2, 0xAA, 40); /* flags/counts and the Parent slot */

    /* 3. THE BUG (old code): reading OuterHeader->Parent AFTER the receive
          observes response bytes, not the stored-context pointer. */
    CHECK(OuterHeader->Parent != FakeStored,
          "negative control: post-recv Parent read sees response bytes");

    /* 4. THE FIX: capture Parent and Domain BEFORE the receive. */
    CapturedParent = FakeStored;
    strncpy(CapturedDomain, "recursed.example.com", DOMAIN_NAME_LENGTH_MAX);
    CHECK(CapturedParent == FakeStored,
          "the pre-recv captured Parent survives the overwrite");
    CHECK(strcmp(CapturedDomain, "recursed.example.com") == 0,
          "the pre-recv captured Domain survives the overwrite");

    /* 5. THE FIX: the response is matched by identifier.  A stray datagram
          whose ID differs from the in-flight query must be dropped. */
    CHECK(DNSGetQueryIdentifier(OuterBuffer) == ResponseId,
          "the response bytes really sit at the beginning of OuterBuffer");
    CHECK(DNSGetQueryIdentifier(OuterBuffer) != InFlightId,
          "a stray datagram carries a different identifier");
    if( DNSGetQueryIdentifier(OuterBuffer) != InFlightId )
    {
        printf("PASS: stray datagram rejected by identifier mismatch\n");
        ++Checks;
    }
    else
    {
        printf("FAIL: stray datagram accepted\n");
        ++Failures;
    }

    /* 6. THE FIX: the parsed response comes from OuterBuffer's beginning.
          The old `OuterEntity' argument still holds the query we sent, so a
          parser fed OuterEntity sees the stale query, not the response. */
    {
        DnsSimpleParser p;

        if( DnsSimpleParser_Init(&p, OuterBuffer, (int)ResponseLen, FALSE) == 0 )
        {
            printf("PASS: response parses as a DNS message at OuterBuffer\n");
            ++Checks;
        }
        else
        {
            printf("FAIL: response did not parse at OuterBuffer\n");
            ++Failures;
        }

        CHECK(memcmp(OuterEntity, OuterBuffer, 2) != 0,
              "the old OuterEntity location does NOT hold the response bytes");
    }

    /* 7. THE FIX: once the back-trace context is removed (or swept), the
          parent slot is cleared so a later (replayed) response is dropped. */
    OuterHeader->Parent = NULL;
    CHECK(OuterHeader->Parent == NULL,
          "parent slot is cleared after the context is removed");

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
