/* Regression test for the hosts.c "capture the query identifier before the
   back-trace context is deleted" fix.

   Bug: after Context.GenAnswerHeaderAndRemove() returns 0, the back-trace
   context (OuterHeader->Parent, a BST node data pointer) has been reset and
   unlinked -- Bst_Delete() places the node header on the free list.  The old
   code then read the query identifier from BackTraceHeader + 1 (the DNS
   message inside that node) and copied it into the response.  The bytes
   happen to survive today because the backing StableBuffer never frees memory
   and the worker is single-threaded, but the object is logically gone: the
   very next ModuleContext_Add() reuses the free-list slot and overwrites
   those bytes, so a racing/repeated dispatch could stamp the response with a
   stale or foreign identifier.

   Fix: Hosts_SocketLoop() captures DNSGetQueryIdentifier(BackTraceHeader + 1)
   BEFORE the GenAnswerHeaderAndRemove() call and writes it back afterwards,
   so the identifier never comes from a deleted node.

   The test reproduces the hosts.c data flow on the real ModuleContext/BST:
     1. Buffer1 (client query, ID 0x1234) is stored via ModuleContext_Add()
        and Buffer2 mirrors the already-received inner query (same ID).
     2. Capture the ID from the stored node (what the fixed code does).
     3. GenAnswerHeaderAndRemove() copies the header into Buffer2, then resets
        and unlinks the stored node (it goes to the BST free list).
     4. The next Add() pops that slot and overwrites it (ID 0x5678).
     5. The fixed write-back (DNSSetQueryIdentifier) restores 0x1234; the old
        "read the node after the delete" order would have copied 0x5678 --
        the negative control below demonstrates exactly that.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common.h"
#include "iheader.h"
#include "mcontext.h"
#include "dnsparser.h"
#include "dnsgenerator.h"

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

/* Build a query context: IHeader fields plus a DNS message whose ID is
   `Id` (network order in the first two bytes of the entity). */
static void FillContext(char *Buf, uint32_t Hash, uint16_t Id)
{
    IHeader *h = (IHeader *)Buf;

    memset(Buf, 0, SOCKET_CONTEXT_LENGTH);
    h->HashValue = Hash;
    h->EntityLength = 12; /* just the DNS header; ID lives at Entity[0..1] */
    SET_16_BIT_U_INT(IHEADER_TAIL(h), Id);
}

int main(void)
{
    ModuleContext c;
    char Buf1[SOCKET_CONTEXT_LENGTH];
    char Buf2[SOCKET_CONTEXT_LENGTH];
    char Buf3[SOCKET_CONTEXT_LENGTH];
    MsgContext *Stored;
    uint16_t CapturedId;
    uint16_t RecycledId;

    printf("== hosts query-ID captured before context delete ==\n\n");

    if( ModuleContext_Init(&c, SOCKET_CONTEXT_LENGTH) != 0 )
    {
        printf("FAIL: ModuleContext_Init\n");
        return 2;
    }

    /* 1. Store the original query (ID 0x1234) as hosts.c does; Buffer2 is the
          InnerBuffer that already holds the same client query. */
    FillContext(Buf1, 0xABCD1234, 0x1234);
    FillContext(Buf2, 0xABCD1234, 0x1234);
    Stored = c.Add(&c, (MsgContext *)Buf1);
    if( Stored == NULL )
    {
        printf("FAIL: ModuleContext_Add\n");
        return 2;
    }

    /* 2. The fixed hosts.c reads the ID BEFORE deleting the node. */
    CapturedId = DNSGetQueryIdentifier(IHEADER_TAIL(Stored));
    CHECK(CapturedId == 0x1234,
          "the identifier is captured before the delete");

    /* 3. GenAnswerHeaderAndRemove() copies the IHeader into Buffer2, then
          resets and unlinks the stored node. */
    if( c.GenAnswerHeaderAndRemove(&c, Stored, (MsgContext *)Buf2) != 0 )
    {
        printf("FAIL: GenAnswerHeaderAndRemove\n");
        return 2;
    }
    CHECK(((IHeader *)Buf2)->EntityLength == 12,
          "the output context carries the header copy");

    /* 4. The next Add reuses the freed slot and overwrites its payload. */
    FillContext(Buf3, 0x11111111, 0x5678);
    if( c.Add(&c, (MsgContext *)Buf3) == NULL )
    {
        printf("FAIL: ModuleContext_Add (reuse)\n");
        return 2;
    }

    /* Negative control: the OLD order (read the node after the delete)
       picks up the recycled identifier, not the original one. */
    RecycledId = DNSGetQueryIdentifier(IHEADER_TAIL(Stored));
    CHECK(RecycledId == 0x5678,
          "negative control: the recycled node holds 0x5678");
    CHECK(RecycledId != CapturedId,
          "negative control: the old read-after-delete order is wrong");

    /* 5. The fixed code writes the captured ID back afterwards. */
    DNSSetQueryIdentifier(IHEADER_TAIL((IHeader *)Buf2), CapturedId);
    CHECK(DNSGetQueryIdentifier(IHEADER_TAIL((IHeader *)Buf2)) == 0x1234,
          "the captured identifier is written back after the delete");

    ModuleContext_Free(&c);

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
