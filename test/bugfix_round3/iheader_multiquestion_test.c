/*
 * Regression proof for Bug #1: IHeader_Fill() must derive h->Type from the
 * *current* QUESTION record, not from the first record of the message.
 *
 * Before the fix, IHeader_Fill() used DNSGetRecordType(DNSJumpHeader(DnsEntity))
 * for every QUESTION record.  DNSJumpHeader() always points at the first record
 * of the message regardless of which record the iterator is visiting, so h->Type
 * reflected the first record's type for every QUESTION.  With QDCOUNT > 1 the
 * type then mismatched the domain that was just parsed (h->Domain came from the
 * current record), and downstream type filters / hosts / cache rules keyed on
 * h->Type operated on the wrong record type.
 *
 * This test builds a DNS request with two QUESTION records -- the first an A
 * query for www.example.com, the second an AAAA query for mail.example.com --
 * and checks that after IHeader_Fill() h->Domain is the second question's name
 * ("mail.example.com") and h->Type is DNS_TYPE_AAAA (28), NOT DNS_TYPE_A (1).
 *
 * Build & run:
 *     gcc -Wall -Wextra -I../.. iheader_multiquestion_test.c -o t && ./t
 */
#include <stdio.h>
#include <string.h>
#include "iheader.h"
#include "dnsparser.h"
#include "dnsrelated.h"

/* Test stub: IHeader_Fill() does not invoke socket release, but linking
 * iheader.c pulls in MsgContext_ReleaseSocket() which references
 * TcpFrontend_ReleaseSocket().  Provide a no-op so the unit test links without
 * dragging in the whole frontend / logging / config dependency tree. */
void TcpFrontend_ReleaseSocket(int s) { (void)s; }

int main(void)
{
    static char buf[SOCKET_CONTEXT_LENGTH];
    IHeader *h = (IHeader *)buf;
    char *entity = (char *)IHEADER_TAIL(h);

    int failures = 0;

    /* DNS header: id=0x1234, flags=0x0100 (recursion desired),
     * QDCOUNT=2, AN/NS/AR = 0. */
    memcpy(entity + 0,  "\x12\x34", 2);
    memcpy(entity + 2,  "\x01\x00", 2);
    memcpy(entity + 4,  "\x00\x02", 2);   /* QDCOUNT = 2 */
    memcpy(entity + 6,  "\x00\x00", 2);
    memcpy(entity + 8,  "\x00\x00", 2);
    memcpy(entity + 10, "\x00\x00", 2);

    int off = DNS_HEADER_LENGTH;

    /* Q1: www.example.com  A  IN
     * Labelled form is "\x03 www \x07 example \x03 com" = 16 wire bytes,
     * plus the terminating 0x00 = 17 bytes total. */
    memcpy(entity + off, "\x03""www""\x07""example""\x03""com", 16);
    entity[off + 16] = '\0';
    off += 17;
    memcpy(entity + off, "\x00\x01", 2);   /* TYPE A */
    memcpy(entity + off + 2, "\x00\x01", 2); /* CLASS IN */
    off += 4;

    /* Q2: mail.example.com  AAAA  IN
     * Labelled form is "\x04 mail \x07 example \x03 com" = 17 wire bytes,
     * plus the terminating 0x00 = 18 bytes total. */
    memcpy(entity + off, "\x04""mail""\x07""example""\x03""com", 17);
    entity[off + 17] = '\0';
    off += 18;
    memcpy(entity + off, "\x00\x1c", 2);   /* TYPE AAAA = 28 */
    memcpy(entity + off + 2, "\x00\x01", 2); /* CLASS IN */
    off += 4;

    int entity_len = off;

    if( IHeader_Fill(h, FALSE, entity, entity_len, NULL, -1, AF_UNSPEC, NULL) != 0 )
    {
        printf("FAIL: IHeader_Fill returned non-zero for a valid request\n");
        return 1;
    }

    printf("h->Domain = \"%s\"\n", h->Domain);
    printf("h->Type   = %d (expected AAAA = 28)\n", (int)h->Type);

    /* The last QUESTION record visited wins, so the domain must be the second
     * question's name. */
    if( strcmp(h->Domain, "mail.example.com") != 0 )
    {
        printf("FAIL: h->Domain is \"%s\", expected \"mail.example.com\"\n", h->Domain);
        ++failures;
    }

    /* And the type must be that record's type (AAAA), not the first one (A). */
    if( h->Type != DNS_TYPE_AAAA )
    {
        printf("FAIL: h->Type = %d, expected DNS_TYPE_AAAA (28)\n", (int)h->Type);
        ++failures;
    }

    if( failures == 0 )
    {
        printf("\nBug #1 fix verified: h->Type matches the current QUESTION record.\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
