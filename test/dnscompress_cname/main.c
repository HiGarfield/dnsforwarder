/* Semantic validation of DNSCompress() on a CNAME chain.
 *
 * Builds an uncompressed response with a question, a CNAME answer and an A
 * answer, runs DNSCompress(), then re-parses the compressed message and
 * checks every owner name, record type and RDATA.  This exercises the subtle
 * part of DNSCompress(): after the memmove() that replaces an owner name
 * with a two-byte compression pointer, the iterator's CurrentPosition points
 * at a *compressed* name, so DnsSimpleParserIterator_RowData() must skip
 * exactly the two pointer bytes -- DNSGetHostName() with a NULL buffer stops
 * at the first pointer -- for the CNAME-target offset to stay correct.  If
 * the RDATA position were computed against the pre-memmove layout, the next
 * record's pointer would land in the middle of the CNAME target and every
 * subsequent name would decode to garbage.
 */
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "dnsparser.h"
#include "dnsgenerator.h"

static int failures = 0;

#define CHECK(cond, msg) \
    do { if (!(cond)) { printf("FAIL: %s (line %d)\n", (msg), __LINE__); ++failures; } } while (0)

int main(void)
{
    char buf[1024];
    char compressed[1024];
    DnsGenerator g;
    DnsSimpleParser p;
    DnsSimpleParserIterator i;
    char name[256];
    int ridx = 0;
    int rawlen, clen;

    if (DnsGenerator_Init(&g, buf, sizeof(buf), NULL, 0, FALSE) != 0)
    {
        printf("FAIL: DnsGenerator_Init\n");
        return 1;
    }

    /* question: www.example.com A IN.  DnsGenerator_Init() leaves the cursor
       on the question count, so the first record is written without a prior
       NextPurpose(). */
    if (g.Question(&g, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN) != 0)
    {
        printf("FAIL: question generation\n");
        return 1;
    }

    /* answers: CNAME www.example.com -> example.com, then A example.com.
       Both are written while the cursor stays on the answer count; the
       DNSCompress() loop only touches ANSWER-purpose records. */
    if (g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ANSWER)
    {
        printf("FAIL: cannot move to answer section\n");
        return 1;
    }
    if (g.CName(&g, "www.example.com", "example.com", 300) != 0 ||
        g.A(&g, "example.com", "1.2.3.4", 300) != 0)
    {
        printf("FAIL: answer generation\n");
        return 1;
    }

    rawlen = g.Length(&g);
    if (rawlen <= 0 || rawlen > (int)sizeof(compressed))
    {
        printf("FAIL: bad generated length %d\n", rawlen);
        return 1;
    }

    memcpy(compressed, buf, (size_t)rawlen);
    clen = DNSCompress(compressed, rawlen);
    CHECK(clen >= 0, "DNSCompress() returns >= 0");
    if (clen < 0)
        return 1;
    CHECK(clen < rawlen, "compression shrinks the message");
    printf("rawlen=%d compressed=%d\n", rawlen, clen);

    /* Re-parse the compressed message and verify every record. */
    if (DnsSimpleParser_Init(&p, compressed, clen, FALSE) != 0)
    {
        printf("FAIL: re-parse compressed message\n");
        return 1;
    }
    if (DnsSimpleParserIterator_Init(&i, &p) != 0)
    {
        printf("FAIL: iterator init on compressed message\n");
        return 1;
    }

    while (i.Next(&i) != NULL)
    {
        int nl = i.GetName(&i, name, sizeof(name));
        CHECK(nl >= 0, "owner name decodes");
        if (nl < 0)
            return 1;

        switch (ridx)
        {
        case 0: /* question */
            CHECK(i.Purpose == DNS_RECORD_PURPOSE_QUESTION, "record 0 is the question");
            CHECK(strcmp(name, "www.example.com") == 0, "question name intact");
            CHECK(i.Type == DNS_TYPE_A, "question type intact");
            break;

        case 1: /* CNAME */
            CHECK(i.Purpose == DNS_RECORD_PURPOSE_ANSWER, "record 1 is an answer");
            CHECK(strcmp(name, "www.example.com") == 0, "CNAME owner name intact");
            CHECK(i.Type == DNS_TYPE_CNAME, "CNAME type intact");
            {
                char target[256];
                int tl = DNSGetHostName(p.RawDns, p.RawDnsLength,
                                        i.RowData(&i), target, sizeof(target));
                CHECK(tl >= 0 && strcmp(target, "example.com") == 0,
                      "CNAME target intact");
            }
            break;

        case 2: /* A */
            CHECK(i.Purpose == DNS_RECORD_PURPOSE_ANSWER, "record 2 is an answer");
            CHECK(strcmp(name, "example.com") == 0, "A owner name intact");
            CHECK(i.Type == DNS_TYPE_A, "A type intact");
            CHECK(GET_32_BIT_U_INT(i.RowData(&i)) == 0x01020304, "A RDATA intact");
            break;

        default:
            break;
        }
        ++ridx;
    }

    CHECK(ridx == 3, "exactly three records parsed");
    if (ridx != 3)
        return 1;

    if (failures == 0)
    {
        printf("dnscompress_cname: all ok\n");
        return 0;
    }
    printf("dnscompress_cname: %d failure(s)\n", failures);
    return 1;
}
