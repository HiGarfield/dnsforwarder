#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "dnsparser.h"
#include "dnsgenerator.h"

/* A DNS response with QDCOUNT == 0 but ANCOUNT == 1.
 * The buggy iterator mis-computes section positions when the question
 * section is empty and therefore classifies the answer as UNKNOWN and
 * stops iterating after the first record. */
static unsigned char ZeroQuestionResponse[] = {
    /* Header */
    0x12, 0x34,        /* ID */
    0x81, 0x80,        /* Flags: response, recursion available */
    0x00, 0x00,        /* QDCOUNT = 0 */
    0x00, 0x01,        /* ANCOUNT = 1 */
    0x00, 0x00,        /* NSCOUNT = 0 */
    0x00, 0x00,        /* ARCOUNT = 0 */
    /* Answer record (root name) */
    0x00,              /* root label */
    0x00, 0x01,        /* TYPE A */
    0x00, 0x01,        /* CLASS IN */
    0x00, 0x00, 0x00, 0x3c,  /* TTL = 60 */
    0x00, 0x04,        /* RDLENGTH = 4 */
    0x0a, 0x00, 0x00, 0x01   /* RDATA 10.0.0.1 */
};

/* Sanity: a normal response with QDCOUNT == 1 must still parse. */
static unsigned char OneQuestionResponse[] = {
    0x12, 0x34,
    0x81, 0x80,
    0x00, 0x01,        /* QDCOUNT = 1 */
    0x00, 0x01,        /* ANCOUNT = 1 */
    0x00, 0x00,
    0x00, 0x00,
    /* Question: root name, TYPE A, CLASS IN */
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    /* Answer: root name, TYPE A, CLASS IN, TTL, RDLENGTH, 10.0.0.2 */
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x00, 0x3c,
    0x00, 0x04,
    0x0a, 0x00, 0x00, 0x02
};

int main(void)
{
    int failures = 0;

    /* Case 1: QDCOUNT == 0, ANCOUNT == 1 */
    {
        DnsSimpleParser p;
        DnsSimpleParserIterator i;
        if( DnsSimpleParser_Init(&p, (char *)ZeroQuestionResponse,
                                 sizeof(ZeroQuestionResponse), FALSE) != 0 )
        {
            printf("FAIL: init zero-question response\n");
            ++failures;
        } else if( DnsSimpleParserIterator_Init(&i, &p) != 0 ) {
            printf("FAIL: iterator init zero-question response\n");
            ++failures;
        } else {
            char *rec = i.Next(&i);
            if( rec == NULL )
            {
                printf("FAIL: iterator stopped at first record (QDCOUNT=0)\n");
                ++failures;
            } else if( i.Purpose != DNS_RECORD_PURPOSE_ANSWER ) {
                printf("FAIL: answer misclassified as purpose %d\n", (int)i.Purpose);
                ++failures;
            } else if( i.Type != DNS_TYPE_A ) {
                printf("FAIL: wrong type %d\n", (int)i.Type);
                ++failures;
            } else if( i.DataLength != 4 ) {
                printf("FAIL: wrong rdlength %d\n", i.DataLength);
                ++failures;
            } else {
                const char *rd = i.RowData(&i);
                if( rd == NULL || rd[0] != 10 || rd[1] != 0 || rd[2] != 0 || rd[3] != 1 )
                {
                    printf("FAIL: wrong RDATA\n");
                    ++failures;
                } else if( i.Next(&i) != NULL ) {
                    printf("FAIL: expected end after single answer\n");
                    ++failures;
                } else {
                    printf("OK: QDCOUNT=0 response parsed (answer 10.0.0.1)\n");
                }
            }
        }
    }

    /* Case 2: regression - QDCOUNT == 1 still works */
    {
        DnsSimpleParser p;
        DnsSimpleParserIterator i;
        if( DnsSimpleParser_Init(&p, (char *)OneQuestionResponse,
                                 sizeof(OneQuestionResponse), FALSE) != 0 )
        {
            printf("FAIL: init one-question response\n");
            ++failures;
        } else if( DnsSimpleParserIterator_Init(&i, &p) != 0 ) {
            printf("FAIL: iterator init one-question response\n");
            ++failures;
        } else {
            /* Skip question */
            char *q = i.Next(&i);
            if( q == NULL || i.Purpose != DNS_RECORD_PURPOSE_QUESTION )
            {
                printf("FAIL: question not parsed\n");
                ++failures;
            } else {
                char *a = i.Next(&i);
                if( a == NULL || i.Purpose != DNS_RECORD_PURPOSE_ANSWER )
                {
                    printf("FAIL: answer not parsed (regression)\n");
                    ++failures;
                } else {
                    const char *rd = i.RowData(&i);
                    if( rd == NULL || rd[3] != 2 )
                    {
                        printf("FAIL: wrong answer RDATA\n");
                        ++failures;
                    } else {
                        printf("OK: QDCOUNT=1 response still parses\n");
                    }
                }
            }
        }
    }

    if( failures == 0 )
    {
        printf("ALL DNSPARSER-ZERO-QUESTION TESTS PASSED\n");
        return 0;
    }
    printf("%d DNSPARSER-ZERO-QUESTION TESTS FAILED\n", failures);
    return 1;
}
