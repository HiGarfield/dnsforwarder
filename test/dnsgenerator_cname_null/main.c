/* Regression test for the DnsGenerator_CName NULL-pointer dereference.
 *
 * A CNAME/PTR/NS resource record whose RDATA has zero length makes
 * DnsSimpleParserIterator_RowData() return NULL. DnsGenerator_Generate()
 * forwarded that NULL as the CName argument, and DnsGenerator_CName()
 * dereferenced it via the LABEL_LENGTH() macro -> crash.
 *
 * This test builds a minimal CNAME answer with an empty RDATA and verifies
 * the generator rejects it with a negative error code instead of crashing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "dnsparser.h"
#include "dnsgenerator.h"

int main(void)
{
    /* question: example.com.  CNAME IN */
    unsigned char msg[] = {
        0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
        0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,
        0x00,0x05,0x00,0x01,            /* CNAME IN */
        0x00,0x00,0x00,0x00,            /* TTL = 0 */
        0x00,0x00                       /* RDLENGTH = 0 -> empty RDATA */
    };
    int len = (int)sizeof(msg);

    DnsSimpleParser p;
    DnsSimpleParserIterator i;
    if( DnsSimpleParser_Init(&p, (char*)msg, len, FALSE) != 0 ){
        fprintf(stderr, "parser init failed\n"); return 1;
    }
    if( DnsSimpleParserIterator_Init(&i, &p) != 0 ){
        fprintf(stderr, "iterator init failed\n"); return 1;
    }

    char *pos;
    int saw_cname = 0;
    while( (pos = i.Next(&i)) != NULL ){
        if( i.Type != DNS_TYPE_CNAME ) continue;
        saw_cname = 1;
        char name[2048];
        i.GetName(&i, name, (int)sizeof(name));
        char *rd = i.RowData(&i);   /* NULL because RDLENGTH==0 */
        int dl  = i.DataLength;     /* 0 */
        int ttl = i.GetTTL(&i);

        char out[1024];
        DnsGenerator g;
        if( DnsGenerator_Init(&g, out, (int)sizeof(out), (char*)msg, len, TRUE) != 0 ){
            fprintf(stderr, "generator init failed\n"); return 1;
        }
        g.NextPurpose(&g);
        int ret = g.Generate(&g, name, i.Type, i.Klass, rd, dl, ttl);
        if( ret >= 0 ){
            fprintf(stderr, "BUG: Generate accepted NULL CName (ret=%d)\n", ret);
            return 1;
        }
        printf("NULL CName rejected with ret=%d (expected <0)\n", ret);
    }

    if( !saw_cname ){
        fprintf(stderr, "test setup error: no CNAME record parsed\n"); return 1;
    }
    printf("OK: DnsGenerator_CName NULL deref fixed\n");
    return 0;
}
