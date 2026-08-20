/*
 * Regression tests for dnsgenerator.c:
 *   Bug #1: DnsGenerator_CopyA / CopyAAAA / CopyCName / RawData used to write
 *   the record header (including RDLENGTH) BEFORE validating the RDATA and the
 *   remaining buffer.  A malformed/short record therefore left an internally
 *   inconsistent (partial) record in the answer buffer.  These cases verify the
 *   generator rejects such records and leaves the output length UNCHANGED.
 *
 * Build (from the repository root):
 *   cc -I. -o /tmp/t_dnsgen test/dnsgenerator_malformed_rdata/main.c \
 *      dnsparser.c dnsgenerator.c utils.c array.c stringlist.c stablebuffer.c \
 *      dnsrelated.c iheader.c -lpthread -lm
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../dnsparser.h"
#include "../../dnsgenerator.h"
#include "../../utils.h"

static int Failures = 0;
static int Checks = 0;

static void Check(const char *Name, int Condition)
{
    ++Checks;
    if( Condition )
    {
        printf("  [ ok ] %s\n", Name);
    } else {
        printf("  [FAIL] %s\n", Name);
        ++Failures;
    }
}

/* Build a single-answer DNS response for "a.bc" whose answer is of `Type'
 * (A / AAAA / CNAME) with the given (possibly malformed) RDLENGTH, and return
 * the raw packet plus its length.  The RDATA content is filled with 16 bytes so
 * the parser accepts the record boundaries, but RDLENGTH is set independently so
 * we can simulate a short record. */
static int BuildAnswer(const char *Name,
                       uint16_t Type,
                       int RdLength,
                       unsigned char *Out)
{
    /* Header: 1 question, 1 answer. */
    static const unsigned char Hdr[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    int o = 0;
    memcpy(Out + o, Hdr, sizeof(Hdr)); o += (int)sizeof(Hdr);

    /* Question: a.bc IN A. */
    Out[o++] = 1; Out[o++] = 'a';
    Out[o++] = 2; Out[o++] = 'b'; Out[o++] = 'c';
    Out[o++] = 0;
    Out[o++] = 0; Out[o++] = 0x01; /* QTYPE A */
    Out[o++] = 0; Out[o++] = 0x01; /* QCLASS IN */

    /* Answer name: pointer to question name at offset 12. */
    Out[o++] = 0xC0; Out[o++] = 0x0C;
    /* TYPE (use caller's type). */
    Out[o++] = (unsigned char)(Type >> 8);
    Out[o++] = (unsigned char)(Type & 0xFF);
    Out[o++] = 0x00; Out[o++] = 0x01; /* CLASS IN */
    Out[o++] = 0x00; Out[o++] = 0x00; Out[o++] = 0x00; Out[o++] = 0x3C; /* TTL */
    /* RDLENGTH. */
    Out[o++] = (unsigned char)(RdLength >> 8);
    Out[o++] = (unsigned char)(RdLength & 0xFF);
    /* RDATA: 16 bytes of filler (enough for A/AAAA/CNAME label). */
    {
        int k;
        for( k = 0; k < 16; ++k )
            Out[o++] = (unsigned char)(0x30 + (k & 0x0F));
    }
    (void)Name;
    return o;
}

/* Copy one answer record of the given type from `Raw' (length `RawLen') into a
 * fresh DnsGenerator.  Returns the generator's length BEFORE the copy attempt,
 * AFTER it, and the copy return code. */
static void AttemptCopy(uint16_t RecordType,
                        int RdLength,
                        int *BeforeLen,
                        int *AfterLen,
                        int *Ret)
{
    unsigned char Raw[256];
    int RawLen = BuildAnswer("a.bc", RecordType, RdLength, Raw);

    DnsSimpleParser p;
    DnsSimpleParserIterator i;
    char GenBuf[512];
    DnsGenerator g;

    *BeforeLen = 0;
    *AfterLen = 0;
    *Ret = -999;

    if( DnsSimpleParser_Init(&p, (char *)Raw, RawLen, FALSE) != 0 )
        return;
    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
        return;

    /* Walk to the answer section. */
    {
        char *pos;
        while( (pos = i.Next(&i)) != NULL &&
               i.Purpose != DNS_RECORD_PURPOSE_ANSWER )
            ; /* advance */
        if( pos == NULL )
            return;
    }

    if( DnsGenerator_Init(&g, GenBuf, sizeof(GenBuf), NULL, 0, FALSE) != 0 )
        return;

    /* Move to the answer section of the generator. */
    while( g.CurrentPurpose(&g) != DNS_RECORD_PURPOSE_ANSWER )
    {
        if( g.NextPurpose(&g) == DNS_RECORD_PURPOSE_UNKNOWN )
            return;
    }

    *BeforeLen = g.Length(&g);

    switch( RecordType )
    {
    case DNS_TYPE_A:     *Ret = g.CopyA(&g, &i); break;
    case DNS_TYPE_AAAA:  *Ret = g.CopyAAAA(&g, &i); break;
    case DNS_TYPE_CNAME: *Ret = g.CopyCName(&g, &i); break;
    default:             *Ret = -998; break;
    }

    *AfterLen = g.Length(&g);
}

static void Test_ShortARecord(void)
{
    int before, after, ret;
    printf("Short A record (RDLENGTH = 2)\n");
    AttemptCopy(DNS_TYPE_A, 2, &before, &after, &ret);
    Check("CopyA rejects a short A record", ret < 0);
    Check("CopyA leaves the generator length unchanged", before == after);
}

static void Test_ShortAAAARecord(void)
{
    int before, after, ret;
    printf("Short AAAA record (RDLENGTH = 4)\n");
    AttemptCopy(DNS_TYPE_AAAA, 4, &before, &after, &ret);
    Check("CopyAAAA rejects a short AAAA record", ret < 0);
    Check("CopyAAAA leaves the generator length unchanged", before == after);
}

static void Test_ZeroRDATACName(void)
{
    int before, after, ret;
    printf("Zero-RDLENGTH CNAME\n");
    AttemptCopy(DNS_TYPE_CNAME, 0, &before, &after, &ret);
    Check("CopyCName rejects a zero-RDLENGTH CNAME", ret < 0);
    Check("CopyCName leaves the generator length unchanged", before == after);
}

static void Test_ValidARecordStillCopies(void)
{
    int before, after, ret;
    printf("Valid A record (RDLENGTH = 4)\n");
    AttemptCopy(DNS_TYPE_A, 4, &before, &after, &ret);
    Check("CopyA accepts a well-formed A record", ret == 0);
    Check("CopyA advanced the generator for a valid record",
          after > before);
    Check("CopyA refused to write a partial record for valid input",
          after - before > 0);
}

int main(void)
{
    printf("== dnsgenerator malformed-RDATA regression tests ==\n\n");
    Test_ShortARecord();
    Test_ShortAAAARecord();
    Test_ZeroRDATACName();
    Test_ValidARecordStillCopies();

    printf("\n%d checks, %d failure(s)\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
