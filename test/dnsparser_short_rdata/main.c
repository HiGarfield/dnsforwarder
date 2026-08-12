/*
 * Regression test: a resource record whose RDLENGTH is shorter than the
 * layout its type mandates must not make the field parsers read past the
 * RDATA -- and, when the record is the last one in the message, past the end
 * of the received packet.
 *
 * DnsSimpleParserIterator_ParseData() walks a per-type list of field parsers
 * and only stops when the remaining RDATA length reaches zero. The fixed-width
 * parsers used to read their 2, 4 or 16 bytes unconditionally, so a response
 * carrying e.g. a SOA record with a 3-byte RDATA, or an A record with
 * RDLENGTH 1, over-read the packet buffer. Both the logging path
 * (GetAllAnswers()/TextifyData()) and the caching path (ToCacheData()) reach
 * that code with completely unvalidated upstream responses.
 *
 * The messages below are copied to the very end of a writable page that is
 * followed by a PROT_NONE guard page, so any read beyond the stated message
 * length is a hard SIGSEGV rather than a silent peek at adjacent heap.
 *
 * Build (from the repository root):
 *   cc -I. -o /tmp/t_short_rdata test/dnsparser_short_rdata/main.c \
 *      dnsparser.c utils.c addresslist.c array.c stringlist.c -lpthread
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../../dnsparser.h"
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

/* ------------------------------------------------------------------ */
/* Message building                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned char Raw[512];
    int Length;
} Message;

static void Message_Init(Message *m, int AnswerCount)
{
    memset(m->Raw, 0, sizeof(m->Raw));
    m->Raw[0] = 0x12; m->Raw[1] = 0x34;
    m->Raw[2] = 0x81; m->Raw[3] = 0x80;     /* response, no error */
    m->Raw[5] = 1;                          /* QDCOUNT */
    m->Raw[7] = (unsigned char)AnswerCount; /* ANCOUNT */
    m->Length = DNS_HEADER_LENGTH;
}

static void Message_AppendName(Message *m, const char *Name)
{
    const char *Itr = Name;

    while( *Itr != '\0' )
    {
        const char *Dot = strchr(Itr, '.');
        int Len = Dot == NULL ? (int)strlen(Itr) : (int)(Dot - Itr);

        m->Raw[m->Length++] = (unsigned char)Len;
        memcpy(m->Raw + m->Length, Itr, Len);
        m->Length += Len;

        if( Dot == NULL )
        {
            break;
        }
        Itr = Dot + 1;
    }

    m->Raw[m->Length++] = 0;
}

static void Message_AppendQuestion(Message *m, const char *Name, int Type)
{
    Message_AppendName(m, Name);
    m->Raw[m->Length++] = (unsigned char)(Type >> 8);
    m->Raw[m->Length++] = (unsigned char)Type;
    m->Raw[m->Length++] = 0;
    m->Raw[m->Length++] = 1;                /* IN */
}

/* Starts a record; returns the offset of its RDLENGTH field. */
static int Message_StartRecord(Message *m, int Type)
{
    int RdLengthPos;

    m->Raw[m->Length++] = 0xC0;             /* pointer to the question name */
    m->Raw[m->Length++] = DNS_HEADER_LENGTH;
    m->Raw[m->Length++] = (unsigned char)(Type >> 8);
    m->Raw[m->Length++] = (unsigned char)Type;
    m->Raw[m->Length++] = 0;
    m->Raw[m->Length++] = 1;                /* IN */
    m->Raw[m->Length++] = 0;
    m->Raw[m->Length++] = 0;
    m->Raw[m->Length++] = 1;
    m->Raw[m->Length++] = 44;               /* TTL = 300 */

    RdLengthPos = m->Length;
    m->Length += 2;

    return RdLengthPos;
}

static void Message_EndRecord(Message *m, int RdLengthPos)
{
    int RdLength = m->Length - RdLengthPos - 2;

    m->Raw[RdLengthPos] = (unsigned char)(RdLength >> 8);
    m->Raw[RdLengthPos + 1] = (unsigned char)RdLength;
}

/* Overrides RDLENGTH with a bogus, too-small value. */
static void Message_ForgeRdLength(Message *m, int RdLengthPos, int RdLength)
{
    m->Raw[RdLengthPos] = (unsigned char)(RdLength >> 8);
    m->Raw[RdLengthPos + 1] = (unsigned char)RdLength;
    m->Length = RdLengthPos + 2 + RdLength;
}

/* ------------------------------------------------------------------ */
/* Guard-page placement                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    char   *Base;
    size_t  MapLength;
    char   *Message;
    int     Length;
} Placed;

static int Place(Placed *P, const Message *m)
{
    long PageSize = sysconf(_SC_PAGESIZE);

    P->MapLength = (size_t)PageSize * 2;
    P->Base = mmap(NULL, P->MapLength, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if( P->Base == MAP_FAILED )
    {
        P->Base = NULL;
        return -1;
    }

    if( mprotect(P->Base + PageSize, (size_t)PageSize, PROT_NONE) != 0 )
    {
        munmap(P->Base, P->MapLength);
        P->Base = NULL;
        return -1;
    }

    /* End the message exactly at the guard page. */
    P->Message = P->Base + PageSize - m->Length;
    P->Length = m->Length;
    memcpy(P->Message, m->Raw, m->Length);

    return 0;
}

static void Unplace(Placed *P)
{
    if( P->Base != NULL )
    {
        munmap(P->Base, P->MapLength);
        P->Base = NULL;
    }
}

/* Runs both consumers of the field parsers over every answer of `m'.
   `*Textified' / `*Cached' receive the number of answers that were
   successfully converted. */
static int Walk(const Message *m, int *Textified, int *Cached)
{
    Placed P;
    DnsSimpleParser p;
    DnsSimpleParserIterator i;
    char Buffer[512];

    *Textified = 0;
    *Cached = 0;

    if( Place(&P, m) != 0 )
    {
        return -1;
    }

    /* The exact code path the logger takes for every single response. */
    GetAllAnswers(P.Message, P.Length, Buffer, sizeof(Buffer));

    if( DnsSimpleParser_Init(&p, P.Message, P.Length, FALSE) != 0 )
    {
        Unplace(&P);
        return -1;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        Unplace(&P);
        return -1;
    }

    i.GotoAnswers(&i);

    while( i.Next(&i) != NULL && i.Purpose == DNS_RECORD_PURPOSE_ANSWER )
    {
        if( i.TextifyData(&i, "%t: %v\n", Buffer, sizeof(Buffer)) > 0 )
        {
            ++*Textified;
        }
        if( i.ToCacheData(&i, Buffer, sizeof(Buffer)) > 0 )
        {
            ++*Cached;
        }
    }

    Unplace(&P);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

static void Test_ShortRdataIsRefused(void)
{
    struct {
        const char *Name;
        int         Type;
        int         RdLength;   /* forged, too small for the type */
    } Cases[] = {
        { "A with RDLENGTH 0",      DNS_TYPE_A,     0 },
        { "A with RDLENGTH 1",      DNS_TYPE_A,     1 },
        { "A with RDLENGTH 3",      DNS_TYPE_A,     3 },
        { "AAAA with RDLENGTH 1",   DNS_TYPE_AAAA,  1 },
        { "AAAA with RDLENGTH 15",  DNS_TYPE_AAAA, 15 },
        { "MX with RDLENGTH 1",     DNS_TYPE_MX,    1 },
        { "SOA with RDLENGTH 1",    DNS_TYPE_SOA,   1 },
        { "SOA with RDLENGTH 3",    DNS_TYPE_SOA,   3 },
        { "CNAME with RDLENGTH 1",  DNS_TYPE_CNAME, 1 }
    };
    unsigned int c;

    printf("Records whose RDLENGTH is too small for their type\n");

    for( c = 0; c < sizeof(Cases) / sizeof(Cases[0]); ++c )
    {
        Message m;
        int RdLengthPos;
        int Textified;
        int Cached;
        char CaseName[96];

        Message_Init(&m, 1);
        Message_AppendQuestion(&m, "www.example.com", DNS_TYPE_A);
        RdLengthPos = Message_StartRecord(&m, Cases[c].Type);
        /* Fill in a plausible body first so that the bytes the parser would
           over-read really are outside the message. */
        memset(m.Raw + m.Length, 0x41, 24);
        m.Length += 24;
        Message_ForgeRdLength(&m, RdLengthPos, Cases[c].RdLength);

        if( Walk(&m, &Textified, &Cached) != 0 )
        {
            printf("  [SKIP] %s (could not place the message)\n",
                   Cases[c].Name);
            continue;
        }

        snprintf(CaseName, sizeof(CaseName),
                 "%s is not textified", Cases[c].Name);
        Check(CaseName, Textified == 0);

        snprintf(CaseName, sizeof(CaseName),
                 "%s is not cached", Cases[c].Name);
        Check(CaseName, Cached == 0);
    }
}

/*
 * A truncated record must not stop the parser from handling the records that
 * come before it, and it must not stop the message from being walked at all.
 */
static void Test_GoodRecordBeforeShortOne(void)
{
    Message m;
    int RdLengthPos;
    int Textified;
    int Cached;

    printf("A good record followed by a truncated one\n");

    Message_Init(&m, 2);
    Message_AppendQuestion(&m, "www.example.com", DNS_TYPE_A);

    RdLengthPos = Message_StartRecord(&m, DNS_TYPE_A);
    m.Raw[m.Length++] = 93;
    m.Raw[m.Length++] = 184;
    m.Raw[m.Length++] = 216;
    m.Raw[m.Length++] = 34;
    Message_EndRecord(&m, RdLengthPos);

    RdLengthPos = Message_StartRecord(&m, DNS_TYPE_SOA);
    memset(m.Raw + m.Length, 0x41, 24);
    m.Length += 24;
    Message_ForgeRdLength(&m, RdLengthPos, 2);

    if( Walk(&m, &Textified, &Cached) != 0 )
    {
        printf("  [SKIP] could not place the message\n");
        return;
    }

    Check("the well-formed A record is still textified", Textified == 1);
    Check("the well-formed A record is still cached", Cached == 1);
}

/*
 * The new length checks must not reject well-formed records: every type the
 * parser knows about is exercised as the last record of the message, so that
 * an off-by-one in the checks would either drop the record or fault on the
 * guard page.
 */
static void Test_WellFormedRecordsStillParse(void)
{
    struct {
        const char *Name;
        int         Type;
    } Cases[] = {
        { "A",      DNS_TYPE_A },
        { "AAAA",   DNS_TYPE_AAAA },
        { "CNAME",  DNS_TYPE_CNAME },
        { "NS",     DNS_TYPE_NS },
        { "PTR",    DNS_TYPE_PTR },
        { "MX",     DNS_TYPE_MX },
        { "TXT",    DNS_TYPE_TXT },
        { "SOA",    DNS_TYPE_SOA }
    };
    unsigned int c;

    printf("Well-formed records of every known type\n");

    for( c = 0; c < sizeof(Cases) / sizeof(Cases[0]); ++c )
    {
        Message m;
        int RdLengthPos;
        int Textified;
        int Cached;
        char CaseName[96];

        Message_Init(&m, 1);
        Message_AppendQuestion(&m, "www.example.com", DNS_TYPE_A);
        RdLengthPos = Message_StartRecord(&m, Cases[c].Type);

        switch( Cases[c].Type )
        {
        case DNS_TYPE_A:
            m.Raw[m.Length++] = 93; m.Raw[m.Length++] = 184;
            m.Raw[m.Length++] = 216; m.Raw[m.Length++] = 34;
            break;

        case DNS_TYPE_AAAA:
            memset(m.Raw + m.Length, 0x20, 16);
            m.Length += 16;
            break;

        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
        case DNS_TYPE_PTR:
            Message_AppendName(&m, "alias.example.org");
            break;

        case DNS_TYPE_MX:
            m.Raw[m.Length++] = 0; m.Raw[m.Length++] = 10;
            Message_AppendName(&m, "mail.example.org");
            break;

        case DNS_TYPE_TXT:
            m.Raw[m.Length++] = 5;
            memcpy(m.Raw + m.Length, "hello", 5);
            m.Length += 5;
            break;

        case DNS_TYPE_SOA:
            Message_AppendName(&m, "ns.example.org");
            Message_AppendName(&m, "root.example.org");
            memset(m.Raw + m.Length, 0, 20);
            m.Length += 20;
            break;

        default:
            break;
        }

        Message_EndRecord(&m, RdLengthPos);

        if( Walk(&m, &Textified, &Cached) != 0 )
        {
            printf("  [SKIP] %s (could not place the message)\n",
                   Cases[c].Name);
            continue;
        }

        snprintf(CaseName, sizeof(CaseName),
                 "a well-formed %s record is textified", Cases[c].Name);
        Check(CaseName, Textified == 1);

        snprintf(CaseName, sizeof(CaseName),
                 "a well-formed %s record is cached", Cases[c].Name);
        Check(CaseName, Cached == 1);
    }
}

/*
 * A record whose RDATA is larger than the layout needs is legal (unknown
 * trailing fields); it must still be usable.
 */
static void Test_OverLongRdataStillParses(void)
{
    Message m;
    int RdLengthPos;
    int Textified;
    int Cached;

    printf("A record with trailing RDATA\n");

    Message_Init(&m, 1);
    Message_AppendQuestion(&m, "www.example.com", DNS_TYPE_MX);
    RdLengthPos = Message_StartRecord(&m, DNS_TYPE_MX);
    m.Raw[m.Length++] = 0; m.Raw[m.Length++] = 10;
    Message_AppendName(&m, "mail.example.org");
    memset(m.Raw + m.Length, 0, 8);         /* unknown trailing bytes */
    m.Length += 8;
    Message_EndRecord(&m, RdLengthPos);

    if( Walk(&m, &Textified, &Cached) != 0 )
    {
        printf("  [SKIP] could not place the message\n");
        return;
    }

    Check("an MX record with trailing RDATA is textified", Textified == 1);
    Check("an MX record with trailing RDATA is cached", Cached == 1);
}

int main(void)
{
    printf("== short-RDATA regression tests ==\n\n");

    Test_ShortRdataIsRefused();
    Test_GoodRecordBeforeShortOne();
    Test_WellFormedRecordsStillParse();
    Test_OverLongRdataStillParses();

    printf("\n%d checks, %d failure(s)\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
