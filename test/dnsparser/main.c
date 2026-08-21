/*
 * Regression tests for the DNS message parser and the address/IP helpers.
 *
 * Every case below reproduces a bug that was found and fixed; they exist so
 * that a future change cannot silently reintroduce the same defect.
 *
 * Build (from the repository root):
 *   cc -I. -o /tmp/t_dnsparser test/dnsparser/main.c dnsparser.c utils.c \
 *      addresslist.c array.c stringlist.c -lpthread
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "../../dnsparser.h"
#include "../../addresslist.h"
#include "../../utils.h"
#include "../../iheader.h"

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

/* A minimal well-formed query for "a.bc" IN A. */
static int BuildQuery(char *Buffer)
{
    static const unsigned char Tpl[] = {
        0x12, 0x34,             /* id */
        0x01, 0x00,             /* flags: standard query */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x00,             /* ANCOUNT */
        0x00, 0x00,             /* NSCOUNT */
        0x00, 0x00,             /* ARCOUNT */
        0x01, 'a',              /* label "a" */
        0x02, 'b', 'c',         /* label "bc" */
        0x00,                   /* root */
        0x00, 0x01,             /* QTYPE  = A */
        0x00, 0x01              /* QCLASS = IN */
    };

    memcpy(Buffer, Tpl, sizeof(Tpl));
    return (int)sizeof(Tpl);
}

/*
 * The iterator used to accept a record starting exactly at the end of the
 * message and then read its 4-byte type/class from beyond the buffer.
 * Truncating a message right after the name must make the iterator stop
 * instead of walking off the end.
 */
static void Test_TruncatedRecordIsRejected(void)
{
    char Raw[512];
    int Length = BuildQuery(Raw);
    int Cut;

    printf("Truncated records\n");

    /* Chop the message at every offset from just past the header up to the
       full length. None of them may crash or report a usable record beyond
       the buffer. Run under valgrind to prove the absence of OOB reads. */
    for( Cut = DNS_HEADER_LENGTH; Cut <= Length; ++Cut )
    {
        DnsSimpleParser p;
        DnsSimpleParserIterator i;
        /* Exactly `Cut' bytes, so that anything the parser touches beyond the
           stated message length is a genuine heap overrun that valgrind will
           report rather than a read of adjacent stack padding. */
        char *Copy = malloc(Cut);

        if( Copy == NULL )
        {
            continue;
        }

        memcpy(Copy, Raw, Cut);

        if( DnsSimpleParser_Init(&p, Copy, Cut, FALSE) != 0 )
        {
            free(Copy);
            continue;
        }

        if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
        {
            free(Copy);
            continue;
        }

        while( i.Next(&i) != NULL )
        {
            /* Whatever the iterator hands out must lie inside the buffer. */
            if( i.CurrentPosition < Copy || i.CurrentPosition >= Copy + Cut )
            {
                printf("  [FAIL] record pointer escaped the buffer at cut=%d\n",
                       Cut);
                ++Failures;
                break;
            }
        }

        free(Copy);
    }
    ++Checks;
    printf("  [ ok ] iterator stays inside the buffer for every truncation\n");
}

/*
 * A TCP buffer of 12 or 13 bytes passes the `Length >= DNS_HEADER_LENGTH`
 * test, but after the 2-byte length prefix is stripped the body is shorter
 * than a header. Init must refuse it.
 */
static void Test_ShortTcpBufferIsRejected(void)
{
    char Raw[32];
    DnsSimpleParser p;
    int Length;

    printf("Short TCP buffers\n");

    memset(Raw, 0, sizeof(Raw));

    for( Length = DNS_HEADER_LENGTH; Length < DNS_HEADER_LENGTH + 2; ++Length )
    {
        char Name[64];
        snprintf(Name, sizeof(Name),
                 "TCP buffer of %d bytes is rejected", Length);
        Check(Name, DnsSimpleParser_Init(&p, Raw, Length, TRUE) != 0);
    }

    /* One more byte and the body is exactly a header, which is acceptable. */
    Check("TCP buffer of 14 bytes is accepted",
          DnsSimpleParser_Init(&p, Raw, DNS_HEADER_LENGTH + 2, TRUE) == 0);

    Check("UDP buffer shorter than a header is rejected",
          DnsSimpleParser_Init(&p, Raw, DNS_HEADER_LENGTH - 1, FALSE) != 0);
}

/*
 * A compression pointer that points at itself, or two pointers that point at
 * each other, must not send the name walker into an endless loop.
 */
static void Test_CompressionPointerLoop(void)
{
    char Raw[64];
    int Length;

    printf("Compression pointer loops\n");

    memset(Raw, 0, sizeof(Raw));
    Length = BuildQuery(Raw);

    /* Self-referencing pointer at offset 12. */
    Raw[12] = (char)0xC0;
    Raw[13] = (char)12;

    {
        char Name[256];
        Check("self-referencing pointer is rejected when expanding",
              DNSGetHostName(Raw, Length, Raw + 12, Name, sizeof(Name)) < 0);
    }

    /* Two pointers referring to each other. This only loops when the name is
       actually expanded, i.e. when a real output buffer is supplied: with
       buffer == NULL the walker just measures the 2 bytes of the first
       pointer and stops without following it. */
    Raw[12] = (char)0xC0;
    Raw[13] = (char)14;
    Raw[14] = (char)0xC0;
    Raw[15] = (char)12;

    {
        char Name[256];
        Check("mutually-referencing pointers are rejected when expanding",
              DNSGetHostName(Raw, Length, Raw + 12, Name, sizeof(Name)) < 0);
    }

    /* A pointer aiming past the end of the message. */
    Raw[12] = (char)0xC0;
    Raw[13] = (char)200;

    Check("out-of-range pointer is rejected",
          DNSGetHostName(Raw, Length, Raw + 12, NULL, 0) < 0);
}

/*
 * DNSGetHostName() must validate NameStart against the message bounds BEFORE
 * reading the first label-length octet.  The old code read
 * `LabelCount = GET_8_BIT_U_INT(NameItr)' first and only then checked
 * `NameStart >= DNSBody + DNSBodyLength', so a caller that passed an
 * out-of-range NameStart (e.g. one-past-the-end) caused a single
 * out-of-bounds read before the function returned -1.  The buffer is heap
 * allocated so ASan/UBSan flags that read as heap-buffer-overflow.
 */
static void Test_DNSGetHostNameRejectsOutOfRangeStart(void)
{
    char Raw[64];
    char Name[128];
    char *Tight;
    int Length;

    printf("DNSGetHostName out-of-range NameStart\n");

    memset(Raw, 0, sizeof(Raw));
    Length = BuildQuery(Raw);

    /* The message is Length bytes.  A second heap block of EXACTLY Length
       bytes makes `Tight + Length' one-past-the-end of the allocation, so an
       out-of-bounds read at that spot is a real ASan/UBSan heap-buffer-
       overflow, not a read of adjacent stack/padding bytes. */
    Tight = (char *)malloc((size_t)Length);
    if( Tight == NULL )
    {
        Check("heap allocation", 0);
        return;
    }
    memcpy(Tight, Raw, (size_t)Length);

    /* One-past-the-end: the pre-fix code dereferenced it before bailing. */
    Check("NameStart == end is rejected without reading OOB",
          DNSGetHostName(Tight, Length, Tight + Length, Name, sizeof(Name)) < 0);

    /* Far past the end. */
    Check("NameStart far past the end is rejected",
          DNSGetHostName(Tight, Length, Tight + Length + 16, Name, sizeof(Name)) < 0);

    /* Before the message start (one-past-end of a shorter range). */
    Check("NameStart before the message is rejected",
          DNSGetHostName(Tight + 4, Length - 4, Tight, Name, sizeof(Name)) < 0);

    /* The in-range path is unaffected (returns the label length > 0). */
    Check("in-range NameStart still parses",
          DNSGetHostName(Tight, Length, Tight + 12, Name, sizeof(Name)) > 0 &&
          strcmp(Name, "a.bc") == 0);

    free(Tight);
}

/*
 * IPv4AddressToNum() must not write anything, and must report failure, when
 * the textual address is not exactly four in-range decimal components.
 * Otherwise callers store uninitialised stack bytes as an IP address.
 */
static void Test_IPv4AddressToNum(void)
{
    unsigned char Buffer[4];

    printf("IPv4AddressToNum\n");

    memset(Buffer, 0xAA, sizeof(Buffer));
    Check("\"1.2.3\" is rejected", IPv4AddressToNum("1.2.3", Buffer) < 0);
    Check("\"1.2.3\" left the buffer untouched",
          Buffer[0] == 0xAA && Buffer[3] == 0xAA);

    Check("\"999.1.1.1\" is rejected", IPv4AddressToNum("999.1.1.1", Buffer) < 0);
    Check("\"-1.1.1.1\" is rejected", IPv4AddressToNum("-1.1.1.1", Buffer) < 0);
    Check("\"\" is rejected", IPv4AddressToNum("", Buffer) < 0);

    Check("\"1.2.3.4\" is accepted", IPv4AddressToNum("1.2.3.4", Buffer) == 4);
    Check("\"1.2.3.4\" decodes correctly",
          Buffer[0] == 1 && Buffer[1] == 2 && Buffer[2] == 3 && Buffer[3] == 4);

    Check("\"255.255.255.255\" is accepted",
          IPv4AddressToNum("255.255.255.255", Buffer) == 4);
    Check("\"255.255.255.255\" decodes correctly",
          Buffer[0] == 255 && Buffer[3] == 255);
}

/*
 * An over-long "::" literal used to keep writing past the 16-byte output
 * buffer. Guard against a regression by placing canaries around it.
 */
static void Test_IPv6AddressToNumDoesNotOverflow(void)
{
    struct {
        unsigned char Head[8];
        unsigned char Addr[16];
        unsigned char Tail[8];
    } Guarded;

    printf("IPv6AddressToNum\n");

    memset(&Guarded, 0x5A, sizeof(Guarded));
    IPv6AddressToNum("1:2:3:4:5:6:7:8:9:10:11:12", Guarded.Addr);
    Check("over-long literal did not run past the buffer",
          Guarded.Tail[0] == 0x5A && Guarded.Tail[7] == 0x5A);
    Check("over-long literal did not run before the buffer",
          Guarded.Head[0] == 0x5A && Guarded.Head[7] == 0x5A);

    memset(&Guarded, 0x5A, sizeof(Guarded));
    IPv6AddressToNum("::", Guarded.Addr);
    Check("\"::\" yields the all-zero address",
          Guarded.Addr[0] == 0 && Guarded.Addr[15] == 0);
    Check("\"::\" respected the guards",
          Guarded.Head[7] == 0x5A && Guarded.Tail[0] == 0x5A);
}

/*
 * A missing or non-numeric port must fall back to the default instead of
 * leaving the port uninitialised.
 */
static void Test_AddressPortFallback(void)
{
    Address_Type Addr;

    printf("Address parsing\n");

    memset(&Addr, 0, sizeof(Addr));
    if( AddressList_ConvertFromString(&Addr, "1.2.3.4", 5353) == AF_INET )
    {
        Check("IPv4 without a port uses the default",
              ntohs(Addr.Addr.Addr4.sin_port) == 5353);
    } else {
        Check("IPv4 without a port parses", 0);
    }

    memset(&Addr, 0, sizeof(Addr));
    if( AddressList_ConvertFromString(&Addr, "1.2.3.4:", 5353) == AF_INET )
    {
        Check("IPv4 with an empty port uses the default",
              ntohs(Addr.Addr.Addr4.sin_port) == 5353);
    } else {
        Check("IPv4 with an empty port parses", 0);
    }

    memset(&Addr, 0, sizeof(Addr));
    if( AddressList_ConvertFromString(&Addr, "1.2.3.4:notanumber", 5353) == AF_INET )
    {
        Check("IPv4 with a non-numeric port uses the default",
              ntohs(Addr.Addr.Addr4.sin_port) == 5353);
    } else {
        Check("IPv4 with a non-numeric port parses", 0);
    }

    memset(&Addr, 0, sizeof(Addr));
    if( AddressList_ConvertFromString(&Addr, "1.2.3.4:5300", 53) == AF_INET )
    {
        Check("IPv4 with an explicit port honours it",
              ntohs(Addr.Addr.Addr4.sin_port) == 5300);
    } else {
        Check("IPv4 with an explicit port parses", 0);
    }
}

/*
 * GetAddressLength() must report the size of the concrete sockaddr, because
 * callers feed the result to memcpy()/connect(). A negative value would be
 * converted to a huge size_t.
 */
static void Test_GetAddressLength(void)
{
    printf("GetAddressLength\n");

    Check("AF_INET reports sizeof(struct sockaddr_in)",
          GetAddressLength(AF_INET) == (int)sizeof(struct sockaddr_in));
    Check("AF_INET6 reports sizeof(struct sockaddr_in6)",
          GetAddressLength(AF_INET6) == (int)sizeof(struct sockaddr_in6));
    Check("an unknown family never reports a negative length",
          GetAddressLength(AF_UNSPEC) > 0);
}

/*
 * The frontend receive buffers are reused across clients, and IHeader_Fill
 * only sets h->Type when a QUESTION record is present. A query with QDCOUNT
 * == 0 (no QUESTION) still succeeds, so without an explicit init the second
 * fill into the same buffer would inherit the previous request's h->Type.
 * That stale value then drives filter/hosts/cache decisions.
 *
 * Reproduce with the real layout: the IHeader lives at the front of the
 * receive buffer and the DNS message starts at sizeof(IHeader), exactly how
 * udpm.c / tcpfrontend.c hand the entity to IHeader_Fill.
 */
static void Test_IHeaderFillDoesNotLeakStaleType(void)
{
    char Buf[SOCKET_CONTEXT_LENGTH];
    IHeader *h = (IHeader *)Buf;
    char DnsMsg[256];
    int Len;

    printf("IHeader_Fill stale-type leakage\n");

    Len = BuildQuery(DnsMsg);   /* QDCOUNT = 1, type A */

    /* Normal query: place the DNS message where the frontend would. */
    memset(Buf, 0, sizeof(Buf));
    memcpy((char *)h + sizeof(IHeader), DnsMsg, Len);

    Check("first fill of a normal query succeeds",
          IHeader_Fill(h, FALSE, (char *)h + sizeof(IHeader), Len, NULL, 0, AF_INET, NULL) == 0);
    Check("first fill records type A",
          h->Type == DNS_TYPE_A);
    Check("first fill records the domain",
          strcmp(h->Domain, "a.bc") == 0);

    /* Now a QDCOUNT == 0 message into the SAME, un-memset buffer. */
    {
        static const unsigned char Empty[] = {
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        memcpy((char *)h + sizeof(IHeader), Empty, sizeof(Empty));
        Check("QDCOUNT=0 query is still accepted by IHeader_Fill",
              IHeader_Fill(h, FALSE, (char *)h + sizeof(IHeader), (int)sizeof(Empty), NULL, 0, AF_INET, NULL) == 0);
        Check("QDCOUNT=0 query does not leak the previous type",
              h->Type == DNS_TYPE_UNKNOWN);
        Check("QDCOUNT=0 query resets the domain",
              h->Domain[0] == '\0');
    }
}

int main(void)
{
    printf("== dnsparser / address helper regression tests ==\n\n");

    Test_ShortTcpBufferIsRejected();
    Test_TruncatedRecordIsRejected();
    Test_CompressionPointerLoop();
    Test_DNSGetHostNameRejectsOutOfRangeStart();
    Test_IPv4AddressToNum();
    Test_IPv6AddressToNumDoesNotOverflow();
    Test_AddressPortFallback();
    Test_GetAddressLength();
    Test_IHeaderFillDoesNotLeakStaleType();

    printf("\n%d checks, %d failure(s)\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
