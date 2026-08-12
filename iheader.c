#include <string.h>
#include "iheader.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "common.h"
#include "logs.h"
#include "tcpfrontend.h"

static BOOL ap = FALSE;

void IHeader_Reset(IHeader *h)
{
    h->Parent = NULL;
    h->RequestTcp = FALSE;
    h->Agent[0] = '\0';
    h->BackAddress.family = AF_UNSPEC;
    h->Domain[0] = '\0';
    h->HashValue = 0;
    h->EDNSEnabled = FALSE;
}

int IHeader_Fill(IHeader *h,
                 BOOL ReturnHeader, /* For tcp, this will be ignored */
                 char *DnsEntity,
                 int EntityLength,
                 const struct sockaddr *BackAddress, /* NULL for tcp */
                 SOCKET SendBackSocket,
                 sa_family_t Family, /* For tcp, this will be ignored */
                 const char *Agent
                 )
{
    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    h->Parent = NULL;
    h->RequestTcp = FALSE;
    h->EDNSEnabled = FALSE;

    /* The frontend receive buffers are reused across clients, and h->Type /
       h->Domain / h->HashValue are only set when a QUESTION record is parsed.
       A request with QDCOUNT == 0 (no QUESTION) still returns success from
       IHeader_Fill, so initialize them here to avoid leaking the previous
       request's values into downstream consumers (filter, hosts, cache). */
    h->Type = DNS_TYPE_UNKNOWN;
    h->Domain[0] = '\0';
    h->HashValue = 0;

    if( DnsSimpleParser_Init(&p, DnsEntity, EntityLength, FALSE) != 0 )
    {
        return -31;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        return -36;
    }

    while( i.Next(&i) != NULL )
    {
        switch( i.Purpose )
        {
        case DNS_RECORD_PURPOSE_QUESTION:
            if( i.Klass != DNS_CLASS_IN )
            {
                return -48;
            }

            if( i.GetName(&i, h->Domain, sizeof(h->Domain)) < 0 )
            {
                return -46;
            }

            StrToLower(h->Domain);
            h->HashValue = HASH(h->Domain, 0);
            h->Type = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(DnsEntity));
            break;

        case DNS_RECORD_PURPOSE_ADDITIONAL:
            if( i.Type == DNS_TYPE_OPT )
            {
                h->EDNSEnabled = TRUE;
            }
            break;

        default:
            break;
        }
    }

    h->ReturnHeader = ReturnHeader;

    if( BackAddress != NULL )
    {
        memcpy(&(h->BackAddress.Addr), BackAddress, GetAddressLength(Family));
        h->BackAddress.family = Family;
    } else {
        h->BackAddress.family = AF_UNSPEC;
    }

    h->SendBackSocket = SendBackSocket;

    if( Agent != NULL )
    {
        strncpy(h->Agent, Agent, sizeof(h->Agent));
        h->Agent[sizeof(h->Agent) - 1] = '\0';
    } else {
        h->Agent[0] = '\0';
    }

    h->EntityLength = EntityLength;

    return 0;
}


int MsgContext_Init(BOOL _ap)
{
    ap = _ap;

    return 0;
}

int MsgContext_AddFakeEdns(MsgContext *MsgCtx, int BufferLength)
{
    DnsGenerator g;
    IHeader *h = (IHeader *)MsgCtx;

    if( ap == FALSE || h->EDNSEnabled )
    {
        return 0;
    }

    if( DnsGenerator_Init(&g,
                          IHEADER_TAIL(h),
                          BufferLength - sizeof(IHeader),
                          IHEADER_TAIL(h),
                          h->EntityLength,
                          FALSE
                          )
        != 0 )
    {
        return -125;
    }

    /* DnsGenerator_Init() leaves the record counter on the *last non-empty*
       section of the copied request. When the request already carries
       additional records that section is ADDITIONAL, so there is nothing to
       advance: NextPurpose() would step past the additional-record counter and
       report UNKNOWN from then on, without ever moving again. The former
       unconditional `while( g.NextPurpose(&g) != ADDITIONAL );' therefore span
       forever at 100% CPU, wedging the frontend thread that called
       UdpM_Send(). A query with ARCOUNT > 0 whose additional section holds no
       OPT record (or is simply absent, since IHeader_Fill() tolerates a
       truncated additional section) is enough to trigger it whenever "AP" is
       enabled.

       Test the current section first and stop if the counter is not where it
       should be. */
    while( g.CurrentPurpose(&g) != DNS_RECORD_PURPOSE_ADDITIONAL )
    {
        if( g.NextPurpose(&g) == DNS_RECORD_PURPOSE_UNKNOWN )
        {
            return -126;
        }
    }

    g.EDns(&g, 1280);

    h->EntityLength = g.Length(&g);
    h->EDNSEnabled = TRUE;

    return 0;
}

BOOL MsgContext_IsBlocked(const MsgContext *MsgCtx)
{
    const IHeader *h = (IHeader *)MsgCtx;

    return (ap && !(h->EDNSEnabled));
}

BOOL MsgContext_IsFromTCP(const MsgContext *MsgCtx)
{
    IHeader *h = (IHeader *)MsgCtx;

    return (h->BackAddress.family == AF_UNSPEC);
}

int MsgContext_SendBack(MsgContext *MsgCtx)
{
    IHeader *h = (IHeader *)MsgCtx;
    char *Content = (char *)(IHEADER_TAIL(h));
    int Length = h->EntityLength;
    int SendResult;

    if( MsgContext_IsFromTCP(MsgCtx) )
    {
        /* TCP */
        Content -= 2;
        Length += 2;

        DNSSetTcpLength(Content, h->EntityLength);

        SendResult = (send(h->SendBackSocket,
                           Content,
                           Length,
                           MSG_NOSIGNAL
                           )
                      != Length);
    } else {
        /* UDP */
        if( h->ReturnHeader )
        {
            Content -= sizeof(IHeader);
            Length += sizeof(IHeader);
        }

        SendResult = (sendto(h->SendBackSocket,
                             Content,
                             Length,
                             MSG_NOSIGNAL,
                             (const struct sockaddr *)&(h->BackAddress.Addr),
                             GetAddressLength(h->BackAddress.family)
                             )
                        != Length);
    }

    /* The TCP client socket was dispatched to a module worker thread that owns
       this send; once we return the frontend may finally close it (and,
       eventually, reuse the descriptor for a different client). Release our
       hold so it does not tear the descriptor down while a later response is
       still being written, nor reuse it for the wrong client. No-op for UDP,
       whose descriptor is the shared server socket. */
    MsgContext_ReleaseSocket(MsgCtx);

    return SendResult ? (MsgContext_IsFromTCP(MsgCtx) ? -112 : -138) : 0;
}

/* Released exactly once per dispatched TCP query, after the socket is no
   longer needed by the module thread. For UDP the descriptor is the shared
   server socket and this is a no-op. */
void MsgContext_ReleaseSocket(MsgContext *MsgCtx)
{
    IHeader *h = (IHeader *)MsgCtx;

    if( MsgContext_IsFromTCP(MsgCtx) )
    {
        TcpFrontend_ReleaseSocket(h->SendBackSocket);
    }
}

int MsgContext_SendBackRefusedMessage(MsgContext *MsgCtx)
{
    IHeader *h = (IHeader *)MsgCtx;
    DNSHeader *RequestContent = IHEADER_TAIL(h);

    RequestContent->Flags.Direction = 1;
    RequestContent->Flags.RecursionAvailable = 1;
    RequestContent->Flags.ResponseCode = 0;

    return MsgContext_SendBack(MsgCtx);

}
