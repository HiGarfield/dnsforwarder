#include "dnsparser.h"
#include "dnsgenerator.h"
#include "utils.h"

char *DNSJumpOverName(char *NameStart)
{
    return NameStart + DNSGetHostName(NULL, INT_MAX, NameStart, NULL, 0);
}

/* Bounded counterpart of DNSJumpOverName().
 *
 * DNSJumpOverName() passes DNSBody == NULL and DNSBodyLength == INT_MAX,
 * which switches off every boundary check inside DNSGetHostName(): the only
 * thing that stops the walk is the 255-octet name cap or a terminating zero
 * octet. A truncated message whose name runs right up to the last byte
 * therefore makes the scan read past the end of the packet.
 *
 * Callers that know where the message ends must use this function instead.
 * It returns NULL when the name is malformed or would leave the message.
 */
char *DNSJumpOverNameSafe(const char *DNSBody, int DNSBodyLength, char *NameStart)
{
    int Length;

    if( DNSBody == NULL || NameStart == NULL || DNSBodyLength <= 0 )
    {
        return NULL;
    }

    if( NameStart < DNSBody || NameStart >= DNSBody + DNSBodyLength )
    {
        return NULL;
    }

    Length = DNSGetHostName(DNSBody, DNSBodyLength, NameStart, NULL, 0);
    if( Length < 0 )
    {
        return NULL;
    }

    /* The byte right after the name may legitimately be the end of the
       message, hence `>' and not `>='. */
    if( NameStart + Length > DNSBody + DNSBodyLength )
    {
        return NULL;
    }

    return NameStart + Length;
}

/* Labels length returned */
int DNSGetHostName(const char *DNSBody, int DNSBodyLength, const char *NameStart, char *buffer, int BufferLength)
{
    char *BufferItr = buffer;
    const char *NameItr = NameStart;
    int LabelsLength = 0;
    BOOL Redirected = FALSE;
    int RedirectCount = 0;
    /* Total wire length consumed by the encoded name, accumulated
       independently of `Redirected'. This bound holds even when DNSBody
       is NULL (e.g. the DNSJumpOverName helper), otherwise a name with
       no terminating 0x00 could be scanned far past the end of the
       message. RFC 1035 caps a domain name at 255 octets. */
    int TotalNameBytes = 0;
    int LabelCount = GET_8_BIT_U_INT(NameItr); /* The amount of characters of the next label */

    /* A DNS name (all labels + length octets, excluding the final root
       label) may never exceed 255 bytes per RFC 1035. Without this guard a
       malformed message with labels that point at each other could make us
       walk far past the end of the packet. */
    if( DNSBody != NULL && (NameStart < DNSBody || NameStart >= DNSBody + DNSBodyLength) )
    {
        return -1;
    }
    while( LabelCount != 0 )
    {
        if( DNSIsLabelPointerStart(LabelCount) )
        {
            int LabelPointer = 0;
            if( Redirected == FALSE )
            {
                LabelsLength += 2;
                Redirected = TRUE;
            }
            TotalNameBytes += 2;
            if( TotalNameBytes > 255 )
            {
                return -1;
            }
            /* A compression pointer needs two bytes, both of which must
               reside inside the message. These checks MUST run before the
               `buffer == NULL` early-out below, otherwise a caller that
               only wants to skip the name (e.g. DNSJumpOverName, which
               passes DNSBody == NULL) would bypass all boundary checks and
               keep reading past the end of the message. */
            if( DNSBody != NULL &&
                NameItr + 1 >= DNSBody + DNSBodyLength
                )
            {
                return -1;
            }
            LabelPointer = DNSLabelGetPointer(NameItr);
            /* The target offset must be a valid position inside the
               message. Note that an offset equal to the body length is
               already out of bounds. */
            if( LabelPointer < 0 || LabelPointer >= DNSBodyLength )
            {
                return -1;
            }
            /* Only meaningful when DNSBody is known: `DNSBody + LabelPointer`
               would be a NULL + non-zero offset (undefined behaviour) for the
               DNSJumpOverName helper, which passes DNSBody == NULL. */
            if( DNSBody != NULL && NameItr == DNSBody + LabelPointer )
            {
                // malformed, dead loop
                return -1;
            }
            /* Guard against malformed messages whose pointers reference
               each other in a cycle. Every redirection must consume at
               least two bytes of the message, therefore no valid message
               can redirect more than DNSBodyLength / 2 times. */
            ++RedirectCount;
            if( RedirectCount > DNSBodyLength / 2 )
            {
                // malformed, dead loop
                return -1;
            }
            if( buffer == NULL )
            {
                /* Caller only wants to compute the skipped length: a
                   compression pointer already accounts for the rest of
                   the name, so we are done. */
                break;
            }
            NameItr = DNSBody + LabelPointer;
        } else {
            /* The label occupies the length octet plus LabelCount data
               octets, and after skipping them the loop reads one more octet
               (the next label's length, or the terminating zero) at the end
               of this iteration. All of NameItr[0 .. 1 + LabelCount] must
               therefore be inside the message.
               The old test used `NameItr + LabelCount', which omitted both
               the length octet and that trailing read and so allowed a read
               up to two bytes past the end of a truncated message. */
            if( DNSBody != NULL &&
                NameItr + 1 + LabelCount > DNSBody + DNSBodyLength - 1
                )
            {
                return -1;
            }

            if( buffer != NULL )
            {
                if( BufferItr + LabelCount + 1 - buffer <= BufferLength )
                {
                    memcpy(BufferItr, NameItr + 1, LabelCount);
                } else {
                    if( BufferItr == buffer )
                    {
                        if( BufferLength > 0 )
                        {
                            *BufferItr = '\0';
                        }
                    } else {
                        *(BufferItr - 1) = '\0';
                    }
                    return -1;
                }
            }

            if( Redirected == FALSE )
            {
                LabelsLength += (LabelCount + 1);
            }
            TotalNameBytes += (1 + LabelCount);
            if( TotalNameBytes > 255 )
            {
                return -1;
            }
            NameItr += (1 + LabelCount);
            if( buffer != NULL )
            {
                BufferItr += LabelCount;
                *BufferItr = '.';
                ++BufferItr;
            }
        }

        LabelCount = GET_8_BIT_U_INT(NameItr);
    }

    if( buffer != NULL )
    {
        if( BufferItr == buffer )
        {
            if( BufferLength > 0 )
            {
                *BufferItr = '\0';
            } else {
                return -1;
            }
        } else {
            *(BufferItr - 1) = '\0';
        }
    }

    if( Redirected == FALSE )
    {
        ++LabelsLength;
    }

    return LabelsLength;
}

char *GetAllAnswers(char *DNSBody, int DNSBodyLength, char *Buffer, int BufferLength)
{
    DnsSimpleParser p;
    DnsSimpleParserIterator i;
    int ANACount;

    static const char *Tail = "   And       More ...\n";
    char *BufferItr = Buffer;
    int BufferLeft = BufferLength - strlen(Tail);

    if( BufferLeft <= 0 )
    {
        return NULL;
    }

    if( DnsSimpleParser_Init(&p, DNSBody, DNSBodyLength, FALSE) != 0 )
    {
        return NULL;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        return NULL;
    }

    ANACount = p.AnswerCount(&p) + p.NameServerCount(&p) + p.AdditionalCount(&p);

    if( ANACount == 0 )
    {
        if( BufferLength > (int)sizeof("   Nothing.\n") )
        {
            strcpy(BufferItr, "   Nothing.\n");
        }
        return Buffer;
    }

    i.GotoAnswers(&i);

    while( i.Next(&i) != NULL &&
           i.Purpose != DNS_RECORD_PURPOSE_QUESTION &&
           i.Purpose != DNS_RECORD_PURPOSE_UNKNOWN
         )
    {
        if( i.TextifyData(&i, "   %t: %v\n", BufferItr, BufferLeft) <= 0 )
        {
            snprintf(BufferItr,
                     (size_t)(BufferLength - (BufferItr - Buffer)),
                     "   And %d More ...\n", ANACount);

            break;
        } else {
            int StageLength = strlen(BufferItr);

            if( StageLength >= BufferLeft )
            {
                break;
            }

            BufferItr += StageLength;
            BufferLeft -= StageLength;

            --ANACount;
        }
    }

    return Buffer;
}

/* Full label length returned, including terminated-zero.
   Returns -1 if the message is malformed. */
int DNSCopyLable(const char *DNSBody,
                 int DNSBodyLength,
                 char *here,
                 const char *src
                 )
{
    int FullLength = 0;
    int RedirectCount = 0;

    if( DNSBody == NULL || src == NULL || DNSBodyLength <= 0 )
    {
        return -1;
    }

    while( TRUE )
    {
        /* Every byte read must lie inside the message. */
        if( src < DNSBody || src >= DNSBody + DNSBodyLength )
        {
            return -1;
        }

        if( DNSIsLabelPointerStart(GET_8_BIT_U_INT(src)) )
        {
            int LabelPointer;

            /* A compression pointer occupies two bytes. */
            if( src + 1 >= DNSBody + DNSBodyLength )
            {
                return -1;
            }

            LabelPointer = DNSLabelGetPointer(src);

            if( LabelPointer < 0 || LabelPointer >= DNSBodyLength )
            {
                return -1;
            }

            /* Guard against pointers referencing each other in a cycle.
               Each redirection consumes at least two bytes of the
               message, so a valid message cannot redirect more than
               DNSBodyLength / 2 times. */
            ++RedirectCount;
            if( RedirectCount > DNSBodyLength / 2 )
            {
                return -1;
            }

            src = DNSBody + LabelPointer;
        } else {
            ++FullLength;

            if( here != NULL )
            {
                *here = *src;
                ++here;
            }

            if( *src == '\0' )
            {
                break;
            }

            ++src;
        }
    }

    return FullLength;
}

/**
  New Implementation
*/

/* Converted to host byte order */
static uint16_t DnsSimpleParser_QueryIdentifier(const DnsSimpleParser *p)
{
    return DNSGetQueryIdentifier(p->RawDns);
}

static DnsDirection DnsSimpleParser_Flags_Direction(const DnsSimpleParser *p)
{
    return (DnsDirection)(p->_Flags.Flags->Direction);
}

static DnsOperation DnsSimpleParser_Flags_Operation(const DnsSimpleParser *p)
{
    return (DnsOperation)(p->_Flags.Flags->Type);
}

static BOOL DnsSimpleParser_Flags_IsAuthoritative(const DnsSimpleParser *p)
{
    return !!(p->_Flags.Flags->AuthoritativeAnswer);
}

static BOOL DnsSimpleParser_Flags_Truncated(const DnsSimpleParser *p)
{
    return !!(p->_Flags.Flags->TrunCation);
}

static BOOL DnsSimpleParser_Flags_RecursionDesired(const DnsSimpleParser *p)
{
    return !!(p->_Flags.Flags->RecursionDesired);
}

static BOOL DnsSimpleParser_Flags_RecursionAvailable(const DnsSimpleParser *p)
{
    return !!(p->_Flags.Flags->RecursionAvailable);
}

static ResponseCode DnsSimpleParser_Flags_ResponseCode(const DnsSimpleParser *p)
{
    return (ResponseCode)(p->_Flags.Flags->ResponseCode);
}

static int DnsSimpleParser_QuestionCount(const DnsSimpleParser *p)
{
    return DNSGetQuestionCount(p->RawDns);
}

static int DnsSimpleParser_AnswerCount(const DnsSimpleParser *p)
{
    return DNSGetAnswerCount(p->RawDns);
}

static int DnsSimpleParser_NameServerCount(const DnsSimpleParser *p)
{
    return DNSGetNameServerCount(p->RawDns);
}

static int DnsSimpleParser_AdditionalCount(const DnsSimpleParser *p)
{
    return DNSGetAdditionalCount(p->RawDns);
}

static BOOL DnsSimpleParser_HasType(const DnsSimpleParser *p,
                                    DnsRecordPurpose Purpose,
                                    DNSRecordClass Klass,
                                    DNSRecordType Type
                                    )
{
    DnsSimpleParserIterator i;

    if( DnsSimpleParserIterator_Init(&i, (DnsSimpleParser *)p) != 0 )
    {
        return FALSE;
    }

    while( i.Next(&i) != NULL )
    {
        if( (Purpose == DNS_RECORD_PURPOSE_UNKNOWN || i.Purpose == Purpose) &&
            (Klass == DNS_CLASS_UNKNOWN || i.Klass == Klass) &&
             i.Type == Type
             )
        {
            return TRUE;
        }
    }

    return FALSE;
}

int DnsSimpleParser_Init(DnsSimpleParser *p,
                         char *RawDns,
                         int Length,
                         BOOL IsTcp)
{
    if( RawDns == NULL || Length < DNS_HEADER_LENGTH )
    {
        return -1;
    }

    /* For TCP the first two octets are the length prefix and are stripped
       below, so the *remaining* bytes - not the raw ones already checked
       above - must still hold a full header. Without this second check a
       12..13 byte TCP buffer would produce a RawDnsLength of 10 or 11 and
       every subsequent bounds test would be computed against a body that is
       shorter than the header the parser unconditionally reads. */
    if( IsTcp && Length - 2 < DNS_HEADER_LENGTH )
    {
        return -1;
    }

    if( IsTcp )
    {
        p->RawDns = RawDns + 2;
        p->RawDnsLength = Length - 2;
    } else {
        p->RawDns = RawDns;
        p->RawDnsLength = Length;
    }

    p->_Flags.Flags = (DNSFlags *)(p->RawDns + 2);

    p->QueryIdentifier = DnsSimpleParser_QueryIdentifier;

    p->_Flags.Direction = DnsSimpleParser_Flags_Direction;
    p->_Flags.Operation = DnsSimpleParser_Flags_Operation;
    p->_Flags.IsAuthoritative = DnsSimpleParser_Flags_IsAuthoritative;
    p->_Flags.Truncated = DnsSimpleParser_Flags_Truncated;
    p->_Flags.RecursionDesired = DnsSimpleParser_Flags_RecursionDesired;
    p->_Flags.RecursionAvailable = DnsSimpleParser_Flags_RecursionAvailable;
    p->_Flags.ResponseCode = DnsSimpleParser_Flags_ResponseCode;

    p->QuestionCount = DnsSimpleParser_QuestionCount;
    p->AnswerCount = DnsSimpleParser_AnswerCount;
    p->NameServerCount = DnsSimpleParser_NameServerCount;
    p->AdditionalCount = DnsSimpleParser_AdditionalCount;
    p->HasType = DnsSimpleParser_HasType;

    return 0;
}

/**
  Iterator
*/
static DnsRecordPurpose DnsSimpleParserIterator_DeterminePurpose(
                                                    const DnsSimpleParserIterator *i,
                                                    int RecordPosition)
{
    if( i->QuestionFirst != 0 &&
        RecordPosition >= i->QuestionFirst &&
        RecordPosition <= i->QuestionLast
      )
    {
        return DNS_RECORD_PURPOSE_QUESTION;
    }

    if( i->AnswerFirst != 0 &&
        RecordPosition >= i->AnswerFirst &&
        RecordPosition <= i->AnswerLast
      )
    {
        return DNS_RECORD_PURPOSE_ANSWER;
    }

    if( i->NameServerFirst != 0 &&
        RecordPosition >= i->NameServerFirst &&
        RecordPosition <= i->NameServerLast
      )
    {
        return DNS_RECORD_PURPOSE_NAME_SERVER;
    }

    if( i->AdditionalFirst != 0 &&
        RecordPosition >= i->AdditionalFirst &&
        RecordPosition <= i->AdditionalLast
      )
    {
        return DNS_RECORD_PURPOSE_ADDITIONAL;
    }

    return DNS_RECORD_PURPOSE_UNKNOWN;
}

static char *DnsSimpleParserIterator_Next(DnsSimpleParserIterator *i)
{
    if( i->CurrentPosition == NULL )
    {
        i->CurrentPosition = i->Parser->RawDns + DNS_HEADER_LENGTH;
        i->RecordPosition = 1;
    } else if( i->RecordPosition < i->AllRecordCount ){
        /* The record length excluding its labeled name at the beginning. */
        int ExLength = i->Purpose == DNS_RECORD_PURPOSE_QUESTION ?
                       /* For a question record, there are only 4 bytes */
                       4 :
                       /* For an other types of record, there are many things */
                       10 + i->DataLength;

        /* The length of all labels in the beginning of current record
           plus `ExLength'
         */

        /* Pass the real message body so DNSGetHostName performs its
           out-of-bounds checks (compression-pointer redirection in
           particular). Using NULL here skipped those checks and could
           dereference an absolute address built from the pointer value. */
        int FullLength = DNSGetHostName(i->Parser->RawDns,
                                            i->Parser->RawDnsLength,
                                            i->CurrentPosition,
                                            NULL,
                                            0)
                         + ExLength;

        if( FullLength < ExLength )
        {
            return NULL;
        }

        i->CurrentPosition += FullLength;

        i->RecordPosition += 1;
    } else {
        i->CurrentPosition = NULL;
        i->RecordPosition = 0;
        return NULL;
    }

    /* `>=' rather than `>': a record that starts exactly at the end of the
       buffer has no bytes at all, and the accessors below unconditionally
       read the 2-byte type and the 2-byte class after the name. The old `>'
       accepted that position and read past the end of the packet. */
    if( (i->RecordPosition > i->AllRecordCount) ||
        (i->CurrentPosition - i->Parser->RawDns >= i->Parser->RawDnsLength)
      )
    {
        i->CurrentPosition = NULL;
        i->RecordPosition = 0;
        return NULL;
    }

    /* Update record informations */
    i->Purpose =  DnsSimpleParserIterator_DeterminePurpose(i, i->RecordPosition);

    /* DNSGetRecordType()/DNSGetRecordClass() jump over the name and then read
       4 bytes (type + class). Verify that those bytes, and for a resource
       record the TTL and RDLENGTH that follow, are really inside the message
       before touching them. */
    {
        char *AfterName = DNSJumpOverNameSafe(i->Parser->RawDns,
                                              i->Parser->RawDnsLength,
                                              i->CurrentPosition);
        const char *End = i->Parser->RawDns + i->Parser->RawDnsLength;
        int NeedAfterName =
            i->Purpose == DNS_RECORD_PURPOSE_QUESTION ? 4 : 10;

        if( AfterName == NULL || End - AfterName < NeedAfterName )
        {
            i->CurrentPosition = NULL;
            i->RecordPosition = 0;
            return NULL;
        }
    }

    i->Type = DNSGetRecordType(i->CurrentPosition);
    i->Klass = DNSGetRecordClass(i->CurrentPosition);

    if( i->Purpose != DNS_RECORD_PURPOSE_UNKNOWN &&
        i->Type != DNS_TYPE_UNKNOWN &&
        i->Klass != DNS_CLASS_UNKNOWN
      )
    {
        if( i->Purpose != DNS_RECORD_PURPOSE_QUESTION )
        {
            i->DataLength = DNSGetResourceDataLength(i->CurrentPosition);

            /* The RDATA must stay inside the message. A lying RDLENGTH
               would otherwise let subsequent parsers read past the end
               of the packet. */
            const char *RDataPos = DNSGetResourceDataPos(i->CurrentPosition);
            if( RDataPos == NULL ||
                RDataPos + i->DataLength > i->Parser->RawDns + i->Parser->RawDnsLength )
            {
                i->CurrentPosition = NULL;
                i->RecordPosition = 0;
                return NULL;
            }
        }

        return i->CurrentPosition;
    } else {
        i->CurrentPosition = NULL;
        i->RecordPosition = 0;
        return NULL;
    }
}

static void DnsSimpleParserIterator_GotoAnswers(DnsSimpleParserIterator *i)
{
    i->CurrentPosition = NULL;

    if( i->QuestionFirst > 0 )
    {
        while( DnsSimpleParserIterator_Next(i) != NULL )
        {
            if( i->RecordPosition == i->QuestionLast )
            {
                break;
            }
        }
    }
}

static int DnsSimpleParserIterator_GetName(DnsSimpleParserIterator *i,
                                       char *Buffer, /* Could be NULL */
                                       int BufferLength
                                       )
{
    return DNSGetHostName(i->Parser->RawDns,
                          i->Parser->RawDnsLength,
                          i->CurrentPosition,
                          Buffer,
                          BufferLength
                          );
}

static char *DnsSimpleParserIterator_RowData(DnsSimpleParserIterator *i)
{
    if( i->Purpose != DNS_RECORD_PURPOSE_QUESTION )
    {
        return DNSGetResourceDataPos(i->CurrentPosition);
    } else {
        return NULL;
    }
}

/* Field Processors
   `Format == NULL` means copying to cache.
   Textify: Return unpacked string length, without NULL;
   ToCache: Return unpacked data length, including NULL for string;
   negative means error.
*/

typedef int (*FieldParser)(DnsSimpleParserIterator *i,
                           const char *Data,
                           int *DataLength,
                           const char *Format,
                           char *Buffer,
                           int BufferLength,
                           const char *Preface
                           );

static int DnsSimpleParserIterator_Parse16Uint(DnsSimpleParserIterator *i,
                                               const char *Data,
                                               int *DataLength,
                                               const char *Format,
                                               char *Buffer,
                                               int BufferLength,
                                               const char *Preface
                                               )
{
    char Example[] = "4294967295";
    uint32_t    u;

    BOOL IsToCache = Format == NULL;

    if( IsToCache )
    {
        if( 2 > BufferLength )
        {
            return -1;
        }
        memcpy(Buffer, Data, 2);
        *DataLength -= 2;
        return 2;
    }

    if( BufferLength <= 0 || strlen(Format) + 1 > (size_t)BufferLength )
    {
        return -1;
    }

    if( Preface == NULL )
    {
        Preface = "";
    }

    strcpy(Buffer, Format);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%t",
                                      Preface,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    u = GET_16_BIT_U_INT(Data);

    sprintf(Example, "%d", (int)u);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%v",
                                      Example,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    *DataLength -= 2;
    return strlen(Buffer);
}

static int DnsSimpleParserIterator_Parse32Uint(DnsSimpleParserIterator *i,
                                               const char *Data,
                                               int *DataLength,
                                               const char *Format,
                                               char *Buffer,
                                               int BufferLength,
                                               const char *Preface
                                               )
{
    char Example[] = "4294967295";
    uint32_t    u;

    BOOL IsToCache = Format == NULL;

    if( IsToCache )
    {
        if( 4 > BufferLength )
        {
            return -1;
        }
        memcpy(Buffer, Data, 4);
        *DataLength -= 4;
        return 4;
    }

    if( BufferLength <= 0 || strlen(Format) + 1 > (size_t)BufferLength )
    {
        return -1;
    }

    if( Preface == NULL )
    {
        Preface = "";
    }

    strcpy(Buffer, Format);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%t",
                                      Preface,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    u = GET_32_BIT_U_INT(Data);

    sprintf(Example, "%u", u);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%v",
                                      Example,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    *DataLength -= 4;
    return strlen(Buffer);
}

static int DnsSimpleParserIterator_ParseIPv4(DnsSimpleParserIterator *i,
                                             const char *Data,
                                             int *DataLength,
                                             const char *Format,
                                             char *Buffer,
                                             int BufferLength,
                                             const char *Preface
                                             )
{
    char Example[LENGTH_OF_IPV4_ADDRESS_ASCII];

    BOOL IsToCache = Format == NULL;

    if( IsToCache )
    {
        if( 4 > BufferLength )
        {
            return -1;
        }
        memcpy(Buffer, Data, 4);
        *DataLength -= 4;
        return 4;
    }

    if( BufferLength <= 0 || strlen(Format) + 1 > (size_t)BufferLength )
    {
        return -1;
    }

    if( Preface == NULL )
    {
        Preface = "";
    }

    strcpy(Buffer, Format);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%t",
                                      Preface,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    IPv4AddressToAsc(Data, Example);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%v",
                                      Example,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    *DataLength -= 4;
    return strlen(Buffer);
}

static int DnsSimpleParserIterator_ParseIPv6(DnsSimpleParserIterator *i,
                                             const char *Data,
                                             int *DataLength,
                                             const char *Format,
                                             char *Buffer,
                                             int BufferLength,
                                             const char *Preface
                                             )
{
    char Example[LENGTH_OF_IPV6_ADDRESS_ASCII + 1];

    BOOL IsToCache = Format == NULL;

    if( IsToCache )
    {
        if( 16 > BufferLength )
        {
            return -1;
        }
        memcpy(Buffer, Data, 16);
        *DataLength -= 16;
        return 16;
    }

    if( BufferLength <= 0 || strlen(Format) + 1 > (size_t)BufferLength )
    {
        return -1;
    }

    if( Preface == NULL )
    {
        Preface = "";
    }

    strcpy(Buffer, Format);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%t",
                                      Preface,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    IPv6AddressToAsc(Data, Example);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%v",
                                      Example,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    *DataLength -= 16;
    return strlen(Buffer);
}

/* <domain-name>: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3 */
static int DnsSimpleParserIterator_UnpackLabeledName(DnsSimpleParserIterator *i,
                                                     const char *Data,
                                                     int *DataLength,
                                                     const char *Format,
                                                     char *Buffer,
                                                     int BufferLength,
                                                     const char *Preface
                                                     )
{
    char HostName[253 + 1];
    int LabelLength;

    BOOL IsToCache = Format == NULL;

    if( IsToCache )
    {
        Format = "%v";
    }

    if( BufferLength <= 0 || strlen(Format) + 1 > (size_t)BufferLength )
    {
        return -1;
    }

    strcpy(Buffer, Format);

    if( Preface == NULL )
    {
        Preface = "";
    }

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%t",
                                      Preface,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    LabelLength = DNSGetHostName(i->Parser->RawDns,
                                 i->Parser->RawDnsLength,
                                 Data,
                                 HostName,
                                 sizeof(HostName)
                                 );

    if( LabelLength < 0 )
    {
        *Buffer = '\0';
        return -1;
    }

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%v",
                                      HostName,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    *DataLength -= LabelLength;
    LabelLength = strlen(Buffer);
    if( IsToCache )
    {
        LabelLength += 1;
    }
    return LabelLength;
}

/* RR Parsers */

typedef int (*RRParser)(DnsSimpleParserIterator *i,
                        const char *Data,
                        const char *Format,
                        char *Buffer,
                        int BufferLength
                        );

static int DnsSimpleParserIterator_ParseA(DnsSimpleParserIterator *i,
                                          const char *Data,
                                          const char *Format,
                                          char *Buffer,
                                          int BufferLength
                                          )
{
    int DataLength = i->DataLength;
    return DnsSimpleParserIterator_ParseIPv4(i,
                                             Data,
                                             &DataLength,
                                             Format,
                                             Buffer,
                                             BufferLength,
                                             "IPv4 Address"
                                             );
}

static int DnsSimpleParserIterator_ParseAAAA(DnsSimpleParserIterator *i,
                                             const char *Data,
                                             const char *Format,
                                             char *Buffer,
                                             int BufferLength
                                             )
{
    int DataLength = i->DataLength;
    return DnsSimpleParserIterator_ParseIPv6(i,
                                             Data,
                                             &DataLength,
                                             Format,
                                             Buffer,
                                             BufferLength,
                                             "IPv6 Address"
                                             );
}

static int DnsSimpleParserIterator_ParseCName(DnsSimpleParserIterator *i,
                                              const char *Data,
                                              const char *Format,
                                              char *Buffer,
                                              int BufferLength
                                              )
{
    int DataLength = i->DataLength;
    return DnsSimpleParserIterator_UnpackLabeledName(i,
                                                     Data,
                                                     &DataLength,
                                                     Format,
                                                     Buffer,
                                                     BufferLength,
                                                     DNSGetTypeName(i->Type)
                                                     );
}

typedef struct {
    const char *Preface;
    FieldParser ps;
} ParserProjector;

static int DnsSimpleParserIterator_ParseData(DnsSimpleParserIterator *i,
                                             const char *Data,
                                             const char *Format,
                                             char *Buffer,
                                             int BufferLength,
                                             const ParserProjector *pp
                                             )
{
    const char *DataItr = Data;
    int LeftDataLength = i->DataLength;

    char *BufferItr = Buffer;
    int LeftBufferLength = BufferLength;

    int j = 0;

    while( pp[j].Preface != NULL && LeftDataLength > 0 )
    {
        int n = pp[j].ps(i,
                         DataItr,
                         &LeftDataLength,
                         Format,
                         BufferItr,
                         LeftBufferLength,
                         pp[j].Preface
                         );
        if( n <= 0 )
        {
            return n;
        } else {
            BufferItr += n;
            LeftBufferLength -= n;

            DataItr = Data + i->DataLength - LeftDataLength;
            ++j;
        }
    }

    return BufferItr - Buffer;
}

static int DnsSimpleParserIterator_ParseSOA(DnsSimpleParserIterator *i,
                                            const char *Data,
                                            const char *Format,
                                            char *Buffer,
                                            int BufferLength
                                            )
{
    const ParserProjector pp[] = {
        {"(SOA)primary name server", DnsSimpleParserIterator_UnpackLabeledName},
        {"(SOA)responsible mail addr", DnsSimpleParserIterator_UnpackLabeledName},
        {"(SOA)serial", DnsSimpleParserIterator_Parse32Uint},
        {"(SOA)refresh", DnsSimpleParserIterator_Parse32Uint},
        {"(SOA)retry", DnsSimpleParserIterator_Parse32Uint},
        {"(SOA)expire", DnsSimpleParserIterator_Parse32Uint},
        {"(SOA)default TTL", DnsSimpleParserIterator_Parse32Uint},
        {NULL, NULL},
    };

    return DnsSimpleParserIterator_ParseData(i,
                                             Data,
                                             Format,
                                             Buffer,
                                             BufferLength,
                                             pp
                                             );
}

static int DnsSimpleParserIterator_ParseMailEx(DnsSimpleParserIterator *i,
                                               const char *Data,
                                               const char *Format,
                                               char *Buffer,
                                               int BufferLength
                                               )
{
    const ParserProjector pp[] = {
        {"preference", DnsSimpleParserIterator_Parse16Uint},
        {"mail exchanger", DnsSimpleParserIterator_UnpackLabeledName},
        {NULL, NULL},
    };

    return DnsSimpleParserIterator_ParseData(i,
                                             Data,
                                             Format,
                                             Buffer,
                                             BufferLength,
                                             pp
                                             );
}

static int DNSRRGetString(const char *Data,
                          int DataLength,
                          char *Buffer,
                          int BufferLength
                          )
{
    const char *DataItr = Data;

    char *BufferItr = Buffer;
    int BufferLeft = BufferLength;

    while( DataItr < Data + DataLength )
    {
        int n = GET_8_BIT_U_INT(DataItr);

        /* The length byte itself must fit, and the payload must not
           overflow either the destination buffer or the source RDATA. */
        if( n + 1 > BufferLeft ||
            DataItr + 1 + n > Data + DataLength )
        {
            return -1;
        }

        memcpy(BufferItr, DataItr + 1, n);

        DataItr += 1 + n;

        BufferItr += n;
        BufferLeft -= n;
    }

    if( BufferLeft <= 0 )
    {
        return -1;
    }
    *BufferItr = '\0';

    return BufferItr - Buffer;
}

/* exceed 255 octets: https://datatracker.ietf.org/doc/html/rfc7208#autoid-25 */
static int DnsSimpleParserIterator_ParseTxt(DnsSimpleParserIterator *i,
                                            const char *Data,
                                            const char *Format,
                                            char *Buffer,
                                            int BufferLength
                                            )
{
    char Example[256];
    char *Resulting;

    int ret = -1;

    if( BufferLength <= 0 || strlen(Format) + 1 > (size_t)BufferLength )
    {
        return 0;
    }

    strcpy(Buffer, Format);

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%t",
                                      "TXT",
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    if( i->DataLength >= (int)sizeof(Example) )
    {
        Resulting = SafeMalloc((size_t)i->DataLength + 1);
    } else {
        Resulting = Example;
    }

    if( Resulting == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    /* Pass the *actual* capacity of `Resulting`: it is either the on-stack
     * `Example` buffer (256 bytes) or a heap buffer of size i->DataLength + 1.
     * Passing sizeof(Example) unconditionally wrongly capped the limit at 256
     * and rejected valid TXT records whose RDATA is exactly 256 octets. */
    {
        int ResultingSize = (i->DataLength >= (int)sizeof(Example))
                            ? (int)i->DataLength + 1
                            : (int)sizeof(Example);

        if( DNSRRGetString(Data, i->DataLength, Resulting, ResultingSize) < 0 )
        {
            *Buffer = '\0';
            goto EXIT;
        }
    }

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%v",
                                      Resulting,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        goto EXIT;
    }
    ret = strlen(Buffer) + 1;

EXIT:
    if( Resulting != Example )
    {
        SafeFree(Resulting);
    }
    return ret;
}

static int DnsSimpleParserIterator_ParseRaw(DnsSimpleParserIterator *i,
                                            const char *Data,
                                            const char *Format,
                                            char *Buffer,
                                            int BufferLength
                                            )
{
    char a[] = "UNKNOWN (65535)";
    const char *TypeName = DNSGetTypeName(i->Type);

    BOOL IsToCache = Format == NULL;

    if( IsToCache )
    {
        return -1;
    }

    if( BufferLength <= 0 || strlen(Format) + 1 > (size_t)BufferLength )
    {
        return -1;
    }

    strcpy(Buffer, Format);

    if( TypeName == NULL || strcmp(TypeName, DNS_TYPENAME_UNKNOWN) == 0 )
    {
        sprintf(a, "UNKNOWN (%d)", (int)(i->Type & 0xffff));
        TypeName = (const char *)a;
    }

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%t",
                                      TypeName,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    if( i->Type != DNS_TYPE_OPT )
    {
        sprintf(a, "%d bytes", (int)(i->DataLength & 0xffff));
        Data = (const char *)a;
    } else {
        Data = "Pseudo-RR";
    }

    if( ReplaceStr_WithLengthChecking(Buffer,
                                      "%v",
                                      Data,
                                      BufferLength
                                      )
       == NULL )
    {
        *Buffer = '\0';
        return -1;
    }

    return strlen(Buffer);
}

/* Number of items generated returned */
static int DnsSimpleParserIterator_TextifyData(DnsSimpleParserIterator *i,
                                               const char *Format,
                                               char *Buffer,
                                               int BufferLength
                                               )
{
    const char *Data = DNSGetResourceDataPos(i->CurrentPosition);

    RRParser RecordParser = NULL;

    if( i->Type != DNS_TYPE_OPT &&
        i->Klass != DNS_CLASS_IN
        )
    {
        return 0; /* Unparsable */
    }

    switch( i->Type )
    {
    case DNS_TYPE_A:
        RecordParser = DnsSimpleParserIterator_ParseA;
        break;

    case DNS_TYPE_AAAA:
        RecordParser = DnsSimpleParserIterator_ParseAAAA;
        break;

    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
    case DNS_TYPE_NS:
        RecordParser = DnsSimpleParserIterator_ParseCName;
        break;

    case DNS_TYPE_TXT:
        RecordParser = DnsSimpleParserIterator_ParseTxt;
        break;

    case DNS_TYPE_MX:
        RecordParser = DnsSimpleParserIterator_ParseMailEx;
        break;

    case DNS_TYPE_SOA:
        RecordParser = DnsSimpleParserIterator_ParseSOA;
        break;

    default:
        RecordParser = DnsSimpleParserIterator_ParseRaw;
        break;
    }

    return RecordParser(i,
                        Data,
                        Format,
                        Buffer,
                        BufferLength
                        );
}

/* length of CacheData returned */
static int DnsSimpleParserIterator_ToCacheData(DnsSimpleParserIterator *i,
                                               char *Buffer,
                                               int BufferLength
                                               )
{
    const char *Data = DNSGetResourceDataPos(i->CurrentPosition);

    RRParser RecordParser = NULL;

    if( i->Type != DNS_TYPE_OPT &&
        i->Klass != DNS_CLASS_IN
        )
    {
        return 0; /* Unparsable */
    }

    switch( i->Type )
    {
    case DNS_TYPE_A:
    case DNS_TYPE_AAAA:
    case DNS_TYPE_HTTPS:
    case DNS_TYPE_TXT:
        RecordParser = NULL;
        break;

    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
    case DNS_TYPE_NS:
        RecordParser = DnsSimpleParserIterator_ParseCName;
        break;

    case DNS_TYPE_MX:
        RecordParser = DnsSimpleParserIterator_ParseMailEx;
        break;

    case DNS_TYPE_SOA:
        RecordParser = DnsSimpleParserIterator_ParseSOA;
        break;

    default:
        return -1;
    }

    if( RecordParser != NULL )
    {
        return RecordParser(i,
                            Data,
                            NULL,
                            Buffer,
                            BufferLength
                            );

    } else {
        if( i->DataLength >= BufferLength )
        {
            return 0;
        }
        memcpy(Buffer, Data, i->DataLength);
        return i->DataLength;
    }
}

static uint32_t DnsSimpleParserIterator_GetTTL(DnsSimpleParserIterator *i)
{
    return DNSGetTTL(i->CurrentPosition);
}

int DnsSimpleParserIterator_Init(DnsSimpleParserIterator *i, DnsSimpleParser *p)
{
    int QuestionCount, AnswerCount, NameServerCount, AdditionalCount;

    if( i == NULL || p == NULL )
    {
        return -1;
    }

    QuestionCount = p->QuestionCount(p);
    AnswerCount = p->AnswerCount(p);
    NameServerCount = p->NameServerCount(p);
    AdditionalCount = p->AdditionalCount(p);

    i->Parser = p;
    i->CurrentPosition = NULL;
    i->RecordPosition = 0;

    i->AllRecordCount = QuestionCount +
                        AnswerCount +
                        NameServerCount +
                        AdditionalCount;

    i->QuestionFirst = QuestionCount == 0 ? -1 : 1;
    i->QuestionLast = QuestionCount == 0 ? -1 : QuestionCount;

    /* Record positions are 1-based. An absent section uses -1 as a sentinel so
     * that its range check can never match a valid (>= 1) record position.
     * Using 0 as the "absent" sentinel previously collided with the valid
     * position when the preceding section had a count of 0, which caused the
     * following (non-empty) section to be mis-classified as UNKNOWN and made
     * iteration stop after the first record. */
    i->AnswerFirst = AnswerCount == 0 ?
                     -1 :
                     QuestionCount + 1;
    i->AnswerLast = AnswerCount == 0 ? -1 : QuestionCount + AnswerCount;

    i->NameServerFirst = NameServerCount == 0 ?
                         -1 :
                         QuestionCount + AnswerCount + 1;
    i->NameServerLast = NameServerCount == 0 ?
                        -1 :
                        QuestionCount + AnswerCount + NameServerCount;

    i->AdditionalFirst = AdditionalCount == 0 ?
                         -1 :
                         QuestionCount + AnswerCount + NameServerCount + 1;
    i->AdditionalLast = AdditionalCount == 0 ?
                        -1 :
                        QuestionCount + AnswerCount + NameServerCount + AdditionalCount;

    i->Next = DnsSimpleParserIterator_Next;
    i->GotoAnswers = DnsSimpleParserIterator_GotoAnswers;
    i->GetName = DnsSimpleParserIterator_GetName;
    i->RowData = DnsSimpleParserIterator_RowData;
    i->TextifyData = DnsSimpleParserIterator_TextifyData;
    i->ToCacheData = DnsSimpleParserIterator_ToCacheData;
    i->GetTTL = DnsSimpleParserIterator_GetTTL;

    return 0;
}
