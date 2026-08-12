#ifndef _DNS_GENERATOR_H_
#define _DNS_GENERATOR_H_

#include <string.h>
#include "dnsparser.h"
#include "array.h"
#include "stringlist.h"
#include "common.h"

/* Write network-order integers through memcpy instead of a cast, which
   would violate strict aliasing and fault on CPUs that require aligned
   access (the same class of defect already fixed on the getter side in
   dnsparser.h). */
#define SET_16_BIT_U_INT(here, val) \
    do { uint16_t _v = htons((uint16_t)(val)); memcpy((here), &_v, 2); } while(0)
#define SET_32_BIT_U_INT(here, val) \
    do { uint32_t _v = htonl((uint32_t)(val)); memcpy((here), &_v, 4); } while(0)

/* Handle DNS header*/
#define DNSSetTcpLength(dns_start, Len)         SET_16_BIT_U_INT((char *)(dns_start), Len)

#define DNSSetQueryIdentifier(dns_start, QId)   SET_16_BIT_U_INT((char *)(dns_start), QId)

#define DNSCopyQueryIdentifier(dst, src) \
    do { uint16_t _v; memcpy(&_v, (src), 2); memcpy((dst), &_v, 2); } while(0)

#define DNSSetFlags(dns_start, Flags)           SET_16_BIT_U_INT((char *)(dns_start) + 2, Flags)

#define DNSSetQuestionCount(dns_start, QC)      SET_16_BIT_U_INT((char *)(dns_start) + 4, QC)

#define DNSSetAnswerCount(dns_start, AnC)       SET_16_BIT_U_INT((char *)(dns_start) + 6, AnC)

#define DNSSetNameServerCount(dns_start, ASC)   SET_16_BIT_U_INT((char *)(dns_start) + 8, ASC)

#define DNSSetAdditionalCount(dns_start, AdC)   SET_16_BIT_U_INT((char *)(dns_start) + 10, AdC)

#define DNSLabelMakePointer(pointer_ptr, location)  (((unsigned char *)(pointer_ptr))[0] = (192 + (location) / 256), ((unsigned char *)(pointer_ptr))[1] = (location) % 256)

char *DNSLabelizedName(__inout char *Origin, __in size_t OriginSpaceLength);

int DNSCompress(__inout char *DNSBody, __in int DNSBodyLength);

/**
  New Implementation
*/

typedef struct _DnsGenerator DnsGenerator;

struct _DnsGenerator {
    /* private */
    char *Buffer;
    int BufferLength;
    char *Itr;

    void *NumberOfRecords;

    /* public */
    DNSHeader *Header;

    int (*Length)(const DnsGenerator *g);

    /* Section the record counter currently points at. Needed to test where a
       generator starts before blindly advancing with NextPurpose(), which
       cannot walk backwards and reports UNKNOWN once it has stepped past the
       additional-record counter. */
    DnsRecordPurpose (*CurrentPurpose)(DnsGenerator *g);
    DnsRecordPurpose (*NextPurpose)(DnsGenerator *g);
    void (*CopyHeader)(DnsGenerator *g,
                       const char *Source,
                       BOOL IncludeRecordCounts
                       );
    void (*SetIdentifier)(DnsGenerator *g, uint16_t Value);
    int (*CopyCName)(DnsGenerator *g, DnsSimpleParserIterator *i);
    int (*CopyA)(DnsGenerator *g, DnsSimpleParserIterator *i);
    int (*CopyAAAA)(DnsGenerator *g, DnsSimpleParserIterator *i);

    int (*Question)(DnsGenerator *g,
                    const char *Name,
                    DNSRecordType Type,
                    DNSRecordClass Klass
                    );

    int (*CName)(DnsGenerator *g,
                 const char *Name,
                 const char *CName,
                 int Ttl
                 );

    int (*MX)(DnsGenerator *g,
              const char *Name,
              int Preference,
              const char *Server,
              int Ttl
              );

    int (*A)(DnsGenerator *g,
             const char *Name,
             const char *ip,
             int Ttl
             );

    int (*AAAA)(DnsGenerator *g,
                const char *Name,
                const char *ip,
                int Ttl
                );

    int (*EDns)(DnsGenerator *g, int UdpPayloadSize);

    int (*RawData)(DnsGenerator *g,
                   const char *Name,
                   DNSRecordType Type,
                   DNSRecordClass Klass,
                   const char *Data,
                   int DataLength,
                   int Ttl
                   );

    int (*Generate)(DnsGenerator *g,
                    const char *Name,
                    DNSRecordType Type,
                    DNSRecordClass Klass,
                    const char *Data,
                    int DataLength,
                    int Ttl
                    );
};

int DnsGenerator_Init(DnsGenerator *g,
                      char *Buffer,
                      int BufferLength,
                      const char *CopyFrom,
                      int SourceLength,

                      /* Whether to remove every record except question and
                         answer records. Used when `CopyFrom' is not `NULL'.
                      */
                      BOOL Strip
                      );

#endif /* _DNS_GENERATOR_H_ */
