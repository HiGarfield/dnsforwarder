/* Regression test: DnsGenerator_RawData / CopyA / CopyAAAA must not write the
   RDATA past the end of the destination buffer.

   The old code validated the destination against the RDATA size BEFORE the
   record name and header were written:

       if( LEFT_LENGTH(g) < DataLength ) return -6;
       CopyNamePart(g, i)        -- consumes NameLen bytes
       type/class/TTL/rdlen      -- 10 header bytes

   A name long enough to eat the remaining space after the pre-check makes the
   final memcpy(g->Itr, Data, DataLength) overflow the buffer.  CopyCName checks
   LEFT_LENGTH < CNameLabelLength again AFTER the header, right before its
   rdata write; RawData/CopyA/CopyAAAA must do the same.

   This test drives RawData with a name length chosen so that after the
   pre-check the name plus the 10-byte header leave 0..3 bytes, then asserts
   the function rejects the record instead of writing out of bounds.  Built
   with ASan in run.sh, an overflow would abort the process. */

#include "dnsgenerator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if( !(cond) ) { \
        printf("[FAIL] %s\n", msg); \
        return 1; \
    } \
    printf("[ ok ] %s\n", msg); \
} while(0)

static int TryRawData(int NameLen, int BufferLength)
{
    DnsGenerator g;
    char *Buffer = (char *)calloc(1, (size_t)BufferLength);
    char Name[256];
    int r;

    if( Buffer == NULL )
    {
        printf("calloc failed\n");
        return 2;
    }

    if( NameLen > 255 )
    {
        NameLen = 255;
    }
    memset(Name, 'a', (size_t)NameLen);
    Name[NameLen] = '\0';

    r = DnsGenerator_Init(&g, Buffer, BufferLength, NULL, 0, FALSE);
    if( r != 0 )
    {
        printf("DnsGenerator_Init rc=%d\n", r);
        free(Buffer);
        return 2;
    }

    /* Name consumes NameLen+1 (LABEL_LENGTH) bytes, the record header 10
       bytes, RDATA 4 bytes.  We drive the post-header remainder into 0..3.
       RawData only writes in ANSWER/NS/ADDITIONAL; step the counter from
       QUESTION to ANSWER first (as DnsGenerator_Generate's callers do). */
    g.NextPurpose(&g);
    r = g.RawData(&g, Name, DNS_TYPE_A, DNS_CLASS_IN, "\x01\x02\x03\x04", 4, 60);
    free(Buffer);
    if( r != 0 )
    {
        printf("RawData rc=%d (NameLen=%d BufferLength=%d)\n", r, NameLen, BufferLength);
    }
    return r;
}

int main(void)
{
    int r;

    /* Baseline: a comfortably large buffer succeeds. */
    r = TryRawData(10, 256);
    CHECK(r == 0, "RawData with ample space succeeds");

    /* NameLen such that after name+header exactly 2 bytes remain: the old
       code memcpy'd 4 bytes -> 2-byte heap overflow. */
    {
        int NameLen = 30;      /* LABEL_LENGTH = 31 */
        int BufLen = 12 + 31 + 10 + 2;   /* header + name + header + 2 left */
        r = TryRawData(NameLen, BufLen);
        CHECK(r != 0, "RawData with 2 bytes left rejects the record (no overflow)");
    }

    /* 0 bytes left after name+header. */
    {
        int NameLen = 30;
        int BufLen = 12 + 31 + 10;
        r = TryRawData(NameLen, BufLen);
        CHECK(r != 0, "RawData with 0 bytes left rejects the record");
    }

    /* 3 bytes left (worst case for a 4-byte A record). */
    {
        int NameLen = 30;
        int BufLen = 12 + 31 + 10 + 3;
        r = TryRawData(NameLen, BufLen);
        CHECK(r != 0, "RawData with 3 bytes left rejects the record");
    }

    /* Long name (255) with exactly 1 byte left. */
    {
        int NameLen = 255;
        int BufLen = 12 + 256 + 10 + 1;
        r = TryRawData(NameLen, BufLen);
        CHECK(r != 0, "RawData with 255-byte name and 1 byte left rejects");
    }

    printf("all checks passed\n");
    return 0;
}
