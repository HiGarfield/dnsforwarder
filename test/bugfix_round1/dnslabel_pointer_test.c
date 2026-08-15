/*
 * Regression test for Bug #1: DNSLabelMakePointer compression-pointer encoding.
 *
 * Original buggy macro:
 *     (192 + (location) / 256)            // high byte
 *     (location) % 256                    // low byte
 * For any location > 255 this produced a high byte whose top two bits were
 * NOT `11`, i.e. an INVALID DNS compression pointer (RFC 1035 �'4.1.4).
 *
 * Fixed macro emits:  high = 0xC0 | ((off >> 8) & 0x3F), low = off & 0xFF,
 * and safely degrades out-of-range offsets to a root label.
 *
 * Build & run (ASan enabled):
 *     gcc -fsanitize=address,undefined -I../.. dnslabel_pointer_test.c -o t && ./t
 */
#include <stdio.h>
#include <stdint.h>
#include "dnsgenerator.h"

static int failures = 0;

static void check(int cond, const char *name)
{
    if( !cond )
    {
        printf("FAIL: %s\n", name);
        failures++;
    }
    else
    {
        printf("PASS: %s\n", name);
    }
}

int main(void)
{
    unsigned char buf[2];

    /* location = 0x0000 -> C00 0x00 */
    DNSLabelMakePointer(buf, 0x0000);
    check(buf[0] == 0xC0 && buf[1] == 0x00, "offset 0x0000 -> C0 00");

    /* location = 0x0012 (small, < 256) -> C0 0x12 */
    DNSLabelMakePointer(buf, 0x0012);
    check(buf[0] == 0xC0 && buf[1] == 0x12, "offset 0x0012 -> C0 12");

    /* location = 0x0500 (top bit of the 14-bit field set) -> C0|05 00 */
    DNSLabelMakePointer(buf, 0x0500);
    check(buf[0] == (0xC0 | 0x05) && buf[1] == 0x00,
          "offset 0x0500 -> C5 00 (high two bits == 11)");

    /* location = 0x1234 -> C0|0x12 0x34 */
    DNSLabelMakePointer(buf, 0x1234);
    check(buf[0] == (0xC0 | 0x12) && buf[1] == 0x34,
          "offset 0x1234 -> D2 34 (high two bits == 11)");

    /* location = 0x3FFF (max valid 14-bit offset) -> C0|0x3F 0xFF */
    DNSLabelMakePointer(buf, 0x3FFF);
    check(buf[0] == (0xC0 | 0x3F) && buf[1] == 0xFF,
          "offset 0x3FFF -> FF FF");

    /* location = 0x4000 (out of range) must NOT emit a pointer;
       it must degrade to a root label (00 00) instead of an illegal byte. */
    DNSLabelMakePointer(buf, 0x4000);
    check(buf[0] == 0x00 && buf[1] == 0x00,
          "offset 0x4000 -> 00 00 (safe degradation, no invalid pointer)");

    /* The critical invariant: the top two bits of the high byte must always
       be `11` for any in-range pointer.  The original macro violated this
       for every offset >= 256. */
    int ok = 1;
    for( int off = 0; off <= 0x3FFF; off++ )
    {
        DNSLabelMakePointer(buf, off);
        if( (buf[0] & 0xC0) != 0xC0 )
        {
            ok = 0;
            break;
        }
    }
    check(ok, "all in-range offsets keep top two bits == 11");

    if( failures == 0 )
    {
        printf("\nALL TESTS PASSED (Bug #1 fixed).\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
