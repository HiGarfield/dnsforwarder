/* Regression test for the IPv6AddressToNum() full-format validation bug
   found in the Round-3 review.

   Bug: the full-format branch ran sscanf("%x:%x:...:%x") without checking
   the conversion count, so short or non-numeric literals such as "1:2:3" or
   "garbage" were silently accepted (the missing trailing groups read as
   zeros) and the function returned 16 as if the input were a valid address.
   Malformed addresses could then be stored into hosts / substitute lists.

   Fix: require exactly eight converted groups and, via %n, that only
   trailing whitespace follows the last group.
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "utils.h"

static int Checks = 0;
static int Failures = 0;

static void expect(const char *what, int cond)
{
    ++Checks;
    if( cond )
    {
        printf("  [ ok ] %s\n", what);
    } else {
        ++Failures;
        printf("  [FAIL] %s\n", what);
    }
}

static uint16_t hi16(const void *buf)
{
    const unsigned char *b = (const unsigned char *)buf;
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

int main(void)
{
    char out[16];

    printf("== IPv6AddressToNum full-format validation tests ==\n\n");

    /* ---- valid inputs must still parse ---- */
    printf("Valid literals\n");
    memset(out, 0xAA, sizeof(out));
    expect("a full 8-group literal parses (returns 16)",
           IPv6AddressToNum("2001:db8:0:1:2:3:4:5", out) == 16);
    expect("... and stores the first group correctly",
           hi16(out) == 0x2001);

    memset(out, 0xAA, sizeof(out));
    expect("'::1' parses", IPv6AddressToNum("::1", out) == 16);

    memset(out, 0xAA, sizeof(out));
    expect("'2001:db8::1' parses", IPv6AddressToNum("2001:db8::1", out) == 16);

    memset(out, 0xAA, sizeof(out));
    expect("'::' parses as the zero address (returns 0)",
           IPv6AddressToNum("::", out) == 0);

    memset(out, 0xAA, sizeof(out));
    expect("trailing whitespace after a full literal is accepted",
           IPv6AddressToNum("1:2:3:4:5:6:7:8 ", out) == 16);

    /* ---- malformed full-format inputs must now FAIL ---- */
    printf("Malformed full-format literals\n");
    memset(out, 0xAA, sizeof(out));
    expect("'1:2:3' is rejected (previously accepted with zero padding)",
           IPv6AddressToNum("1:2:3", out) == 0);

    memset(out, 0xAA, sizeof(out));
    expect("'garbage' is rejected", IPv6AddressToNum("garbage", out) == 0);

    memset(out, 0xAA, sizeof(out));
    expect("'1:2:3:4:5:6:7' (seven groups) is rejected",
           IPv6AddressToNum("1:2:3:4:5:6:7", out) == 0);

    memset(out, 0xAA, sizeof(out));
    expect("'1:2:3:4:5:6:7:8:9' (extra group) is rejected",
           IPv6AddressToNum("1:2:3:4:5:6:7:8:9", out) == 0);

    memset(out, 0xAA, sizeof(out));
    expect("an empty string is rejected", IPv6AddressToNum("", out) == 0);

    memset(out, 0xAA, sizeof(out));
    expect("a single group '1234' is rejected", IPv6AddressToNum("1234", out) == 0);

    printf("\n%d checks, %d failure(s)\n\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
