/*
 * Regression test for ipchunk.c:
 *   Bug #2: IpAddr_Parse used to set ipAddr->Zone (e.g. to Z4) and partially
 *   write ipAddr->Addr BEFORE the numeric conversion, and returned failure only
 *   after that.  A caller that checks IpAddr_IsValid() (which is just
 *   `Zone != Z0') instead of the parse return value would then treat the
 *   half-initialised struct as a valid address.  Verify that a failed parse
 *   yields IpAddr_IsValid() == FALSE.
 *
 * Build (from the repository root):
 *   cc -I. -o /tmp/t_ipchunk test/ipchunk_parse_invariant/main.c \
 *      ipchunk.c utils.c array.c -lpthread
 */
#include <stdio.h>
#include <string.h>
#include "ipchunk.h"
#include "utils.h"

static int Failures = 0;
static int Checks = 0;

static void Check(const char *Name, int Condition)
{
    ++Checks;
    if( Condition ) { printf("  [ ok ] %s\n", Name); }
    else { printf("  [FAIL] %s\n", Name); ++Failures; }
}

static void Test_InvalidIpv4(void)
{
    IpAddr a;

    printf("Invalid IPv4 literals\n");

    memset(&a, 0x5A, sizeof(a));
    Check("\"999.999.999.999\" parse fails",
          IpAddr_Parse("999.999.999.999", &a) != 0);
    Check("\"999.999.999.999\" is NOT reported valid",
          IpAddr_IsValid(&a) == FALSE);

    memset(&a, 0x5A, sizeof(a));
    Check("\"1.2.3\" parse fails",
          IpAddr_Parse("1.2.3", &a) != 0);
    Check("\"1.2.3\" is NOT reported valid",
          IpAddr_IsValid(&a) == FALSE);

    memset(&a, 0x5A, sizeof(a));
    Check("\"not-an-ip\" parse fails",
          IpAddr_Parse("not-an-ip", &a) != 0);
    Check("\"not-an-ip\" is NOT reported valid",
          IpAddr_IsValid(&a) == FALSE);
}

static void Test_InvalidIpv6(void)
{
    IpAddr a;

    printf("Invalid IPv6 literals\n");

    /* "hello" contains neither ':' nor '.', so IpAddr_Parse falls through and
       returns failure (it is not a valid address of any family). */
    memset(&a, 0x5A, sizeof(a));
    Check("\"hello\" parse fails",
          IpAddr_Parse("hello", &a) != 0);
    Check("\"hello\" is NOT reported valid",
          IpAddr_IsValid(&a) == FALSE);
}

static void Test_ValidStillWorks(void)
{
    IpAddr a;

    printf("Valid literals still parse and report valid\n");

    memset(&a, 0, sizeof(a));
    Check("\"1.2.3.4\" parses",
          IpAddr_Parse("1.2.3.4", &a) == 0);
    Check("\"1.2.3.4\" IS reported valid",
          IpAddr_IsValid(&a) == TRUE);

    memset(&a, 0, sizeof(a));
    Check("\"2001:db8::1\" parses",
          IpAddr_Parse("2001:db8::1", &a) == 0);
    Check("\"2001:db8::1\" IS reported valid",
          IpAddr_IsValid(&a) == TRUE);
}

int main(void)
{
    printf("== ipchunk IpAddr_Parse invariant regression tests ==\n\n");
    Test_InvalidIpv4();
    Test_InvalidIpv6();
    Test_ValidStillWorks();

    printf("\n%d checks, %d failure(s)\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
