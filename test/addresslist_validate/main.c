/*
 * AddressList_ConvertFromString must REJECT malformed IP literals instead of
 * silently turning them into garbage addresses.
 *
 * Compile (project style):
 *   cc -g -I../.. $Sources testutils.c main.c -o main.exe
 *   (the codeblocks_win/makefile 'test' target builds this automatically)
 */

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include "addresslist.h"
#include "ipmisc.h"

static int Check(const char *Text, int DefaultPort,
                 sa_family_t ExpectFamily, int ExpectReject)
{
    Address_Type out;
    sa_family_t fam = AddressList_ConvertFromString(&out, Text, DefaultPort);

    if( ExpectReject )
    {
        if( fam == AF_UNSPEC )
        {
            printf("OK   reject   %s\n", Text);
            return 0;
        }
        printf("FAIL accept   %s (family=%d)\n", Text, (int)fam);
        return 1;
    }

    if( fam != ExpectFamily )
    {
        printf("FAIL family   %s (got %d, want %d)\n", Text, (int)fam, (int)ExpectFamily);
        return 1;
    }
    printf("OK   accept   %s\n", Text);
    return 0;
}

int main(void)
{
    int fails = 0;

    /* Valid inputs must be accepted. */
    fails += Check("1.2.3.4:53", 53, AF_INET, 0);
    fails += Check("[2001:db8::1]:53", 53, AF_INET6, 0);
    fails += Check("[::]:53", 53, AF_INET6, 0);

    /* Malformed inputs must be rejected (previously turned into garbage). */
    fails += Check("[foo]:53", 53, 0, 1);          /* not a valid IPv6 literal */
    fails += Check("[1.2.3.4]:53", 53, 0, 1);      /* IPv4 inside IPv6 brackets */
    fails += Check("garbage", 53, 0, 1);           /* no colon at all */
    fails += Check("999.999.999.999:53", 53, 0, 1);/* out-of-range IPv4 */

    if( fails != 0 )
    {
        printf("\n%d check(s) failed\n", fails);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
