/* Regression test for cachettlcrtl.c command-state prefix-match bug.
 *
 * Bug: IS_STATE() used strncmp(Cmd, state, strlen(state)), so mistyped
 * commands such as "origX", "nocacheYY", "fixedZZ" or "variWW" were silently
 * accepted and applied the corresponding TTL policy the user never asked for.
 *
 * Fix: exact strcmp.  Valid commands still parse; malformed ones are rejected
 * with -1.
 */
#include <stdio.h>
#include <string.h>
#include "../../cachettlcrtl.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if( !(cond) ) { \
        printf("FAIL: %s\n", msg); \
        ++failures; \
    } else { \
        printf("PASS: %s\n", msg); \
    } \
} while(0)

int main(void)
{
    CacheTtlCtrl c;
    const CtrlContent *cc;

    if( CacheTtlCrtl_Init(&c) != 0 )
    {
        printf("FAIL: CacheTtlCrtl_Init\n");
        return 2;
    }

    /* Valid commands still work. */
    CHECK(CacheTtlCrtl_Add_From_String(&c, "a.com orig") == 0,
          "`orig` is accepted");
    CHECK(CacheTtlCrtl_Add_From_String(&c, "b.com nocache") == 0,
          "`nocache` is accepted");
    CHECK(CacheTtlCrtl_Add_From_String(&c, "c.com fixed 300") == 0,
          "`fixed 300` is accepted");
    CHECK(CacheTtlCrtl_Add_From_String(&c, "d.com vari 3600x100") == 0,
          "`vari 3600x100` is accepted");

    cc = CacheTtlCrtl_Get(&c, "a.com");
    CHECK(cc != NULL && cc->State == TTL_STATE_ORIGINAL,
          "`orig` maps to TTL_STATE_ORIGINAL");

    cc = CacheTtlCrtl_Get(&c, "b.com");
    CHECK(cc != NULL && cc->State == TTL_STATE_NO_CACHE,
          "`nocache` maps to TTL_STATE_NO_CACHE");

    cc = CacheTtlCrtl_Get(&c, "c.com");
    CHECK(cc != NULL && cc->State == TTL_STATE_FIXED && cc->Increment == 300,
          "`fixed 300` maps to TTL_STATE_FIXED with Increment 300");

    cc = CacheTtlCrtl_Get(&c, "d.com");
    CHECK(cc != NULL && cc->State == TTL_STATE_VARIABLE &&
          cc->Coefficient == 3600 && cc->Increment == 100,
          "`vari 3600x100` maps to TTL_STATE_VARIABLE with Coeff 3600 Incr 100");

    /* Mistyped prefixes must be rejected, not silently treated as valid. */
    CHECK(CacheTtlCrtl_Add_From_String(&c, "e.com origX") == -1,
          "`origX` is rejected (was wrongly accepted as `orig`)");
    CHECK(CacheTtlCrtl_Add_From_String(&c, "f.com nocache2") == -1,
          "`nocache2` is rejected");
    CHECK(CacheTtlCrtl_Add_From_String(&c, "g.com fixedX") == -1,
          "`fixedX` is rejected");
    CHECK(CacheTtlCrtl_Add_From_String(&c, "h.com variX") == -1,
          "`variX` is rejected");

    CacheTtlCrtl_Free(&c);

    if( failures == 0 )
    {
        printf("\nALL TESTS PASSED: cachettlcrtl exact-command matching.\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
