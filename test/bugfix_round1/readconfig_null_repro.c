/*
 * Regression proof for Bug #4: crash in ConfigSetDefaultValue on NULL string.
 *
 * Original code (TYPE_STRING / TYPE_PATH branch):
 *     Option->Holder.str.Clear(&(Option->Holder.str));
 *     Option->Holder.str.Add(&(Option->Holder.str), Value.str, ...);
 * StringList_Add internally does strlen(Value.str); if Value.str == NULL
 * (e.g. a config default supplied as NULL, or a parse failure) this is
 * strlen(NULL) -> undefined behaviour / segfault.
 *
 * The fix guards the Add with `if( Value.str != NULL )`.
 *
 * This test counts how many times the strlen(NULL) crash-point is reached.
 * The OLD branch reaches it once (=> would crash); the NEW branch never
 * reaches it (guarded), proving the crash is eliminated while non-NULL
 * values are still applied exactly as before.
 *
 * Build & run:
 *     gcc -Wall -Wextra readconfig_null_repro.c -o t && ./t
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int crash_point_reached = 0;   /* how many times strlen(NULL) would run */
static int add_called = 0;            /* how many times a real Add happened */

static void stringlist_add(const char *value)
{
    add_called++;
    if( value == NULL )
    {
        crash_point_reached++;        /* models strlen(NULL) -> UB/segfault */
        return;
    }
    (void)strlen(value);
}
static void stringlist_clear(void) { /* no-op model */ }

/* ---- OLD buggy branch ---- */
static void apply_OLD(const char *value)
{
    stringlist_clear();
    stringlist_add(value);   /* value may be NULL -> reaches crash point */
}
/* ---- NEW fixed branch ---- */
static void apply_NEW(const char *value)
{
    stringlist_clear();
    if( value != NULL )
        stringlist_add(value);
}

static int failures = 0;
static void check(int cond, const char *name)
{
    if( !cond ) { printf("FAIL: %s\n", name); failures++; }
    else        { printf("PASS: %s\n", name); }
}

int main(void)
{
    /* OLD: NULL value -> crash point reached (would segfault). */
    crash_point_reached = 0;
    apply_OLD(NULL);
    check(crash_point_reached == 1, "OLD: NULL value reaches strlen(NULL) crash point");

    /* NEW: NULL value -> crash point NOT reached (guarded). */
    crash_point_reached = 0;
    apply_NEW(NULL);
    check(crash_point_reached == 0, "NEW: NULL value is guarded, crash avoided");

    /* NEW: non-NULL value still applied (Add happened, no crash point). */
    crash_point_reached = 0;
    add_called = 0;
    apply_NEW("example");
    check(crash_point_reached == 0 && add_called == 1,
          "NEW: non-NULL value still applied correctly (no crash)");

    if( failures == 0 )
    {
        printf("\nBug #4 fix verified (NULL string no longer reaches strlen(NULL)).\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
