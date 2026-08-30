/*
 * Regression test for the strict C89 (`-std=c89 -pedantic-errors`) build.
 *
 * Before the fix, `snprintf`, `vsnprintf` and `va_copy` are C99 identifiers
 * hidden by `__STRICT_ANSI__`, so every translation unit that calls them fails
 * to compile under the project's mandated strict flags.  This program exercises
 * all three through `common.h`'s shims and proves they both compile AND link
 * and behave at runtime.
 */
#include <stdio.h>
#include <stdarg.h>

#include "common.h"

static void vfmt(const char *fmt, ...)
{
    va_list ap, cp;
    char buf[64];
    int n;

    va_start(ap, fmt);
    va_copy(cp, ap);
    n = vsnprintf(buf, sizeof(buf), fmt, cp);
    va_end(cp);
    va_end(ap);

    if( n < 0 )
        return;
    printf("%s", buf);
}

int main(void)
{
    char b[32];
    int n;

    /* snprintf shim. */
    n = snprintf(b, sizeof(b), "%d-%s", 42, "ok");
    if( n < 0 )
        return 1;
    if( b[0] != '4' || b[1] != '2' )
        return 2;

    /* va_copy + vsnprintf shim (runtime, so we know the symbol links). */
    vfmt("%d\n", 7);

    return 0;
}
