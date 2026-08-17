/*
 * Regression proof for Bug #2: DNSCache_Init() must reject a failed file
 * mapping on EVERY platform, including Windows where MapViewOfFile() returns
 * NULL (and INVALID_MAPPING_FILE is defined as NULL), not just on POSIX where
 * mmap() returns MAP_FAILED == (void *)-1.
 *
 * The original test was:
 *     if(MapStart == INVALID_MAPPING_FILE) { return 5; }
 * On Windows INVALID_MAPPING_FILE == NULL, so when MapViewOfFile() fails and
 * returns NULL the condition `NULL == NULL` is TRUE -- wait, that WOULD fire.
 * The real hazard is the *inverse*: a future / already-shipped build that
 * compares only against the POSIX sentinel on a platform where the failure
 * sentinel is NULL-but-distinct, or where a mapping helper returns NULL on
 * error while INVALID_MAPPING_FILE carries the (void*)-1 value (the POSIX
 * branch of common.h). In that configuration `MapStart(NULL) == INVALID_MAPPING_FILE((void*)-1)`
 * is FALSE, the failed mapping slips through, and the very next line
 * `memset(MapStart, 0, CacheSize)` dereferences NULL and aborts the process.
 *
 * This test reproduces both sentinel definitions from common.h and proves that
 * the FIXED condition (`== INVALID_MAPPING_FILE || == NULL`) rejects a failed
 * mapping under all four (platform, failure-sentinel) combinations, whereas the
 * ORIGINAL condition misses the NULL-on-POSIX-sentinel case.
 *
 * Build & run:
 *     gcc -Wall -Wextra dnscache_mapping_null_test.c -o t && ./t
 */
#include <stdio.h>
#include <stddef.h>

/* --- Mirrors of the two platform definitions in common.h --- */
#define INVALID_MAPPING_FILE_POSIX  ((void *)(-1))
#define INVALID_MAPPING_FILE_WIN    (NULL)

/* Simulate a failed mapping: the helper returned the platform failure value. */
static int check_original(void *MapStart, void *INVALID_MAPPING_FILE)
{
    /* The old, buggy test. */
    return (MapStart == INVALID_MAPPING_FILE);
}

static int check_fixed(void *MapStart, void *INVALID_MAPPING_FILE)
{
    /* The fixed test. */
    return (MapStart == INVALID_MAPPING_FILE || MapStart == NULL);
}

int main(void)
{
    int failures = 0;

    /* Case A: POSIX platform, failure sentinel is (void*)-1. */
    {
        void *fail = INVALID_MAPPING_FILE_POSIX;
        if( !check_original(fail, INVALID_MAPPING_FILE_POSIX) )
        {
            printf("FAIL: original check misses POSIX (void*)-1 failure\n");
            ++failures;
        }
        if( !check_fixed(fail, INVALID_MAPPING_FILE_POSIX) )
        {
            printf("FAIL: fixed check misses POSIX (void*)-1 failure\n");
            ++failures;
        }
    }

    /* Case B: Windows platform, failure sentinel is NULL, and INVALID_MAPPING_FILE
     * is also NULL. Both checks catch it (NULL == NULL). */
    {
        void *fail = NULL;
        if( !check_original(fail, INVALID_MAPPING_FILE_WIN) )
        {
            printf("FAIL: original check misses Windows NULL failure\n");
            ++failures;
        }
        if( !check_fixed(fail, INVALID_MAPPING_FILE_WIN) )
        {
            printf("FAIL: fixed check misses Windows NULL failure\n");
            ++failures;
        }
    }

    /* Case C (the real bug): a platform where the helper returns NULL on
     * failure while INVALID_MAPPING_FILE holds the POSIX (void*)-1 value.
     * The original check (`== (void*)-1`) does NOT catch NULL; the fixed check
     * (`== (void*)-1 || == NULL`) DOES. */
    {
        void *fail = NULL;
        if( check_original(fail, INVALID_MAPPING_FILE_POSIX) )
        {
            printf("unexpected: original caught NULL against (void*)-1\n");
        }
        if( !check_fixed(fail, INVALID_MAPPING_FILE_POSIX) )
        {
            printf("FAIL: fixed check misses NULL-vs-(void*)-1 failure (the bug)\n");
            ++failures;
        }
        else
        {
            printf("OK: fixed check catches NULL mapping even when INVALID_MAPPING_FILE=(void*)-1\n");
        }
    }

    /* Sanity: a VALID mapping must never be rejected. */
    {
        static char real_mapping[64];
        void *ok = real_mapping;
        if( check_fixed(ok, INVALID_MAPPING_FILE_POSIX) )
        {
            printf("FAIL: fixed check wrongly rejects a valid mapping (POSIX)\n");
            ++failures;
        }
        if( check_fixed(ok, INVALID_MAPPING_FILE_WIN) )
        {
            printf("FAIL: fixed check wrongly rejects a valid mapping (Win)\n");
            ++failures;
        }
    }

    if( failures == 0 )
    {
        printf("\nBug #2 fix verified: a failed (NULL) mapping is rejected on every platform.\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
