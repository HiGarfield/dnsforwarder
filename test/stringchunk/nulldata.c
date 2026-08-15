/* Regression test for StringChunk_Match_OnlyWildCard_GetOne.
 *
 * Two defects were fixed:
 *
 * 1. `Data' is documented as an optional output sink -- callers that only want
 *    the boolean match result pass Data == NULL (for example
 *    StringChunk_Domain_Match_WildCardRandom, reached from the "random
 *    upstream" selection paths).  The function unconditionally wrote through
 *    `*Data' and, on the no-match path, executed `*Data = NULL', crashing.
 *
 * 2. The return value was computed as `*Data != NULL'.  An entry added with no
 *    additional payload legitimately stores Data == NULL (see
 *    StringChunk_Add), so a genuine wildcard hit on such an entry was reported
 *    as "no match".  The result now tracks whether something matched.
 *
 * Run via run.sh (builds with ASan/UBSan).
 */
#include <stdio.h>
#include <string.h>
#include "stringchunk.h"
#include "common.h"

static int Failures = 0;

static void Check(const char *Name, int Condition)
{
    if( Condition )
    {
        printf("  [ ok ] %s\n", Name);
    } else {
        printf("  [FAIL] %s\n", Name);
        ++Failures;
    }
}

int main(void)
{
    StringChunk chunk;

    Check("StringChunk_Init", StringChunk_Init(&chunk, NULL) == 0);

    /* Wildcard entry with a payload. */
    StringChunk_Add(&chunk, "*.example.org", "wild", 5);
    /* Non-wildcard entry, must never be reached by the wildcard-only lookup. */
    StringChunk_Add(&chunk, "exact.com", "exact", 6);
    /* Wildcard entry deliberately carrying no payload (defect 2). */
    StringChunk_Add(&chunk, "*.nodata.test", NULL, 0);

    /* --- Data == NULL: must not be dereferenced (defect 1). --- */
    Check("wildcard hit, Data == NULL",
          StringChunk_Match_OnlyWildCard_GetOne(&chunk, "www.example.org",
                                                NULL, NULL, NULL) == TRUE);
    Check("wildcard miss, Data == NULL (used to crash)",
          StringChunk_Match_OnlyWildCard_GetOne(&chunk, "nomatch.net",
                                                NULL, NULL, NULL) == FALSE);
    /* A non-wildcard entry is not visible here, so this is a miss as well and
       again takes the former `*Data = NULL' crash path. */
    Check("non-wildcard entry, Data == NULL (used to crash)",
          StringChunk_Match_OnlyWildCard_GetOne(&chunk, "exact.com",
                                                NULL, NULL, NULL) == FALSE);

    Check("wildcard hit on payload-less entry, Data == NULL",
          StringChunk_Match_OnlyWildCard_GetOne(&chunk, "a.nodata.test",
                                                NULL, NULL, NULL) == TRUE);

    /* Same through the public wrapper that passes Data straight through. */
    Check("Domain_Match_WildCardRandom hit, Data == NULL",
          StringChunk_Domain_Match_WildCardRandom(&chunk, "deep.example.org",
                                                  NULL, NULL, NULL, NULL) == TRUE);
    Check("Domain_Match_WildCardRandom miss, Data == NULL (used to crash)",
          StringChunk_Domain_Match_WildCardRandom(&chunk, "nope.invalid",
                                                  NULL, NULL, NULL, NULL) == FALSE);

    /* --- Data != NULL: previous behaviour preserved. --- */
    {
        void *out = (void *)"sentinel";
        BOOL r = StringChunk_Match_OnlyWildCard_GetOne(&chunk, "a.example.org",
                                                       &out, NULL, NULL);
        Check("wildcard hit, Data receives the payload",
              r == TRUE && out != NULL && strcmp((const char *)out, "wild") == 0);
    }
    {
        void *out = (void *)"sentinel";
        BOOL r = StringChunk_Match_OnlyWildCard_GetOne(&chunk, "nomatch.net",
                                                       &out, NULL, NULL);
        Check("wildcard miss clears Data", r == FALSE && out == NULL);
    }
    {
        /* Defect 2: a hit whose payload is NULL must report TRUE. */
        void *out = (void *)"sentinel";
        BOOL r = StringChunk_Match_OnlyWildCard_GetOne(&chunk, "x.nodata.test",
                                                       &out, NULL, NULL);
        Check("payload-less hit reports TRUE with Data == NULL",
              r == TRUE && out == NULL);
    }

    /* An empty chunk with Data == NULL must be safe too. */
    {
        StringChunk empty;
        Check("empty chunk, Data == NULL (used to crash)",
              StringChunk_Init(&empty, NULL) == 0 &&
              StringChunk_Match_OnlyWildCard_GetOne(&empty, "x",
                                                    NULL, NULL, NULL) == FALSE);
        /* StringChunk_Init(dl, NULL) allocates dl->List internally. */
        StringChunk_Free(&empty, TRUE);
    }

    StringChunk_Free(&chunk, TRUE);

    printf("\n%s\n", Failures == 0 ? "stringchunk: all checks passed"
                                   : "stringchunk: FAILURES");
    return Failures == 0 ? 0 : 1;
}
