#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../stringlist.h"
#include "../testutils.h"

/* Regression test for StringList_AppendLast():
 *   - normal path concatenates onto the last string;
 *   - empty-last-block path (after the only entry was removed) must add the
 *     new string as a new entry instead of overflowing the heap. */
static int test_appendlast(void)
{
    StringList          l;
    StringListIterator  it;
    const char         *ci;

    /* Normal concatenation path. */
    StringList_Init(&l, NULL, ",");
    l.Add(&l, "abc", ",");
    if( l.AppendLast(&l, "def", ",") < 0 )
    {
        printf("FAIL: normal AppendLast returned error\n");
        return 1;
    }
    StringListIterator_Init(&it, &l);
    ci = it.Next(&it);
    if( ci == NULL || strcmp(ci, "abcdef") != 0 )
    {
        printf("FAIL: normal AppendLast produced '%s'\n", ci ? ci : "(null)");
        return 1;
    }
    if( it.Next(&it) != NULL )
    {
        printf("FAIL: normal AppendLast created an extra entry\n");
        return 1;
    }
    l.Free(&l);

    /* Empty-last-block path: remove the only entry, then AppendLast. */
    StringList_Init(&l, NULL, ",");
    l.Add(&l, "hello", ",");
    StringListIterator_Init(&it, &l);
    it.Next(&it);
    it.Remove(&it);                /* last block now empty (Used == 0) */
    if( l.AppendLast(&l, "world", ",") < 0 )
    {
        printf("FAIL: empty-block AppendLast returned error\n");
        return 1;
    }
    StringListIterator_Init(&it, &l);
    ci = it.Next(&it);
    if( ci == NULL || strcmp(ci, "world") != 0 )
    {
        printf("FAIL: empty-block AppendLast produced '%s'\n", ci ? ci : "(null)");
        return 1;
    }
    if( it.Next(&it) != NULL )
    {
        printf("FAIL: empty-block AppendLast created an extra entry\n");
        return 1;
    }
    l.Free(&l);

    printf("test_appendlast: PASS\n");
    return 0;
}

int main(void)
{
    StringList l;
    StringListIterator i;
    const char *ci;
    int n;

    if( test_appendlast() != 0 )
    {
        return 1;
    }

    srand(time(NULL));
    StringList_Init(&l, "          asd          ,      facryhty,,    ,  ,00000", ",");

    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");
    l.Add(&l, ",,,,,,asd          ,      facryhty,,    ,  ,00000,,,,,,,", ",");

    l.TrimAll(&l, NULL);

    printf("Count : %d\n", l.Count(&l));

    StringListIterator_Init(&i, &l);

    ci = i.Next(&i);
    n = 0;
    while( ci != NULL )
    {
        printf("%s\n\n", ci);
        ci = i.Next(&i);
        ++n;
    }

    l.Free(&l);

    printf("Count : %d\n", n);

    return 0;
}
