#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "readconfig.h"
#include "utils.h"

#define CHECK(cond) do { if( !(cond) ) { fprintf(stderr, "FAIL: %s (line %d)\n", #cond, __LINE__); return 1; } } while(0)

int main(void)
{
    ConfigFileInfo   Info;

    CHECK(ConfigInitInfo(&Info) == 0);

    /* Legitimate alias must still resolve to the target's value. */
    {
        VType    v;
        v.str = "value123";
        CHECK(ConfigAddOption(&Info, "Real", STRATEGY_DEFAULT, TYPE_STRING, v) == 0);
        CHECK(ConfigAddAlias(&Info, "Real", "MyAlias", NULL, NULL) == 0);
        CHECK(ConfigGetRawString(&Info, "MyAlias") != NULL);
        CHECK(strcmp(ConfigGetRawString(&Info, "MyAlias"), "value123") == 0);
    }

    /* Cyclic alias (A -> B -> A) used to recurse forever and crash via stack
       overflow. It must now fail gracefully. */
    CHECK(ConfigAddAlias(&Info, "B", "A", NULL, NULL) == 0);
    CHECK(ConfigAddAlias(&Info, "A", "B", NULL, NULL) == 0);
    CHECK(ConfigGetRawString(&Info, "A") == NULL);

    /* Self alias (C -> C). */
    CHECK(ConfigAddAlias(&Info, "C", "C", NULL, NULL) == 0);
    CHECK(ConfigGetRawString(&Info, "C") == NULL);

    ConfigFree(&Info);

    printf("readconfig_alias: all tests passed\n");
    return 0;
}
