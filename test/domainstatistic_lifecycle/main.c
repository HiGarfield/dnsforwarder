/* Integration test for the DomainStatistic module lifecycle.
 *
 * Exercises the real code path: TimedTask_Init -> DomainStatistic_Init (with a
 * template file and insertion marker) -> DomainStatistic_Add (several domains)
 * -> the persistent worker (DomainStatistic_Works) generates statistic.html ->
 * process exit runs DomainStatistic_Cleanup (atexit).
 *
 * Run with HOME pointing at a scratch directory: statistic.html is written to
 * $HOME/.dnsforwarder/statistic.html, and the template file is read from the
 * current working directory.  The run.sh wrapper sets both up.
 *
 * Returning from main() runs all atexit handlers; this test fails (hangs or
 * crashes) if DomainStatistic_Cleanup / TimedTask_Cleanup regress.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include "../../common.h"
#include "../../readconfig.h"
#include "../../domainstatistic.h"
#include "../../timedtask.h"
#include "../../iheader.h"

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
    ConfigFileInfo Info;
    VType vt;
    IHeader h;
    int i;

    if( TimedTask_Init() != 0 )
    {
        printf("FAIL: TimedTask_Init\n");
        return 2;
    }

    if( ConfigInitInfo(&Info) != 0 )
    {
        printf("FAIL: ConfigInitInfo\n");
        return 2;
    }

    memset(&vt, 0, sizeof(vt));
    vt.boolean = TRUE;
    ConfigAddOption(&Info, "DomainStatistic", STRATEGY_APPEND, TYPE_BOOLEAN, vt);

    memset(&vt, 0, sizeof(vt));
    vt.INT32 = 1;                       /* generate every 1 s */
    ConfigAddOption(&Info, "StatisticUpdateInterval", STRATEGY_APPEND, TYPE_INT32, vt);

    memset(&vt, 0, sizeof(vt));
    vt.str = "template.html";
    ConfigAddOption(&Info, "DomainStatisticTempletFile", STRATEGY_APPEND, TYPE_STRING, vt);

    memset(&vt, 0, sizeof(vt));
    vt.str = "@@INSERT@@";
    ConfigAddOption(&Info, "StatisticInsertionPosition", STRATEGY_APPEND, TYPE_STRING, vt);

    if( DomainStatistic_Init(&Info) != 0 )
    {
        printf("FAIL: DomainStatistic_Init\n");
        return 3;
    }

    /* Register a few statistics through the request-side entry point. */
    memset(&h, 0, sizeof(h));
    strcpy(h.Domain, "example.com");
    h.HashValue = 0x1234;
    for( i = 0; i < 5; ++i )
    {
        DomainStatistic_Add(&h, STATISTIC_TYPE_UDP);
    }

    strcpy(h.Domain, "second.org");
    h.HashValue = 0x5678;
    DomainStatistic_Add(&h, STATISTIC_TYPE_TCP);
    DomainStatistic_Add(&h, STATISTIC_TYPE_CACHE);

    /* Let the persistent worker generate the page (1 s interval). */
    sleep(2);

    /* Verify the generated page contains the domains and the template shell.
       GetConfigDirectory() resolves the home directory via getpwuid(), NOT
       the HOME environment variable, so build the expected path the same way. */
    {
        char Path[2048];
        struct passwd *pw = getpwuid(getuid());
        FILE *fp;
        char Buf[4096];
        size_t n;

        if( pw == NULL || pw->pw_dir == NULL )
        {
            printf("FAIL: cannot resolve home directory\n");
            return 4;
        }
        snprintf(Path, sizeof(Path), "%s/.dnsforwarder/statistic.html",
                 pw->pw_dir);

        fp = fopen(Path, "r");
        CHECK(fp != NULL, "statistic.html was generated");
        if( fp != NULL )
        {
            n = fread(Buf, 1, sizeof(Buf) - 1, fp);
            Buf[n] = '\0';
            fclose(fp);

            CHECK(strstr(Buf, "example.com") != NULL,
                  "generated page contains example.com");
            CHECK(strstr(Buf, "second.org") != NULL,
                  "generated page contains second.org");
            CHECK(strstr(Buf, "Total") != NULL,
                  "generated page contains the JS summary");
        }
    }

    /* Returning from main runs the atexit cleanup chain.  Any hang means the
       worker/Cleanup deadlock is back; any crash means the shared-state lock
       protocol regressed. */
    printf("returning from main to trigger atexit cleanup...\n");

    /* Release the config structures built by ConfigAddOption() above.
       Without this the suite reports an LSan leak (1396 bytes in 15
       allocations) at exit, which is a test-harness artifact rather than a
       production leak. */
    ConfigFree(&Info);

    if( failures == 0 )
    {
        printf("\nALL TESTS PASSED: domainstatistic lifecycle.\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED.\n", failures);
    return 1;
}
