/* Regression tests for HostsContainer bugs:
   1) AAAA query with only an A record present must fall back to the A record
      and report HostsRecordType == HOSTS_TYPE_A (not a forged AAAA record).
   2) Adding an invalid IP literal must fail instead of storing a partly
      initialized address. */
#include <stdio.h>
#include <string.h>
#include "hostscontainer.h"
#include "ipchunk.h"   /* IpAddr */

static int g_FoundType = -1;
static unsigned char g_FoundAddr[16];
static int g_FoundLen = 0;

static int OnFound(int Number, HostsRecordType Type, const void *Data, void *Arg)
{
    (void)Number; (void)Arg;
    const IpAddr *ip = (const IpAddr *)Data;
    g_FoundType = (int)Type;
    if( ip != NULL )
    {
        memcpy(g_FoundAddr, ip->Addr, 16);
        g_FoundLen = 16;
    }
    return 0; /* continue */
}

int main(void)
{
    int Ok = 1;
    HostsContainer hc;

    if( HostsContainer_Init(&hc) != 0 )
    {
        printf("FAIL: HostsContainer_Init\n");
        return 1;
    }

    /* ---- Bug 1: AAAA fallback must report HOSTS_TYPE_A ---- */
    if( hc.Load(&hc, "1.2.3.4 example.com") != HOSTS_TYPE_A )
    {
        printf("FAIL: Load(A) failed\n");
        Ok = 0;
    }

    g_FoundType = -1;
    memset(g_FoundAddr, 0, 16);
    hc.Find(&hc, "example.com", HOSTS_TYPE_AAAA, OnFound, NULL);

    if( g_FoundType != HOSTS_TYPE_A )
    {
        printf("FAIL: AAAA fallback reported type %d, expected HOSTS_TYPE_A(%d)\n",
               g_FoundType, (int)HOSTS_TYPE_A);
        Ok = 0;
    }
    if( g_FoundLen == 16 &&
        !(g_FoundAddr[12] == 1 && g_FoundAddr[13] == 2 &&
          g_FoundAddr[14] == 3 && g_FoundAddr[15] == 4) )
    {
        printf("FAIL: AAAA fallback returned wrong address bytes\n");
        Ok = 0;
    }

    /* ---- Bug 2: invalid IP must be rejected ---- */
    if( hc.Load(&hc, "not-an-ip bad.com") == HOSTS_TYPE_A )
    {
        printf("FAIL: Load accepted invalid IP literal\n");
        Ok = 0;
    }
    if( hc.Load(&hc, "999.999.999.999 bad2.com") == HOSTS_TYPE_A )
    {
        printf("FAIL: Load accepted out-of-range IP literal\n");
        Ok = 0;
    }

    hc.Free(&hc);

    if( Ok )
    {
        printf("PASS\n");
        return 0;
    }
    return 1;
}
