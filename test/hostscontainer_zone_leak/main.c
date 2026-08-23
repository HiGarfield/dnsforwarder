/* Regression test for HostsContainer_AddNode() Zone-string double-allocation bug.
 *
 * When two hosts entries share the SAME IPv6 address that carries a scope zone
 * (e.g. "fe80::1%eth0"), the de-duplication path (goto OUT_SEARCH) reuses the
 * single shared IpAddr record.  The old code then unconditionally copied the
 * Zone string into Container->Table again and rebound ipAddr->Zone onto the new
 * copy.  Because the record is shared, every repeated insert leaked one Zone
 * string copy (the previous copy became unreferenced) and pointlessly rewrote a
 * stable pointer.
 *
 * After the fix, the Zone string is copied only when the IpAddr record is first
 * created; on a de-duplication hit the existing persistent Zone pointer is left
 * untouched.  This test proves exactly that: inserting a second entry that
 * de-duplicates onto the first one must NOT rebind the first entry's Zone
 * pointer, and the two entries must share the same IpAddr record. */
#include <stdio.h>
#include <string.h>
#include "hostscontainer.h"
#include "ipchunk.h"   /* IpAddr */

/* OnFound receives Data == IP->Data, i.e. the shared IpAddr record.  We stash
   its Zone pointer so the harness can compare it before/after a second insert. */
static const char *g_Zone = NULL;
static const IpAddr *g_Ip = NULL;

static int OnFound(int Number, HostsRecordType Type, const void *Data, void *Arg)
{
    (void)Number; (void)Type; (void)Arg;
    g_Ip = (const IpAddr *)Data;
    g_Zone = (g_Ip != NULL) ? g_Ip->Zone : NULL;
    return 0; /* continue */
}

int main(void)
{
    int Ok = 1;
    HostsContainer hc;
    const char *ZoneBefore;

    if( HostsContainer_Init(&hc) != 0 )
    {
        printf("FAIL: HostsContainer_Init\n");
        return 1;
    }

    /* First entry: creates the shared IpAddr record and its persistent Zone. */
    if( hc.Load(&hc, "fe80::1%eth0 a.com") != HOSTS_TYPE_AAAA )
    {
        printf("FAIL: Load(a.com) failed\n");
        Ok = 0;
    }

    g_Zone = NULL; g_Ip = NULL;
    hc.Find(&hc, "a.com", HOSTS_TYPE_AAAA, OnFound, NULL);
    if( g_Ip == NULL )
    {
        printf("FAIL: a.com not found\n");
        Ok = 0;
    } else if( !IpAddr_HasZone(g_Ip) )
    {
        printf("FAIL: a.com record lost its zone\n");
        Ok = 0;
    }
    ZoneBefore = g_Zone;

    /* Second entry: same IP+zone, different name -> de-duplication hit on the
       shared record.  This must NOT re-allocate / rebind the Zone. */
    if( hc.Load(&hc, "fe80::1%eth0 b.com") != HOSTS_TYPE_AAAA )
    {
        printf("FAIL: Load(b.com) failed\n");
        Ok = 0;
    }

    const IpAddr *ipA = NULL, *ipB = NULL;
    g_Zone = NULL; g_Ip = NULL;
    hc.Find(&hc, "a.com", HOSTS_TYPE_AAAA, OnFound, NULL);
    ipA = g_Ip;
    const char *ZoneAfter = g_Zone;

    g_Zone = NULL; g_Ip = NULL;
    hc.Find(&hc, "b.com", HOSTS_TYPE_AAAA, OnFound, NULL);
    ipB = g_Ip;

    if( ipA == NULL )
    {
        printf("FAIL: a.com disappeared after b.com insert\n");
        Ok = 0;
    }
    if( ipB == NULL )
    {
        printf("FAIL: b.com not found\n");
        Ok = 0;
    }

    /* The two entries must share the SAME IpAddr record (de-dup works). */
    if( ipA != NULL && ipB != NULL && ipA != ipB )
    {
        printf("FAIL: duplicate IP was NOT de-duplicated\n");
        Ok = 0;
    }

    /* THE BUG: inserting b.com must not rebind a.com's Zone pointer. */
    if( ipA != NULL && ZoneBefore != NULL && ZoneAfter != NULL &&
        ZoneAfter != ZoneBefore )
    {
        printf("FAIL: a.com Zone pointer was rebound on de-dup hit "
               "(Zone leaked / shared record rewritten)\n");
        Ok = 0;
    }

    /* The rebound Zone must still compare equal in content. */
    if( ipA != NULL && ZoneBefore != NULL && ZoneAfter != NULL &&
        strcmp(ZoneAfter, ZoneBefore) != 0 )
    {
        printf("FAIL: Zone content changed after de-dup hit\n");
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
