/* ModuleContext_Del() must be given the pointer ModuleContext_Add() returned.
 *
 * Bst_Delete() reaches its node header through ((Bst_NodeHead *)Node) - 1 and
 * then writes through that header's Left/Right/Parent links. Add() returns a
 * pointer to the copy living inside the node, so it is the only valid argument.
 * UdpM_Send() used to roll its context entry back with the caller's receive
 * buffer instead, which made Bst_Delete() interpret whatever preceded that
 * buffer as a node header and relink the tree through the resulting garbage.
 *
 * mode "contract" : Add/Del/Find cycles using the Add() result stay consistent.
 * mode "bad"      : Del() with the caller's buffer touches memory in front of
 *                   it, which a sanitizer build reports. Used as the negative
 *                   control; run.sh expects this to be diagnosed, not to pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mcontext.h"
#include "iheader.h"
#include "dnsgenerator.h"

#define ENTITY_OFFSET   ((int)sizeof(IHeader))

static void BuildQuery(char *Buffer, int Id, const char *Domain)
{
    IHeader *h = (IHeader *)Buffer;
    DnsGenerator g;

    memset(Buffer, 0, SOCKET_CONTEXT_LENGTH);

    if( DnsGenerator_Init(&g,
                          Buffer + ENTITY_OFFSET,
                          SOCKET_CONTEXT_LENGTH - ENTITY_OFFSET,
                          NULL,
                          0,
                          FALSE
                          )
       != 0 )
    {
        fprintf(stderr, "DnsGenerator_Init failed\n");
        exit(2);
    }

    /* DnsGenerator_Init already zeroed the four record counts and put Itr past
       the header, so only the identifier is left to fill in. */
    g.SetIdentifier(&g, (uint16_t)Id);
    if( g.Question(&g, Domain, DNS_TYPE_A, DNS_CLASS_IN) != 0 )
    {
        fprintf(stderr, "Question failed\n");
        exit(2);
    }

    h->EntityLength = g.Length(&g);
    h->BackAddress.family = AF_INET;    /* pretend UDP, keeps it out of TCP paths */
    h->SendBackSocket = 0;
    h->Parent = NULL;
    h->RequestTcp = FALSE;
    h->EDNSEnabled = FALSE;
    strcpy(h->Domain, Domain);
    h->HashValue = 0;
    strcpy(h->Agent, "t");
}

int main(int argc, char **argv)
{
    const char *Mode = argc > 1 ? argv[1] : "contract";
    ModuleContext c;
    char *Buffer;
    int i;

    if( ModuleContext_Init(&c, SOCKET_CONTEXT_LENGTH) != 0 )
    {
        fprintf(stderr, "ModuleContext_Init failed\n");
        return 2;
    }

    /* Heap allocated and exactly SOCKET_CONTEXT_LENGTH long, like the receive
       buffers the frontends hand to the modules. */
    Buffer = malloc(SOCKET_CONTEXT_LENGTH);
    if( Buffer == NULL )
    {
        return 2;
    }

    if( strcmp(Mode, "bad") == 0 )
    {
        MsgContext *Stored;

        BuildQuery(Buffer, 0x1234, "bad.example.com");
        Stored = c.Add(&c, (MsgContext *)Buffer);
        if( Stored == NULL )
        {
            fprintf(stderr, "Add failed\n");
            return 2;
        }

        /* The defect: roll back with the caller's buffer. Bst_Delete() reads a
           Bst_NodeHead from in front of Buffer and relinks the tree with it. */
        c.Del(&c, (MsgContext *)Buffer);

        /* If nothing complained, keep using the tree so the damage surfaces. */
        for( i = 0; i < 64; ++i )
        {
            char Domain[64];
            sprintf(Domain, "after%d.example.com", i);
            BuildQuery(Buffer, 0x2000 + i, Domain);
            c.Add(&c, (MsgContext *)Buffer);
        }
        printf("bad mode completed without diagnosis\n");
        free(Buffer);
        ModuleContext_Free(&c);
        return 0;
    }

    /* mode "contract": the fixed usage. */
    for( i = 0; i < 512; ++i )
    {
        char Domain[64];
        MsgContext *Stored;
        const MsgContext *Found;

        sprintf(Domain, "q%d.example.com", i);
        BuildQuery(Buffer, 0x1000 + (i & 0xff), Domain);

        Stored = c.Add(&c, (MsgContext *)Buffer);
        if( Stored == NULL )
        {
            fprintf(stderr, "Add failed at %d\n", i);
            return 1;
        }
        if( Stored == (MsgContext *)Buffer )
        {
            fprintf(stderr, "Add returned the caller's buffer at %d\n", i);
            return 1;
        }

        /* The stored copy must be findable ... */
        Found = c.Find(&c, (MsgContext *)Buffer);
        if( Found == NULL )
        {
            fprintf(stderr, "Find missed the entry it just stored at %d\n", i);
            return 1;
        }

        /* ... and removing it through the Add() result must leave the tree in a
           state where it is gone and later lookups still work. */
        c.Del(&c, Stored);

        Found = c.Find(&c, (MsgContext *)Buffer);
        if( Found != NULL )
        {
            fprintf(stderr, "entry still present after Del at %d\n", i);
            return 1;
        }
    }

    /* Interleave: hold several entries at once, then drain them, so Bst_Delete
       exercises nodes with one and two children. */
    {
        MsgContext *Held[32];
        char Domains[32][64];

        for( i = 0; i < 32; ++i )
        {
            sprintf(Domains[i], "held%d.example.com", i);
            BuildQuery(Buffer, 0x3000 + i, Domains[i]);
            Held[i] = c.Add(&c, (MsgContext *)Buffer);
            if( Held[i] == NULL )
            {
                fprintf(stderr, "Add failed while filling at %d\n", i);
                return 1;
            }
        }

        for( i = 0; i < 32; ++i )
        {
            BuildQuery(Buffer, 0x3000 + i, Domains[i]);
            if( c.Find(&c, (MsgContext *)Buffer) == NULL )
            {
                fprintf(stderr, "held entry %d disappeared\n", i);
                return 1;
            }
        }

        /* Delete in an order that hits the two-children case. */
        for( i = 31; i >= 0; i -= 2 )
        {
            c.Del(&c, Held[i]);
        }
        for( i = 0; i < 32; i += 2 )
        {
            c.Del(&c, Held[i]);
        }

        for( i = 0; i < 32; ++i )
        {
            BuildQuery(Buffer, 0x3000 + i, Domains[i]);
            if( c.Find(&c, (MsgContext *)Buffer) != NULL )
            {
                fprintf(stderr, "held entry %d survived Del\n", i);
                return 1;
            }
        }
    }

    free(Buffer);
    ModuleContext_Free(&c);

    printf("ModuleContext Add/Del/Find contract holds\n");
    return 0;
}
