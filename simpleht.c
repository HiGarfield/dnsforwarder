#include <string.h>
#include <stdint.h>
#include "simpleht.h"

typedef struct _Sht_Slot{
    int32_t Next;
} Sht_Slot;

static const Sht_Slot EmptySlot = {-1};

int SimpleHT_Init(SimpleHT *ht, int DataLength, size_t MaxLoadFactor, uint32_t (*HashFunction)(const char *, uint32_t))
{
    int loop;

    if( Array_Init(&(ht->Slots), sizeof(Sht_Slot), 7, FALSE, NULL) != 0 )
    {
        return -1;
    }

    for( loop = 0; loop != 7; ++loop )
    {
        Array_PushBack(&(ht->Slots), &EmptySlot, NULL);
    }

    if( Array_Init(&(ht->Nodes), sizeof(Sht_NodeHead) + DataLength, 0, FALSE, NULL) != 0 )
    {
        Array_Free(&(ht->Slots));
        return -2;
    }

    ht->MaxLoadFactor = MaxLoadFactor;
    ht->LeftSpace = 7 * MaxLoadFactor;
    ht->HashFunction = HashFunction;

    return 0;
}

static int SimpleHT_AddToSlot(SimpleHT *ht, Sht_NodeHead *Node, int NodeSubscript)
{
    int NumberOfSlots = Array_GetUsed(&(ht->Slots));
    Sht_Slot *TheSlot;

    if( Node == NULL || NumberOfSlots <= 0 )
    {
        return -1;
    }

    TheSlot = Array_GetBySubscript(&(ht->Slots), Node->HashValue % NumberOfSlots);
    if( TheSlot == NULL )
    {
        return -1;
    }

    Node->Next = TheSlot->Next;
    TheSlot->Next = NodeSubscript;

    return 0;
}

static int SimpleHT_Expand(SimpleHT *ht)
{
    int NumberOfSlots_Old = Array_GetUsed(&(ht->Slots));
    int NumberOfNodes = Array_GetUsed(&(ht->Nodes));
    Sht_NodeHead *nh = NULL;
    int loop;

    for( loop = 0; loop < NumberOfSlots_Old; ++loop )
    {
        if( Array_PushBack(&(ht->Slots), &EmptySlot, NULL) < 0 )
        {
            /* Roll back the slots added so far, otherwise the table is
               left with a slot count that no longer matches the chains
               hanging off it. */
            ht->Slots.Used = NumberOfSlots_Old;
            return -1;
        }
    }

    /* Reset every slot, both the pre-existing ones and the ones just
       appended, before the nodes are redistributed below.

       The byte count is the product of two `int`s; compute it in `size_t`
       and reject an overflowing request instead of letting the multiplication
       wrap to a small/negative value and silently under-clearing the slot
       array (which would leave stale node indices and corrupt the chains). */
    {
        size_t  Used    = (size_t)Array_GetUsed(&(ht->Slots));
        size_t  ElemLen = (size_t)ht->Slots.DataLength;
        size_t  Bytes;

        if( ElemLen != 0 && Used > SIZE_MAX / ElemLen )
        {
            ht->Slots.Used = NumberOfSlots_Old;
            return -1;
        }
        Bytes = Used * ElemLen;
        memset(ht->Slots.Data, -1, Bytes);
    }

    for( loop = 0; loop < NumberOfNodes; ++loop )
    {
        nh = Array_GetBySubscript(&(ht->Nodes), loop);
        if( nh == NULL )
        {
            continue;
        }

        SimpleHT_AddToSlot(ht, nh, loop);
    }

    return 0;
}

const char *SimpleHT_Add(SimpleHT *ht, const char *Key, int KeyLength, const char *Data, const uint32_t *HashValue)
{
    Sht_NodeHead *New;
    int NewSubscript;

    if( ht->LeftSpace == 0 )
    {
        int NumberOfSlots_Old = Array_GetUsed(&(ht->Slots));

        if( SimpleHT_Expand(ht) != 0 )
        {
            return NULL;
        }

        /* Only the slots that were just added contribute new capacity;
           the pre-existing ones are already accounted for. */
        ht->LeftSpace = (Array_GetUsed(&(ht->Slots)) - NumberOfSlots_Old)
                        * ht->MaxLoadFactor;
    }

    NewSubscript = Array_PushBack(&(ht->Nodes), NULL, NULL);
    if( NewSubscript < 0 )
    {
        return NULL;
    }

    New = Array_GetBySubscript(&(ht->Nodes), NewSubscript);
    if( New == NULL )
    {
        return NULL;
    }

    if( HashValue == NULL )
    {
        New->HashValue = (ht->HashFunction)(Key, KeyLength);
    } else {
        New->HashValue = *HashValue;
    }

    memcpy(New + 1, Data, ht->Nodes.DataLength - sizeof(Sht_NodeHead));

    SimpleHT_AddToSlot(ht, New, NewSubscript);

    --(ht->LeftSpace);

    return (const char *)(New + 1);
}

const char *SimpleHT_Find(SimpleHT *ht, const char *Key, int KeyLength, const uint32_t *HashValue, const char *Start)
{
    int NumberOfSlots = Array_GetUsed(&(ht->Slots));
    Sht_NodeHead *Node;

    if( NumberOfSlots <= 0 )
    {
        return NULL;
    }

    if( Start != NULL )
    {
        Node = Array_GetBySubscript(&(ht->Nodes), (((Sht_NodeHead *)Start) - 1)->Next);
    } else {
        Sht_Slot *TheSlot;
        int SlotNumber;

        if( HashValue == NULL )
        {
            SlotNumber = (ht->HashFunction)(Key, KeyLength) % NumberOfSlots;
        } else {
            SlotNumber = (*HashValue) % NumberOfSlots;
        }

        TheSlot = Array_GetBySubscript(&(ht->Slots), SlotNumber);
        if( TheSlot == NULL )
        {
            return NULL;
        }

        Node = Array_GetBySubscript(&(ht->Nodes), TheSlot->Next);
    }

    if( Node == NULL )
    {
        return NULL;
    }

    return (const char *)(Node + 1);

}

const char *SimpleHT_Enum(SimpleHT *ht, int32_t *Start)
{
    const Array *Nodes = &(ht->Nodes);
    const Sht_NodeHead *Node;

    Node = Array_GetBySubscript(Nodes, *Start);

    if( Node != NULL )
    {
        ++(*Start);
        return (const char *)(Node + 1);
    } else {
        return NULL;
    }
}

void SimpleHT_Free(SimpleHT *ht)
{
    Array_Free(&(ht->Slots));
    Array_Free(&(ht->Nodes));
}
