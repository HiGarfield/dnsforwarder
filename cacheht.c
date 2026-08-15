#include <string.h>
#include <math.h>
#include <stdint.h>
#include "cacheht.h"
#include "common.h"
#include "utils.h"
#include "logs.h"

#define USED_GRADIENT   5   /* for rate diff */
#define IDLE_TIME_SEC   59  /* same as sweepping */

static int32_t  FreeNodeCount = 0;

typedef struct _Cht_Slot{
    int32_t Next;
} Cht_Slot;

static int CacheHT_CalculateSlotCount(int CacheSize)
{
    int PreValue;
    int Result;
    if( CacheSize < 1048576 )
    {
        PreValue = CacheSize / 4979 - 18;
    } else {
        PreValue = pow(log((double)CacheSize), 2);
    }

    /* Clamp negative pre-values (happens when CacheSize is small, e.g.
       below ~87 KB) to zero so we never return a negative or zero slot
       count. A negative/zero Used crashes CacheHT_Init (out-of-bounds
       Slots.Data, the `loop != Allocated` init loop never terminates or
       dereferences NULL) and later causes a modulo-by-zero in
       CacheHT_InsertToSlot / CacheHT_Get. */
    if( PreValue < 0 )
    {
        PreValue = 0;
    }

    Result = ROUND(PreValue, 10) + 7;
    return Result < 7 ? 7 : Result;
}

int CacheHT_Init(CacheHT *h, char *BaseAddr, int CacheSize)
{
    int loop;

    h->Slots.Used = CacheHT_CalculateSlotCount(CacheSize);
    h->Slots.DataLength = sizeof(Cht_Slot);
    h->Slots.Data = BaseAddr + CacheSize - (h->Slots.DataLength) * (h->Slots.Used);

    /* The slot table (and therefore the node chunk that grows downward from it)
       is placed at BaseAddr + CacheSize - sizeof(Cht_Slot) * Used.  Used is
       always odd (CacheHT_CalculateSlotCount ends in 7), so this sits at a
       4-byte offset, leaving every overlaid Cht_Node / Cht_2DList (which carry
       8-byte int64_t members and thus require 8-byte alignment) misaligned.
       Align the base down to 8 bytes so all cache node accesses are well
       defined instead of invoking undefined behaviour. */
    h->Slots.Data = (char *)((uintptr_t)h->Slots.Data & ~(uintptr_t)7);

    h->Slots.Allocated = h->Slots.Used;

    for(loop = 0; loop < h->Slots.Allocated; ++loop)
    {
        ((Cht_Slot *)Array_GetBySubscript(&(h->Slots), loop))->Next = -1;
    }

    h->NodeChunk.DataLength = sizeof(Cht_Node);
    h->NodeChunk.Data = h->Slots.Data - h->NodeChunk.DataLength;
    h->NodeChunk.Used = 0;
    h->NodeChunk.Allocated = -1;

    h->Free2DList = -1;

    return 0;
}

int CacheHT_ReInit(CacheHT *h, char *BaseAddr, int CacheSize)
{
    h->Slots.Data = BaseAddr + CacheSize - (h->Slots.DataLength) * (h->Slots.Used);
    /* Keep the slot/node base aligned to 8 bytes (see CacheHT_Init). */
    h->Slots.Data = (char *)((uintptr_t)h->Slots.Data & ~(uintptr_t)7);
    h->NodeChunk.Data = h->Slots.Data - h->NodeChunk.DataLength;

    return 0;
}

static int CacheHT_CreateNewNode(CacheHT *h, uint32_t ChunkSize, Cht_Node **Out, void *Boundary)
{
    int         NewNode_i;
    Cht_Node    *NewNode;

    Array       *NodeChunk = &(h->NodeChunk);

    NewNode_i = Array_PushBack(NodeChunk, NULL, Boundary);
    if( NewNode_i < 0 )
    {
        return -1;
    }

    NewNode = (Cht_Node *)Array_GetBySubscript(NodeChunk, NewNode_i);
    NewNode->Next = -1;

    NewNode->Length = ChunkSize;
    NewNode->UsedLength = 0;

    if( Out != NULL )
    {
        *Out = NewNode;
    }

    return NewNode_i;
}

int32_t CacheHT_FindUnusedNode(CacheHT      *h,
                               uint32_t     ChunkSize,
                               Cht_Node     **Out,
                               void         *Boundary,
                               BOOL         *NewCreated
                               )
{
    int32_t Subscript = h->Free2DList;
    int32_t PreSubscript = -1;
    Cht_2DList  *GrandHead = NULL;
    Cht_2DList  *PreHead = NULL;
    Cht_2DList  *CurHead = NULL;
    Cht_2DList  *HeirHead = NULL;
    Cht_Node    *CurNode = NULL;
    int count = 0;

    const Array *NodeChunk = &(h->NodeChunk);

    time_t Now = time(NULL);

    DEBUG("CacheHT free nodes: %d, start: %d, desire: %dB\n", FreeNodeCount, Subscript, ChunkSize);

    while( Subscript >= 0 )
    {
        CurNode = (Cht_Node *)Array_GetBySubscript(NodeChunk, Subscript);
        CurHead = (Cht_2DList *)CurNode;
        ++count;

        if( PreHead != NULL &&
            PreHead->Count > CurHead->Count &&
            Now - PreHead->TimeAdded >= IDLE_TIME_SEC
            )
        {
            PreHead->Count = CurHead->Count;
            PreHead->TimeAdded = Now;
        }
        /* Worst case: one of the most used types is consumed, then rejoins. */

        if( CurNode->Length == ChunkSize )
        {
            int32_t HeirSubscript;

            CurHead->TimeAdded = Now;
            CurHead->Count++;

            if( CurHead->ValNext >= 0 )
            {
                HeirSubscript = CurHead->ValNext;
                HeirHead = (Cht_2DList *)Array_GetBySubscript(NodeChunk, HeirSubscript);
            } else {
                HeirHead = NULL;
            }

            if( HeirHead == NULL )
            {
                /* Either there was no ValNext, or the ValNext pointed at a
                   subscript that has since been truncated away: when
                   CacheHT_RemoveFromSlot deletes the *last* node of the
                   NodeChunk it does `--(NodeChunk->Used)' instead of pushing
                   the node back onto the free 2D list, so any earlier node
                   of the same Length whose ValNext still referenced that
                   (now-invalid) subscript would otherwise make
                   Array_GetBySubscript() return NULL and the dereference
                   below crash. Follow KeyNext in that case. */
                HeirSubscript = CurHead->KeyNext;
                if( PreHead == NULL )
                {
                    h->Free2DList = HeirSubscript;
                } else {
                    PreHead->KeyNext = HeirSubscript;
                }
            } else {
                HeirHead->KeyNext = CurHead->KeyNext;
                HeirHead->TimeAdded = CurHead->TimeAdded;
                HeirHead->Count = CurHead->Count;

                if( PreHead == NULL )
                {
                    h->Free2DList = HeirSubscript;

                } else if( HeirHead->Count - PreHead->Count < USED_GRADIENT ) {
                    PreHead->KeyNext = HeirSubscript;

                } else {
                    /* Move ahead */
#ifdef DEV_DEBUG
                    DEBUG("CacheHT free 2D list Pop: %d, Swap: %d: %d <=> %d: %d\n",
                          Subscript,
                          PreSubscript,
                          PreHead->Count,
                          HeirSubscript,
                          HeirHead->Count
                          );
#endif
                    PreHead->KeyNext = HeirHead->KeyNext;
                    HeirHead->KeyNext = PreSubscript;
                    if( GrandHead == NULL )
                    {
                        h->Free2DList = HeirSubscript;
                    } else {
                        GrandHead->KeyNext = HeirSubscript;
                    }
                }
            }

            CurNode->UsedLength = 0;
            CurNode->Next = -1;

            if( Out != NULL )
            {
                *Out = CurNode;
            }

            *NewCreated = FALSE;
            --FreeNodeCount;

            DEBUG("CacheHT free node idx: %d\n", count);

            return Subscript;
        }

        GrandHead = PreHead;
        PreHead = CurHead;
        PreSubscript = Subscript;
        Subscript = CurHead->KeyNext;
    }

    DEBUG("CacheHT new node, groups: %d\n", count);

    *NewCreated = TRUE;
    return CacheHT_CreateNewNode(h, ChunkSize, Out, Boundary);
}

int CacheHT_InsertToSlot(CacheHT    *h,
                         const char *Key,
                         int        Node_index,
                         Cht_Node   *Node,
                         const uint32_t *HashValue
                         )
{
    int         Slot_i;
    Cht_Slot    *Slot;

    if( h == NULL || Key == NULL || Node_index < 0 || Node == NULL )
        return -1;

    if( HashValue != NULL )
    {
        Slot_i = (*HashValue) % (h->Slots.Allocated);
    } else {
        Slot_i = HASH(Key, 0) % (h->Slots.Allocated);
    }

    Node->Slot = Slot_i;

    Slot = (Cht_Slot *)Array_GetBySubscript(&(h->Slots), Slot_i);
    if( Slot == NULL )
        return -2;

    Node->Next = Slot->Next;
    Slot->Next = Node_index;

    return 0;
}

static Cht_Node *CacheHT_FindPredecessor(CacheHT *h, const Cht_Slot *Slot, int32_t SubScriptOfNode)
{
    int Next = Slot->Next;
    Cht_Node *Node;

    if( Next == SubScriptOfNode )
    {
        return NULL;
    }

    while( Next >= 0 )
    {
        Node = Array_GetBySubscript(&(h->NodeChunk), Next);
        Next = Node->Next;

        if( Next == SubScriptOfNode )
        {
            return Node;
        }
    }

    return NULL;
}

/*  PreHead --> (NewHead [+ CurHead]) --> NextHead
    NewHead --> CurHead
 */
static int CacheHT_AddTo2DList(CacheHT *h, int32_t SubScriptOfNode, Cht_Node *Node)
{
    int32_t Subscript = h->Free2DList;
    Cht_2DList  *PreHead = NULL;
    Cht_2DList  *CurHead = NULL;
    Cht_2DList  *NewHead = (Cht_2DList *)Node;
    Cht_Node    *CurNode = NULL;

    const Array *NodeChunk = &(h->NodeChunk);

    while( Subscript >= 0 )
    {
        PreHead = CurHead;
        CurNode = (Cht_Node *)Array_GetBySubscript(NodeChunk, Subscript);
        CurHead = (Cht_2DList *)CurNode;
        if( CurNode->Length == Node->Length )
        {
            NewHead->KeyNext = CurHead->KeyNext;
            NewHead->Count = CurHead->Count;
            break;
        }

        Subscript = CurHead->KeyNext;
    }

#if 1
    if( Subscript == -1 )
    {
        /* New, as head */
        NewHead->KeyNext = h->Free2DList;
        NewHead->Count = 0;
        h->Free2DList = SubScriptOfNode;
    } else if( PreHead == NULL ) {
        /* To be the head of the existing head */
        h->Free2DList = SubScriptOfNode;
    } else {
        /* To be the head of the existing non-head */
        PreHead->KeyNext = SubScriptOfNode;
    }

#else
    if( Subscript == -1 )
    {
        /* New, as tail */
        NewHead->KeyNext = -1;
        NewHead->Count = 0;
        if( CurHead == NULL )
        {
            /* head */
            h->Free2DList = SubScriptOfNode;
        } else {
            CurHead->KeyNext = SubScriptOfNode;
        }
    } else {
        /* To be the head of the existing */
        if( PreHead == NULL )
        {
            /* head */
            h->Free2DList = SubScriptOfNode;
        } else {
            PreHead->KeyNext = SubScriptOfNode;
        }
    }
#endif

    NewHead->ValNext = Subscript;

#ifdef DEV_DEBUG
    DEBUG("CacheHT AddTo2DList: Free2DList=%d, PreKeyNext=%d, NewHead->KeyNext=%d, NewHead->ValNext=%d, Length=%d\n",
          h->Free2DList,
          SubScriptOfNode,
          NewHead->KeyNext,
          NewHead->ValNext,
          Node->Length);
#endif

    return 0;
}

int CacheHT_RemoveFromSlot(CacheHT *h, int32_t SubScriptOfNode, Cht_Node *Node)
{
    Cht_Slot    *Slot;
    Cht_Node    *Predecessor;

    if( Node->Slot < 0 )
    {
        return 0;
    }

    Slot = (Cht_Slot *)Array_GetBySubscript(&(h->Slots), Node->Slot);
    if( Slot == NULL )
    {
        return -1;
    }

    Predecessor = CacheHT_FindPredecessor(h, Slot, SubScriptOfNode);
    if( Predecessor == NULL )
    {
        Slot->Next = Node->Next;
    } else {
        Predecessor->Next = Node->Next;
    }

    /* Every removed node is returned to the free 2D list, regardless of
       whether it was the last one in the NodeChunk. Previously the last node
       was simply dropped with `--(NodeChunk->Used)', but a node that had
       already been freed earlier (and was therefore still referenced by some
       other node's KeyNext/ValNext inside the free list) could become the
       last node, get its subscript truncated away, and then be dereferenced
       as a NULL pointer the next time the free list was walked
       (CacheHT_FindUnusedNode). Reusing freed nodes through the free list also
       keeps the allocation count correct without ever handing out a subscript
       that is no longer backed by `Used'. */
    CacheHT_AddTo2DList(h, SubScriptOfNode, Node);
    ++FreeNodeCount;

    return 0;
}

Cht_Node *CacheHT_Get(CacheHT *h, const char *Key, const Cht_Node *Start, const uint32_t *HashValue)
{
    Cht_Node    *Node;

    if( h == NULL || Key == NULL)
        return NULL;

    if( Start == NULL )
    {
        int         Slot_i;
        Cht_Slot    *Slot;

        if( HashValue != NULL )
        {
            Slot_i = (*HashValue) % (h->Slots.Allocated);
        } else {
            Slot_i = HASH(Key, 0) % (h->Slots.Allocated);
        }

        Slot = (Cht_Slot *)Array_GetBySubscript(&(h->Slots), Slot_i);

        if( Slot->Next < 0 )
        {
            /* Empty slot: no node chains off it. Array_GetBySubscript with a
               negative subscript would hand back an out-of-bounds pointer
               (not NULL), so bail out before dereferencing it. */
            return NULL;
        }

        Node = (Cht_Node *)Array_GetBySubscript(&(h->NodeChunk), Slot->Next);
        if( Node == NULL )
            return NULL;

        return Node;

    } else {
        if( Start->Next < 0 )
        {
            /* Reached the end of the slot's linked list. Array_GetBySubscript
               with a negative subscript would hand back an out-of-bounds
               pointer (not NULL), which the caller would then dereference.
               Signal the end of the chain explicitly. */
            return NULL;
        }
        Node = (Cht_Node *)Array_GetBySubscript(&(h->NodeChunk), Start->Next);
        if( Node == NULL )
            return NULL;

        return Node;
    }

}

void CacheHT_Free(CacheHT *h)
{
    /* The NodeChunk and Slots arrays do not own their backing memory: their
       `Data` pointers are offsets inside the single `BaseAddr` block that the
       caller (DNSCache) allocates and frees as a whole. Calling Array_Free
       here would SafeFree() an interior pointer of that block, corrupting the
       heap. Only reset the bookkeeping; the caller frees BaseAddr itself. */
    h->NodeChunk.Data = NULL;
    h->NodeChunk.Used = 0;
    h->Slots.Data = NULL;
    h->Slots.Used = 0;
    h->Free2DList = -1;
}
