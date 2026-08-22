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

/* Validate a CacheHT that was read verbatim out of the on-disk cache file.
   Every field below -- the two Array headers, Free2DList, and each Cht_Node --
   comes straight from that file, which is a plain file that a crash can
   truncate, that can be corrupted on disk, or that can simply be edited.

   The cache *read* paths already range-check Node->Offset before dereferencing
   it, but the *write* paths do not:

       dnscache.c, DNSCacheTTLCountdown_Task:
           *(unsigned char *)(MapStart + Node->Offset) = 0xFD;
       dnscache.c, DNSCache_GetAvailableChunk:
           memset(MapStart + Node->Offset + Length, 0xFE, RoundedLength - Length);

   With an out-of-range Offset those two statements write outside the mapping.
   Subscript fields are just as dangerous: CacheHT_RemoveFromSlot indexes
   h->Slots with Node->Slot, and the slot chains are walked through Node->Next,
   so a bogus subscript reads or writes arbitrary memory near the mapping.

   `DataOffsetMin` is the first byte the records may occupy (the size of the
   caller's file header) and `CacheSize` is the size of the whole mapping.
   Returns TRUE only when the structure is entirely self-consistent.

   Note that h->Slots.Data / h->NodeChunk.Data still hold the raw pointer values
   written by the previous process and must not be dereferenced, so the bases
   are recomputed here exactly the way CacheHT_ReInit does. */
BOOL CacheHT_IsStructureSane(const CacheHT *h,
                             const char *BaseAddr,
                             int CacheSize,
                             int DataOffsetMin,
                             int DataEnd
                             )
{
    const Array *NodeChunk = &(h->NodeChunk);
    const Array *Slots = &(h->Slots);
    const char *SlotBase;
    const char *NodeBase;
    size_t SlotBytes;
    size_t NodeBytes;
    int loop;

    if( BaseAddr == NULL || CacheSize <= 0 || DataOffsetMin < 0 )
    {
        return FALSE;
    }

    /* The record high-water mark must lie between the header and the map end. */
    if( DataEnd < DataOffsetMin || DataEnd > CacheSize )
    {
        return FALSE;
    }

    /* Slots is a grow-up array of Cht_Slot pinned at the top of the mapping,
       fully allocated by CacheHT_Init. */
    if( Slots->DataLength != (int)sizeof(Cht_Slot) ||
        Slots->Used <= 0 ||
        Slots->Allocated != Slots->Used )
    {
        return FALSE;
    }

    /* NodeChunk grows downward from just below the slot table, so it always
       carries the Allocated == -1 sentinel. */
    if( NodeChunk->DataLength != (int)sizeof(Cht_Node) ||
        NodeChunk->Allocated >= 0 ||
        NodeChunk->Used < 0 )
    {
        return FALSE;
    }

    /* The slot table, every node, and the record region must all fit in the
       mapping without overlapping each other. All arithmetic is done in size_t
       with subtraction only, so nothing can wrap. */
    SlotBytes = sizeof(Cht_Slot) * (size_t)Slots->Used;
    NodeBytes = sizeof(Cht_Node) * (size_t)NodeChunk->Used;

    if( SlotBytes > (size_t)CacheSize ||
        NodeBytes > (size_t)CacheSize - SlotBytes ||
        (size_t)DataEnd > (size_t)CacheSize - SlotBytes - NodeBytes )
    {
        return FALSE;
    }

    if( h->Free2DList < -1 || h->Free2DList >= NodeChunk->Used )
    {
        return FALSE;
    }

    SlotBase = (const char *)((uintptr_t)(BaseAddr + CacheSize - SlotBytes)
                              & ~(uintptr_t)7);
    NodeBase = SlotBase - sizeof(Cht_Node);

    for( loop = 0; loop < NodeChunk->Used; ++loop )
    {
        const Cht_Node *Node =
            (const Cht_Node *)(NodeBase - sizeof(Cht_Node) * (size_t)loop);

        /* The record must start inside the data region and must not run past
           the end of the mapping.  The upper bound is exclusive: the write
           paths (DNSCacheTTLCountdown_Task writing 0xFD at MapStart+Offset,
           DNSCache_GetAvailableChunk memsetting at MapStart+Offset+Length)
           write at Offset and Offset+Length, so Offset == CacheSize would
           write one byte past the mapping. */
        if( Node->Offset < DataOffsetMin || Node->Offset >= CacheSize )
        {
            return FALSE;
        }

        if( (uint32_t)Node->Length > (uint32_t)CacheSize ||
            (uint32_t)Node->Offset > (uint32_t)CacheSize - Node->Length )
        {
            return FALSE;
        }

        if( Node->UsedLength > Node->Length )
        {
            return FALSE;
        }

        /* -1 terminates a chain; anything else must index a real element. */
        if( Node->Slot < -1 || Node->Slot >= Slots->Used )
        {
            return FALSE;
        }

        if( Node->Next < -1 || Node->Next >= NodeChunk->Used )
        {
            return FALSE;
        }
    }

    for( loop = 0; loop < Slots->Used; ++loop )
    {
        const Cht_Slot *Slot =
            (const Cht_Slot *)(SlotBase + sizeof(Cht_Slot) * (size_t)loop);
        int hops = 0;
        int sub;

        if( Slot->Next < -1 || Slot->Next >= NodeChunk->Used )
        {
            return FALSE;
        }

        /* Each slot heads a linked list of nodes (via Cht_Node.Next).  The
           bounds are validated above; additionally reject cyclic chains,
           which would make CacheHT_Get()'s walkers and
           CacheHT_FindPredecessor() (CacheHT_RemoveFromSlot) loop forever on
           the corrupted file.  A chain without repetition can hold at most
           NodeChunk->Used distinct nodes, so more hops than that prove a
           cycle. */
        sub = Slot->Next;
        while( sub >= 0 )
        {
            const Cht_Node *N;

            if( ++hops > NodeChunk->Used )
            {
                return FALSE;
            }

            N = (const Cht_Node *)(NodeBase - sizeof(Cht_Node) * (size_t)sub);
            sub = N->Next;
        }
    }

    /* The per-node check above bounds Node->Slot by Slots->Used, which is the
       correct bound for a node living on a slot chain but the wrong one for a
       node on the free 2D list: there the same memory is overlaid with
       Cht_2DList, whose offset-0 field (overlaying Cht_Node.Slot) is
       `KeyNext' -- a NodeChunk subscript, not a slot subscript.  A corrupted
       KeyNext in [NodeChunk->Used, Slots->Used) slips past the generic Slot
       check; when the cache is next used, CacheHT_FindUnusedNode() /
       CacheHT_AddTo2DList() walk the free list through that KeyNext, call
       Array_GetBySubscript() with it, get NULL back and dereference it,
       crashing on a merely-corrupted cache file.  Walk the free list
       explicitly: every hop must name a real node (KeyNext and ValNext
       alike) and the chain must terminate before it can cycle. */
    {
        int hops = 0;
        int sub = h->Free2DList;

        while( sub >= 0 )
        {
            const Cht_Node *N;

            /* A valid chain visits each node at most once; more hops than
               nodes means a cycle. */
            if( ++hops > NodeChunk->Used )
            {
                return FALSE;
            }

            if( sub >= NodeChunk->Used )
            {
                /* KeyNext names a node the chunk does not hold. */
                return FALSE;
            }

            N = (const Cht_Node *)(NodeBase - sizeof(Cht_Node) * (size_t)sub);

            /* KeyNext (overlaid on Node->Slot) and ValNext (overlaid on
               Node->Next) must both name real nodes or terminate the chain.
               ValNext additionally holds for a node that is not (yet) reachable
               from Free2DList but would become so later, so requiring both to
               stay inside the chunk is the safe bound. */
            if( N->Slot < -1 || N->Slot >= NodeChunk->Used ||
                N->Next < -1 || N->Next >= NodeChunk->Used )
            {
                return FALSE;
            }

            sub = N->Slot;  /* follow KeyNext */
        }
    }

    return TRUE;
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
