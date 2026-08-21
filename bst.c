#include <string.h>
#include <assert.h>
#include "bst.h"
#include "utils.h"
#include "logs.h"

PRIFUNC Bst_NodeHead *GetUnusedNode(Bst *t)
{
    if( t->FreeList == NULL )
    {
        return t->Nodes.Add(&(t->Nodes),
                            NULL,
                            sizeof(Bst_NodeHead) + t->ElementLength,
                            TRUE
                            );
    } else {
        Bst_NodeHead *ret = t->FreeList;

        t->FreeList = ret->Right;

        return ret;
    }
}

PRIFUNC const void *InsertNode(Bst          *t,
                               Bst_NodeHead *ParentNode,
                               int          CompareResult,
                               const void   *Data
                               )
{
    Bst_NodeHead *NewNode = GetUnusedNode(t);

    if( NewNode == NULL )
    {
        return NULL;
    }

    /* Set parent node */
    if( ParentNode == NULL )
    {
        /* Insert as the root */
        t->Root = NewNode;
    } else {
        /* Non-root */
        if( CompareResult <= 0 )
        {
            assert(ParentNode->Left == NULL);
            ParentNode->Left = NewNode;
        } else {
            assert(ParentNode->Right == NULL);
            ParentNode->Right = NewNode;
        }
    }

    /* Set the new child node */
    NewNode->Parent = ParentNode;
    NewNode->Left = NULL;
    NewNode->Right = NULL;

    /* Copy the data */
    memcpy(NewNode + 1, Data, t->ElementLength);

    /* Return the data position */
    return (const void *)(NewNode + 1);
}

PUBFUNC const void *Bst_Add(Bst *t, const void *Data)
{
    if( t->Root == NULL )
    {
        /* Insert as root */
        return InsertNode(t, NULL, 0, Data);
    } else {
        /* Non-root, finding the currect place to insert */
        Bst_NodeHead *Current = t->Root;

        while( TRUE )
        {
            int CompareResult = (t->Compare)(Data, (const void *)(Current + 1));

            if( CompareResult <= 0 )
            {
                /* Left branch */
                Bst_NodeHead *Left = Current->Left;
                if( Left == NULL )
                {
                    /* Insert as a left child */
                    return InsertNode(t, Current, CompareResult, Data);
                }

                Current = Left;
            } else {
                /* Right branch */
                Bst_NodeHead *Right = Current->Right;
                if( Right == NULL )
                {
                    /* Insert as a right child */
                    return InsertNode(t, Current, CompareResult, Data);
                }

                Current = Right;
            }
        }
    }
}

/* Bst_Search() is meant to enumerate every node whose key compares equal to
   `Key`: call it repeatedly with the previously returned match as `Last`
   until it returns NULL.  The continuation rule below relies on Bst_Add()
   inserting equal keys into the LEFT subtree (CompareResult <= 0 goes left):

     1. No node whose key equals `Key` can ever live in the RIGHT subtree of
        another such node (an equal key inserted later compares 0 against it
        and always turns left).  Hence, once a match `Last` has been found,
        every remaining match is confined to `Last`'s left subtree.
     2. The first call (Last == NULL) hits the topmost equal node, and all
        other equal keys are descendants of it (they all follow the same
        comparison path and branch left at the first equal node).

   Therefore "restart a normal search from Last's left child" visits every
   equal node exactly once, in the order they were inserted, and cannot loop:
   each returned match is a strict descendant of the previous one.  Resuming
   from the in-order successor instead is WRONG: it skips equal keys that the
   equal-goes-left rule placed in Last's left subtree (verified by the
   duplicate-key regression test in test/bst_invariant). */
PUBFUNC const void *Bst_Search(Bst *t, const void *Key, const void *Last)
{
    Bst_NodeHead *Current;

    /* Set the starting point */
    if( Last == NULL )
    {
        /* root as the starting point */
        Current = t->Root;
    } else {
        /* Continuing a previous match: every remaining equal key lives in
           the left subtree of `Last` (see comment above). */
        Current = (((Bst_NodeHead *)Last) - 1)->Left;
    }

    while( Current != NULL )
    {
        int CompareResult = (t->Compare)(Key, (const void *)(Current + 1));

        if( CompareResult == 0 )
        {
            return (const void *)(Current + 1);
        } else if( CompareResult < 0 ){
            Current = Current->Left;
        } else /** CompareResult > 0 */{
            Current = Current->Right;
        }
    }

    return NULL;
}

#define BST_ENUM_STACK_CAPACITY 64

/* Push a node onto the explicit walk stack, growing it if needed.  Returns 0
   on success, -1 if the (re)allocation fails. */
PRIFUNC int Bst_Enum_Push(Bst_NodeHead ***Stack,
                          size_t *StackCap,
                          size_t *Top,
                          Bst_NodeHead *Node
                          )
{
    if( *Top >= *StackCap )
    {
        Bst_NodeHead **NewStack;
        size_t NewCap = (*StackCap) * 2;

        NewStack = (Bst_NodeHead **)realloc(*Stack,
                                            NewCap * sizeof(Bst_NodeHead *)
                                            );
        if( NewStack == NULL )
        {
            return -1;
        }
        *Stack = NewStack;
        *StackCap = NewCap;
    }

    (*Stack)[(*Top)++] = Node;
    return 0;
}

PUBFUNC void Bst_Enum(Bst *t, Bst_Enum_Callback cb, void *Arg)
{
    /* The old implementation walked the tree recursively.  A BST has no
       balancing invariant here, so a sorted insertion produces a degenerate
       tree whose depth equals the node count; on a large dataset the recursive
       pre-order walk then blows the stack.  Use an explicit stack instead. */
    Bst_NodeHead **Stack;
    size_t StackCap = BST_ENUM_STACK_CAPACITY;
    size_t Top = 0;                 /* number of elements currently on the stack */
    BOOL StopFlag = FALSE;

    if( t == NULL || cb == NULL )
    {
        return;
    }

    Stack = (Bst_NodeHead **)malloc(StackCap * sizeof(Bst_NodeHead *));
    if( Stack == NULL )
    {
        return;
    }

    if( t->Root != NULL )
    {
        Stack[Top++] = t->Root;
    }

    while( Top != 0 )
    {
        Bst_NodeHead *n = Stack[--Top];

        /* Same stop semantics as the recursive version: a node whose callback
           returns non-zero stops the walk and its subtree is never visited. */
        if( StopFlag )
        {
            break;
        }

        StopFlag = cb(t, n + 1, Arg) != 0;

        /* Push children so the left subtree is processed first (pre-order,
           exactly like the old recursive traversal order). */
        if( n->Right != NULL )
        {
            if( Bst_Enum_Push(&Stack, &StackCap, &Top, n->Right) != 0 )
            {
                free(Stack);
                return;
            }
        }
        if( n->Left != NULL )
        {
            if( Bst_Enum_Push(&Stack, &StackCap, &Top, n->Left) != 0 )
            {
                free(Stack);
                return;
            }
        }
    }

    free(Stack);
}

PUBFUNC const void *Bst_Minimum(Bst *t, const void *Subtree)
{
    Bst_NodeHead *Current;

    if( Subtree == NULL )
    {
        /* Starting with the root */
        if( t->Root == NULL )
        {
            /* Empty tree */
            return NULL;
        }

        Current = t->Root;
    } else {
        Current = ((Bst_NodeHead *)Subtree) - 1;
    }

    while( Current->Left != NULL )
    {
        Current = Current->Left;
    }

    return (const void *)(Current + 1);
}

PUBFUNC const void *Bst_Successor(Bst *t, const void *Last)
{
    Bst_NodeHead *Current = ((Bst_NodeHead *)Last) - 1;

    if( Current->Right != NULL )
    {
        return Bst_Minimum(t, (Current->Right) + 1);
    } else {
        Bst_NodeHead *Parent = Current->Parent;

        while( Parent != NULL && Parent->Left != Current )
        {
            Current = Parent;
            Parent = Parent->Parent;
        }

        return Parent == NULL ? NULL : (const void *)(Parent + 1);
    }
}

PUBFUNC void Bst_Delete(Bst *t, const void *Node)
{
    Bst_NodeHead *Current = ((Bst_NodeHead *)Node) - 1;
    Bst_NodeHead *ActuallyRemoved, *Child;

    /* Finding the node that will be actually removed. */
    if( Current->Left == NULL || Current->Right == NULL )
    {
        /* If Current has one or no child */
        ActuallyRemoved = Current;
    } else {
        /* If Current has two child */
        ActuallyRemoved = ((Bst_NodeHead *)Bst_Successor(t, Current + 1)) - 1;
    }

    /* If ActuallyRemoved:
        has two child, impossible case,
        has only one child, get the child,
        or no child, set it to NULL
    */
    if( ActuallyRemoved->Left != NULL )
    {
        Child = ActuallyRemoved->Left;
    } else {
        Child = ActuallyRemoved->Right;
    }

    /* If ActuallyRemoved has one child ( Child != NULL ) */
    if( Child != NULL )
    {
        /* Set the child's parent to its parent's parent */
        Child->Parent = ActuallyRemoved->Parent;
    }

    if( ActuallyRemoved->Parent == NULL )
    {
        /* If ActuallyRemoved is the root */

        t->Root = Child;
    } else {
        /* Or not the root */

        if( ActuallyRemoved->Parent->Left == ActuallyRemoved )
        {
            /* If ActuallyRemoved is a left child */
            ActuallyRemoved->Parent->Left = Child;
        } else {
            /* Or a right child */
            ActuallyRemoved->Parent->Right = Child;
        }
    }

    if( ActuallyRemoved != Current )
    {
        /* Replace Current with ActuallyRemoved */

        /*memcpy(Current + 1, ActuallyRemoved + 1, t->ElementLength);*/

        Bst_NodeHead *CurrentParent = Current->Parent;
        Bst_NodeHead *CurrentLeft = Current->Left;
        Bst_NodeHead *CurrentRight = Current->Right;

        /* Parent */
        if( CurrentParent != NULL )
        {
            if( CurrentParent->Left == Current )
            {
                CurrentParent->Left = ActuallyRemoved;
            } else {
                CurrentParent->Right = ActuallyRemoved;
            }
        } else {
            t->Root = ActuallyRemoved;
        }

        /* Left Child */
        CurrentLeft->Parent = ActuallyRemoved;

        /* Right Child */
        if( CurrentRight != NULL )
        {
            CurrentRight->Parent = ActuallyRemoved;
        }

        /* ActuallyRemoved */
        ActuallyRemoved->Parent = CurrentParent;
        ActuallyRemoved->Left = CurrentLeft;
        ActuallyRemoved->Right = CurrentRight;

        ActuallyRemoved = Current;
    }

    ActuallyRemoved->Right = t->FreeList;
    t->FreeList = ActuallyRemoved;

    return;
}

PUBFUNC void Bst_Reset(Bst *t)
{
    t->Nodes.Clear(&(t->Nodes));
    t->Root = NULL;
    t->FreeList = NULL;
}

PUBFUNC void Bst_Free(Bst *t)
{
    t->Nodes.Free(&(t->Nodes));
}

int Bst_Init(Bst *t, int ElementLength, CompareFunc Compare)
{
    t->Compare = Compare;
    t->Root = NULL;
    t->FreeList = NULL;
    t->ElementLength = ElementLength;

    if( StableBuffer_Init(&(t->Nodes)) != 0 )
    {
        return -497;
    }

    t->Add = Bst_Add;
    t->Delete = Bst_Delete;
    t->Enum = Bst_Enum;
    t->Free = Bst_Free;
    t->Minimum = Bst_Minimum;
    t->Reset = Bst_Reset;
    t->Search = Bst_Search;
    t->Successor = Bst_Successor;

    return 0;
}
