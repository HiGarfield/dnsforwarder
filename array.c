#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "array.h"
#include "utils.h"

/* Compute `Count * ElemSize` into *Out without losing the result to an integer
   overflow. The allocation routines take a `size_t`, but the callers used to
   compute `Count * ElemSize` in `int` arithmetic and then widen it to `size_t`.
   When the product exceeded INT_MAX it wrapped to a small (or zero) value, so
   SafeMalloc()/SafeRealloc() was handed a far-too-small buffer and the
   subsequent memcpy()/memset() overflowed the heap. */
static int Array_SafeCapacitySize(int Count, int ElemSize, size_t *Out)
{
    if( Count < 0 || ElemSize < 0 )
        return -1;

    if( ElemSize != 0 && (size_t)Count > SIZE_MAX / (size_t)ElemSize )
        return -1;

    *Out = (size_t)Count * (size_t)ElemSize;
    return 0;
}

/* if it grows down, the InitialCount will be ignored. Otherwise, TheFirstAddress will be ignored. */
int Array_Init(__in Array *a, __in int DataLength, __in int InitialCount, __in BOOL GrowsDown, __in void *TheFirstAddress /* The first means the biggest address*/)
{
    if( InitialCount < 0)
        return 1;

    a->DataLength = DataLength;
    a->Used = 0;

    if( GrowsDown == FALSE )
    {
        if( InitialCount > 0 )
        {
            size_t  Bytes;

            if( Array_SafeCapacitySize(InitialCount, DataLength, &Bytes) != 0
                || (a->Data = SafeMalloc(Bytes)) == NULL )
                return 2;

            memset(a->Data, 0, Bytes);
        } else {
            a->Data = NULL;
        }

        a->Allocated = InitialCount;
    } else {
        a->Allocated = -1;
        a->Data = TheFirstAddress;
    }

    return 0;
}

/* Subscripts are always non-negative. */
void *Array_GetBySubscript(__in const Array *a, __in int Subscript)
{
    if( Subscript >= 0 && Subscript < a->Used )
    {
        if( a->Allocated < 0 )
        {
            Subscript *= (-1);
        }

        return (void *)((a->Data) + (a->DataLength) * Subscript);
    } else {
        return NULL;
    }
}

/* Subscript of the element `Position' belongs to, or a negative value if
   `Position' is not the start of an element of `a'. Grow-down arrays store
   subscript i at a->Data - i * DataLength, so the raw offset has to be negated
   for them, otherwise every subscript but 0 comes out with the wrong sign. */
static int Array_SubscriptOf(__in const Array *a, __in const char *Position)
{
    int n = (int)((Position - a->Data) / a->DataLength);

    if( a->Allocated < 0 )
    {
        n *= (-1);
    }

    return n;
}

void *Array_GetThis(__in const Array *a, __in const void *Position)
{
    if( Position == NULL )
    {
        return NULL;
    }

    return Array_GetBySubscript(a, Array_SubscriptOf(a, Position));
}

void *Array_GetNext(__in const Array *a, __in const void *Position)
{
    int n;

    if( Position == NULL )
    {
        n = 0;
    } else {
        n = Array_SubscriptOf(a, Position) + 1;
    }

    return Array_GetBySubscript(a, n);
}

/* Subscript returned */
int Array_PushBack(__in Array *a, __in_opt const void *Data, __in_opt void *Boundary /* Only used by grow down array */)
{
    if( a->Allocated >= 0 )
    {
        if( a->Used == a->Allocated )
        {
            int     NewCount    = (a->Allocated) < 2 ? 2 : (a->Allocated) + (a->Allocated) / 2;
            size_t  Bytes;

            if( Array_SafeCapacitySize(NewCount, a->DataLength, &Bytes) != 0
                || SafeRealloc((void **)&(a->Data), Bytes) != 0 )
            {
                return -1;
            }

            a->Allocated = NewCount;
        }

        if( Data != NULL )
            memcpy((a->Data) + (a->DataLength) * (a->Used), Data, a->DataLength);

        return (a->Used)++;

    } else {
        if( Boundary != NULL && ((a->Data) + (-1) * (a->DataLength) * (a->Used)) < (char *)Boundary )
        {
            return -1;
        } else {
            if( Data != NULL )
            {
                memcpy((a->Data) + (-1) * (a->DataLength) * (a->Used), Data, a->DataLength);
            }
            return (a->Used)++;
        }
    }
}

void *Array_SetToSubscript(Array *a, int Subscript, const void *Data)
{
    if( a->Allocated >= 0 )
    {
        if( Subscript >= a->Allocated )
        {
            size_t  Bytes;

            if( Array_SafeCapacitySize(Subscript + 1, a->DataLength, &Bytes) != 0
                || SafeRealloc((void **)&(a->Data), Bytes) != 0 )
                return NULL;

            a->Allocated = Subscript + 1;
        }

        memcpy((a->Data) + (a->DataLength) * Subscript, Data, a->DataLength);

        if( a->Used < Subscript + 1 )
            a->Used = Subscript + 1;

        return (a->Data) + (a->DataLength) * Subscript;
    } else {
        if( a->Used < Subscript + 1 )
        {
            a->Used = Subscript + 1;
        }

        memcpy((a->Data) + (-1) * (a->DataLength) * Subscript, Data, a->DataLength);

        return (a->Data) + (-1) * (a->DataLength) * Subscript;
    }
}

void Array_Sort(Array *a, int (*Compare)(const void *, const void *))
{
    if( a->Allocated < 0 )
    {
        /* Grow-down array: subscript 0 lives at the highest address (a->Data)
           and subscript (Used - 1) at the lowest, so the contiguous block of
           Used elements starts (lowest address) at
           a->Data - (Used - 1) * DataLength. The old base
           a->Data - Used * DataLength read one element below the region
           (buffer underflow) and silently dropped the element stored at a->Data. */
        qsort(a->Data - (a->Used - 1) * a->DataLength, a->Used, a->DataLength, Compare);
    } else {
        qsort(a->Data, a->Used, a->DataLength, Compare);
    }
}

void Array_Fill(Array *a, int Num, const void *DataSample)
{
    int i;
    for( i = 0; i < Num; ++i )
    {
        Array_SetToSubscript(a, i, DataSample);
    }
}

void Array_Free(Array *a)
{
    if( a->Allocated > 0 )
    {
        SafeFree(a->Data);
    }
    a->Data = NULL;
    a->Used = 0;
    a->Allocated = 0;
}
