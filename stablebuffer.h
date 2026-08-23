#ifndef STABLEBUFFER_C_INCLUDED
#define STABLEBUFFER_C_INCLUDED

#include "array.h"

typedef struct _StableBuffer_MetaInfo{
    char    *Start;
    int32_t Amount; /* In bytes */
    int32_t Used; /* In bytes */
} StableBuffer_MetaInfo;

typedef struct _StableBuffer StableBuffer;

struct _StableBuffer{
    Array   MetaInfo;

    void    *(*Add)(StableBuffer *s, const void *Data, int Length, BOOL Align);
    void    (*Clear)(StableBuffer *s);
    void    (*Free)(StableBuffer *s);
    int     (*RollbackLast)(StableBuffer *s, int Length, BOOL Align);
};

int StableBuffer_Init(StableBuffer *s);

/* Undo the most recent Add() of `Length' (optionally aligned) bytes by
 * removing them from the tail of the last block.  Used to roll back a
 * partially-completed compound write (e.g. when the caller's key insertion
 * fails after the payload was already stored).  Returns 0 on success,
 * -1 on a bad parameter / inconsistent state. */
int StableBuffer_RollbackLast(StableBuffer *s, int Length, BOOL Align);

/**
 Iterator
*/
typedef struct _StableBufferIterator StableBufferIterator;

struct _StableBufferIterator{
    StableBuffer    *Buffer;
    int32_t         Current;

    void *(*NextBlock)(StableBufferIterator *i);
    void (*Reset)(StableBufferIterator *i);
    void *(*ToLast)(StableBufferIterator *i);

    BOOL (*IsInCurrentBlock)(StableBufferIterator *i, const void *Position);

    int32_t (*CurrentBlockSize)(StableBufferIterator *i);
    int32_t (*CurrentBlockUsed)(StableBufferIterator *i);

    void (*RemoveLastNBytesOfCurrentBlock)(StableBufferIterator *i, int n);
    void (*RemoveNBytesOfCurrentBlock)(StableBufferIterator *i,
                                       char *Here,
                                       int n
                                       );

    void (*Free)(StableBufferIterator *i);
};

int StableBufferIterator_Init(StableBufferIterator *i, StableBuffer *s);

#endif /* STABLEBUFFER_C_INCLUDED */
