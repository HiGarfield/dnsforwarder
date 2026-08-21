#include <ctype.h>
#include <string.h>
#include "common.h"
#include "readline.h"

static BOOL ClearAnnotation(char *str, char mark)
{
    char *pos = strchr(str, mark);

    if( pos != NULL )
    {
        /* Walk backwards over trailing whitespace that precedes the comment
           marker.  The loop guard checks `pos > str` *before* dereferencing
           `pos - 1` so we never form a pointer one element before `str`
           (which would be undefined behaviour); the original code decremented
           `pos` first and then compared, creating a `str - 1` pointer. */
        while( pos > str && isspace((unsigned char)*(pos - 1)) )
        {
            --pos;
        }
        *pos = '\0';
        return TRUE;
    } else {
        return FALSE;
    }
}

static BOOL ReachedLineEnd(FILE *fp, const char *str)
{
    int len = strlen(str);

    if( len != 0 && (str[len - 1] == '\r' || str[len - 1] == '\n') )
    {
        return TRUE;
    } else {
        if( feof(fp) )
        {
            return TRUE;
        } else {
            return FALSE;
        }
    }
}

static void EliminateCRLF(char *str)
{
    ClearAnnotation(str, '\r');
    ClearAnnotation(str, '\n');
}

static void EliminateHeadSpace(char *str)
{
    char *Home;

    for(Home = str; isspace((unsigned char)*Home); ++Home);
    if( Home != str )
    {
        memmove(str, Home, strlen(Home) + 1);
    }

}

static void EliminateFootSpace(char *str)
{
    size_t len = strlen(str);

    /* Walk backwards over trailing whitespace using an index instead of a
       pointer: the pointer form computed `str + strlen(str) - 1` for an
       empty string, forming a pointer one element before the buffer start
       (undefined behaviour per C11 6.5.6p8, the same class of bug already
       fixed in ClearAnnotation above). The loop never dereferences before
       `str` and the result is identical. */
    while( len > 0 && isspace((unsigned char)str[len - 1]) )
    {
        --len;
    }
    str[len] = '\0';
}

ReadLineStatus ReadLine(FILE *fp, char *Buffer, int BufferSize)
{
    BOOL    ReachedEnd;

START:
    if( Buffer == NULL || fgets(Buffer, BufferSize, fp) == NULL )
    {
        return READ_FAILED_OR_END;
    } else {
        ReachedEnd = ReachedLineEnd(fp, Buffer);
    }

    if( (ClearAnnotation(Buffer, '#') || ClearAnnotation(Buffer, ';')) != FALSE )
    {
        if( ReachedEnd == FALSE )
        {
            char BlackHole[128];
            do
            {
                if( fgets(BlackHole, sizeof(BlackHole), fp) == NULL )
                {
                    return READ_FAILED_OR_END;
                }
                ReachedEnd = ReachedLineEnd(fp, BlackHole);
            }while( ReachedEnd == FALSE );
        }

        EliminateFootSpace(Buffer);
        EliminateHeadSpace(Buffer);

        if( *Buffer == '\0' )
        {
            goto START;
        } else {
            return READ_DONE;
        }

    }

    if( ReachedEnd == TRUE )
    {
        EliminateCRLF(Buffer);
        EliminateFootSpace(Buffer);
        EliminateHeadSpace(Buffer);
        if( *Buffer == '\0' )
        {
            goto START;
        } else {
            return READ_DONE;
        }
    } else {
        return READ_TRUNCATED;
    }
}

ReadLineStatus ReadLine_GoToNextLine(FILE *fp)
{
    ReadLineStatus Status;
    char Buffer[128];

    do
    {
        Status = ReadLine(fp, Buffer, sizeof(Buffer));
    }
    while( Status == READ_TRUNCATED );

    return Status;
}
