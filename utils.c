#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#ifdef _WIN32
int Execute(const char *Cmd)
{
    int ret;

    ret = system(Cmd);

    return ret;
}
#else
#include <sys/wait.h>
int Execute(const char *Cmd)
{
    int ret;

    ret = system(Cmd);

    if( ret != -1 && WIFEXITED(ret) )
    {
        if( WEXITSTATUS(ret) == 0 )
        {
            return 0;
        }
    }

    return -1;
}
#endif /* _WIN32 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "common.h"
#include "utils.h"
#include "dnsgenerator.h"
#include "addresslist.h"

#ifdef _WIN32
    #ifdef MASKED
    #include <wincrypt.h>
    #ifndef CryptStringToBinary
        BOOL WINAPI CryptStringToBinaryA(const BYTE *,DWORD,DWORD,LPTSTR,DWORD *,DWORD *,DWORD *);
        #define CryptStringToBinary CryptStringToBinaryA
    #endif /* CryptStringToBinary */
    #endif /* MASKED */
#else /* _WIN32 */

    #ifdef MASKED
    #ifdef BASE64_DECODER_OPENSSL
        #include <openssl/bio.h>
        #include <openssl/evp.h>
    #endif /* BASE64_DECODER_OPENSSL */
    #ifdef BASE64_DECODER_UUDECODE
    #endif /* BASE64_DECODER_UUDECODE */
    #ifdef BASE64_DECODER_COREUTILS
    #endif /* BASE64_DECODER_COREUTILS */
    #endif /* MASKED */

    #ifdef HAVE_WORDEXP
        #include <wordexp.h>
    #endif

#endif /* _WIN32 */


int SafeRealloc(void **Memory_ptr, size_t NewBytes)
{
    void *New;

    New = realloc(*Memory_ptr, NewBytes);

    if(New != NULL)
    {
        *Memory_ptr = New;
        return 0;
    } else {
        return -1;
    }
}

char *StrToLower(char *str)
{
    char *head = str;

    /* The contract (utils.h) promises to return the original `str` pointer.
       The previous implementation returned the trailing NUL position.
       Cast to unsigned char to avoid undefined behaviour when `*str` is a
       negative (non-ASCII) byte. */
    while( *str != '\0' )
    {
        *str = (char)tolower((unsigned char)*str);
        ++str;
    }
    return head;
}

char *BoolToYesNo(BOOL value)
{
    return value == FALSE ? "No" : "Yes";
}

int GetModulePath(char *Buffer, int BufferLength)
{
#ifdef _WIN32
    int     ModuleNameLength = 0;
    char    ModuleName[320];
    char    *SlashPosition;

    if( BufferLength < 0 )
        return 0;

    ModuleNameLength = GetModuleFileName(NULL, ModuleName, sizeof(ModuleName) - 1);

    if( ModuleNameLength == 0 )
    {
        if( BufferLength > 0 )
            Buffer[0] = '\0';
        return 0;
    }

    SlashPosition = strrchr(ModuleName, '\\');

    if( SlashPosition == NULL )
    {
        if( BufferLength > 0 )
            Buffer[0] = '\0';
        return 0;
    }

    *SlashPosition = '\0';

    strncpy(Buffer, ModuleName, BufferLength - 1);
    Buffer[BufferLength - 1] = '\0';

    return strlen(Buffer);
#else
    return -1;
#endif
}

int GetErrorMsg(int Code, char *Buffer, int BufferLength)
{

    if( BufferLength <= 0 || Buffer == NULL )
    {
        return 0;
    }

#ifdef _WIN32
    return FormatMessage(   FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
                            NULL,
                            Code,
                            MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                            Buffer,
                            BufferLength,
                            NULL);
#else
    strncpy(Buffer, strerror(Code), BufferLength - 1);
    Buffer[BufferLength - 1] ='\0';
    return strlen(Buffer);

#endif
}

char *GetCurDateAndTime(char *Buffer, int BufferLength)
{
    time_t              rawtime;
    struct tm           *timeinfo;

    if( Buffer == NULL || BufferLength <= 0 )
    {
        return NULL;
    }

    *Buffer = '\0';
    *(Buffer + BufferLength - 1) = '\0';

    time(&rawtime);

    timeinfo = localtime(&rawtime);
    if( timeinfo == NULL )
    {
        /* localtime failed; leave the buffer as an empty string. */
        *Buffer = '\0';
        return Buffer;
    }

    strftime(Buffer, BufferLength - 1 ,"%Y/%m/%d %X", timeinfo);

    return Buffer;
}
#ifdef MASKED
int Base64Decode(const char *File)
{
#ifdef _WIN32
    FILE *fp = fopen(File, "rb");
    long FileSize;
    DWORD OutFileSize = 0;
    char *FileContent;
    char *ResultContent;

    if( fp == NULL )
    {
        return -1;
    }

    if( fseek(fp, 0L, SEEK_END) != 0 )
    {
        ret = -2;
        goto EXIT_1;
    }

    FileSize = ftell(fp);

    if( FileSize < 0 )
    {
        ret = -3;
        goto EXIT_1;
    }

    if( fseek(fp, 0L, SEEK_SET) != 0 )
    {
        ret = -4;
        goto EXIT_1;
    }

    FileContent = SafeMalloc(FileSize);
    if( FileContent == NULL )
    {
        ret = -5;
        goto EXIT_1;
    }

    if( fread(FileContent, 1, FileSize, fp) != FileSize )
    {
        ret = -6;
        goto EXIT_2;
    }

    fclose(fp);

    fp = fopen(File, "wb");
    if( fp == NULL )
    {
        SafeFree(FileContent);
        return -7;
    }

    if( CryptStringToBinary((LPCSTR)FileContent, FileSize, 0x00000001, NULL, &OutFileSize, NULL, NULL) != TRUE )
    {
        ret = -8;
        goto EXIT_2;
    }

    ResultContent = SafeMalloc(OutFileSize);
    if( ResultContent == NULL )
    {
        ret = -9;
        goto EXIT_2;
    }


    if( CryptStringToBinary((LPCSTR)FileContent, FileSize, 0x00000001, (BYTE *)ResultContent, &OutFileSize, NULL, NULL) != TRUE )
    {
        ret = -10;
        goto EXIT_3;
    }

    fwrite(ResultContent, 1, OutFileSize, fp);
    ret = 0;

EXIT_3:
    SafeFree(ResultContent);
EXIT_2:
    SafeFree(FileContent);
EXIT_1:
    fclose(fp);
    return ret;

#else /* _WIN32 */
#ifdef BASE64_DECODER_OPENSSL
    BIO *ub64, *bmem *bmem_2;

    FILE *fp = fopen(File, "rb");
    long FileSize;
    int OutputSize = 0;
    char *FileContent;
    char *ResultContent;

    if( fp == NULL )
    {
        return -1;
    }

    if( fseek(fp, 0L, SEEK_END) != 0 )
    {
        ret = -2;
        goto EXIT_1;
    }

    FileSize = ftell(fp);

    if( FileSize < 0 )
    {
        ret = -3;
        goto EXIT_1;
    }

    if( fseek(fp, 0L, SEEK_SET) != 0 )
    {
        ret = -4;
        goto EXIT_1;
    }

    FileContent = SafeMalloc(FileSize);
    if( FileContent == NULL )
    {
        ret = -5;
        goto EXIT_1;
    }

    if( fread(FileContent, 1, FileSize, fp) != FileSize )
    {
        ret = -6;
        goto EXIT_2;
    }

    fclose(fp);

    fp = fopen(File, "wb");
    if( fp == NULL )
    {
        SafeFree(FileContent);
        return -7;
    }

    ub64 = BIO_new(BIO_f_base64());
    if( ub64 == NULL )
    {
        ret = -8;
        goto EXIT_2;
    }

    bmem = BIO_new_mem_buf(FileContent, FileSize);
    if( bmem == NULL )
    {
        ret = -9;
        goto EXIT_3;
    }

    bmem_2 = BIO_push(ub64, bmem);
    if( bmem_2 == NULL )
    {
        ret = -10;
        goto EXIT_4;
    }
    bmem = bmem_2;

    ResultContent = SafeMalloc(FileSize);
    if( ResultContent == NULL )
    {
        ret = -11;
        goto EXIT_4;
    }

    OutputSize = BIO_read(bmem, ResultContent, FileSize);
    if( OutputSize < 1 )
    {
        ret = -12;
        goto EXIT_5;
    }

    fwrite(ResultContent, 1, OutputSize, fp);
    ret = 0;

EXIT_5:
    SafeFree(ResultContent);
EXIT_4:
    BIO_free_all(bmem);
EXIT_3:
    BIO_free_all(ub64);
EXIT_2:
    SafeFree(FileContent);
EXIT_1:
    fclose(fp);
    return ret;
#endif /* BASE64_DECODER_OPENSSL */
#ifdef BASE64_DECODER_UUDECODE
    char Cmd[2048];
    FILE *fp;

    sprintf(Cmd, "%s.base64", File);

    fp = fopen(Cmd, "w");
    if( fp == NULL )
    {
        return -1;
    }

    fputs("begin-base64 775 \xA7\x0A", fp);

    fclose(fp);

    sprintf(Cmd, "cat %s >> %s.base64", File, File);

    if( Execute(Cmd) != 0 )
    {
        return -1;
    }

    sprintf(Cmd, "rm %s", File);

    if( Execute(Cmd) != 0 )
    {
        return -1;
    }

    sprintf(Cmd, "uudecode -o %s %s.base64", File, File);

    Execute(Cmd);

    return 0;
#endif /* BASE64_DECODER_UUDECODE */
#ifdef BASE64_DECODER_COREUTILS
    char Cmd[2048];
    FILE *fp;

    sprintf(Cmd, "%s.base64", File);

    fp = fopen(Cmd, "w");
    if( fp == NULL )
    {
        return -1;
    }

    fclose(fp);

    sprintf(Cmd, "cat %s >> %s.base64", File, File);

    if( Execute(Cmd) != 0 )
    {
        return -1;
    }

    sprintf(Cmd, "rm %s", File);

    if( Execute(Cmd) != 0 )
    {
        return -1;
    }

    sprintf(Cmd, "base64 -d %s.base64 > %s", File, File);

    Execute(Cmd);

    return 0;
#endif /* BASE64_DECODER_COREUTILS */
#endif /* _WIN32 */
}
#endif /* MASKED */

int IPv6AddressToNum(const char *asc, void *Buffer)
{
    int16_t *buf_s  =   (int16_t *)Buffer;
    const char  *itr;
    const char  *head = asc;

    memset(Buffer, 0, 16);

    for(; isspace((unsigned char)*asc); ++asc);

    if( strstr(asc, "::") == NULL )
    {   /* full format */
        uint32_t a[8] = {0};
        sscanf(asc, "%x:%x:%x:%x:%x:%x:%x:%x",
                a, a + 1, a + 2, a + 3, a + 4, a + 5, a + 6, a + 7
                );
        SET_16_BIT_U_INT(buf_s, a[0]);
        SET_16_BIT_U_INT(buf_s + 1, a[1]);
        SET_16_BIT_U_INT(buf_s + 2, a[2]);
        SET_16_BIT_U_INT(buf_s + 3, a[3]);
        SET_16_BIT_U_INT(buf_s + 4, a[4]);
        SET_16_BIT_U_INT(buf_s + 5, a[5]);
        SET_16_BIT_U_INT(buf_s + 6, a[6]);
        SET_16_BIT_U_INT(buf_s + 7, a[7]);
    } else {
        /* not full*/

        if( asc[2] == '\0' || isspace((unsigned char)asc[2]) )
        {
            memset(Buffer, 0, 16);
            return 0;
        }

        while(1)
        {
            uint32_t a = 0;
            itr = asc;
            asc = strchr(asc, ':');
            if( asc == NULL )
                return 0;

            if( itr == asc )
            {
                break;
            }

            /* Bound the write index: a "::" abbreviated address may have at
               most 7 explicit groups before the gap. Without this check an
               over-long literal (e.g. "1:2:3:4:5:6:7:8:9") keeps writing past
               the 16-byte Buffer and corrupts the caller's stack. */
            if( buf_s >= (int16_t *)Buffer + 8 )
                return 0;

            sscanf(itr, "%x:", &a);
            SET_16_BIT_U_INT(buf_s, a);
            ++buf_s;
            ++asc;
        }
        buf_s = (int16_t *)Buffer + 7;
        for(; *asc != '\0'; ++asc);
        while(1)
        {
            uint32_t a = 0;
            /* Scan backwards for the previous ':' but never walk before the
               start of the input; otherwise we read out of bounds. */
            for(itr = asc; itr > head && *itr != ':'; --itr);

            if( *itr != ':' )
                break;

            if( *(itr + 1) == '\0' )
                break;

            /* Bound the write index from below as well. */
            if( buf_s < (int16_t *)Buffer )
                break;

            sscanf(itr + 1, "%x", &a);
            SET_16_BIT_U_INT(buf_s, a);
            --buf_s;
            asc = itr - 1;

            if( *(itr - 1) == ':' )
                break;
        }
    }

    return 16;
}

int IPv4AddressToNum(const char *asc, void *Buffer)
{
    int ret = 0;

    unsigned char *BufferInByte = (unsigned char *)Buffer;

    int Components[4];
    memset(Components, 0, sizeof(Components));

    ret = sscanf(asc, "%d.%d.%d.%d", Components, Components + 1, Components + 2, Components + 3);
    /* Reject anything that is not exactly four decimal components, and
       reject components that do not fit in a single byte. Previously the
       four bytes were written unconditionally, so an input like "1.2.3"
       leaked uninitialised stack data and "999.999.999.999" was silently
       truncated into a wrong address. */
    if( ret != 4 ||
        Components[0] < 0 || Components[0] > 255 ||
        Components[1] < 0 || Components[1] > 255 ||
        Components[2] < 0 || Components[2] > 255 ||
        Components[3] < 0 || Components[3] > 255
        )
    {
        return -1;
    }
    BufferInByte[0] = (unsigned char)Components[0];
    BufferInByte[1] = (unsigned char)Components[1];
    BufferInByte[2] = (unsigned char)Components[2];
    BufferInByte[3] = (unsigned char)Components[3];

    return ret;
}

sa_family_t GetAddressFamily(const char *Addr)
{
    char Buffer[8];

    if( strchr(Addr, '[') != NULL )
    {
        return AF_INET6;
    }

    if( IPv4AddressToNum(Addr, Buffer) == 4 )
    {
        return AF_INET;
    }

    return AF_UNSPEC;
}

int IPv6AddressToAsc(const void *Address, void *Buffer)
{
    int i;
    int z = -1, n = 0;
    int z2 = -1, n2 = 0;
    char *x = (char *)Address;
    char *s = (char *)Buffer;

    /* Find the longest continuous uint16_t 0. Only one "::",
       "2001:0:0:db8:0:0:0:ec" to "2001:0:0:db8::ec",
       "2001:0:0:0:db8:0:0:ec" to "2001::db8:0:0:ec" */
    for( i = 0; i < 16; i += 2 )
    {
        if( x[i] == 0 && x[i + 1] == 0 )
        {
            if( z2 == -1 )
            {
                z2 = i;
                n2 = 0;
            }
            n2 += 2;
            if( n2 > n )
            {
                z = z2;
                n = n2;
            }
        } else {
            z2 = -1;
        }
    }

    for( i = 0; i < 16; i += 2 )
    {
        uint16_t v;

        if( i == z && n > 2 )
        {
            if( i == 0 )
            {
                *s = ':';
                s++;
            }
            *s = ':';
            s++;
            i += n - 2;
            continue;
        }

        v = GET_16_BIT_U_INT(x + i);
        sprintf(s, "%x", v);
        if( v == 0 )
        {
            s++;
        } else {
            for( ; v > 0; v >>= 4 )
            {
                s++;
            }
        }
        if( i < 14 )
        {
            *s = ':';
            s++;
        }
    }
    *s = 0x0;

    return s - (char *)Buffer;
}

int IPv4AddressToAsc(const void *Address, void *Buffer)
{
    const char  *a = (const char *)Address;

    return sprintf(Buffer,
                   "%u.%u.%u.%u",
                   GET_8_BIT_U_INT(a),
                   GET_8_BIT_U_INT(a + 1),
                   GET_8_BIT_U_INT(a + 2),
                   GET_8_BIT_U_INT(a + 3)
                   );
}

int GetConfigDirectory(char *out)
{
#ifdef _WIN32
    return -1;
#else /* _WIN32 */
#ifndef ANDROID
    struct passwd *pw = getpwuid(getuid());
    char *home;
    *out = '\0';
    if( pw == NULL )
    {
        return 1;
    }
    home = pw->pw_dir;
    if( home == NULL )
        return 1;

    strcpy(out, home);
    strcat(out, "/.dnsforwarder");

    return 0;
#else /* ANDROID */
    strcpy(out, "/system/root/.dnsforwarder");

    return 0;
#endif /* ANDROID */
#endif /* _WIN32 */
}

BOOL FileIsReadable(const char *File)
{
    FILE *fp = fopen(File, "r");

    if( fp == NULL )
    {
        return FALSE;
    } else {
        fclose(fp);
        return TRUE;
    }
}

int GetFileSizePortable(const char *File)
{
    int s = 0;
    FILE *fp = fopen(File, "rb");

    if( fp == NULL )
    {
        return 0;
    }

    if( fseek(fp, 0, SEEK_END) == 0 )
    {
        s = ftell(fp);
    }

    fclose(fp);
    return s;
}

int GetTextFileContent(const char *File, char *Content, size_t MaxLength)
{
    FILE *fp = fopen(File, "rb");
    size_t written = 0;
    int c = 0;

    if( fp == NULL )
    {
        return -1;
    }

    /* Never write past Content[MaxLength - 1] and always NUL-terminate,
       otherwise the caller's strstr()/string handling would run off the
       end of the buffer. */
    while( written + 1 < MaxLength && (c = fgetc(fp)) != EOF )
    {
        Content[written++] = (char)c;
    }

    Content[written] = '\0';

    fclose(fp);

    return 0;
}

BOOL IsPrime(int n)
{
    int i;

    if( n < 2 )
    {
        return FALSE;
    }

    if( n == 2 )
    {
        return TRUE;
    }

    if( n % 2 == 0 )
    {
        return FALSE;
    }

    for(i = 3; i < sqrt(n) + 1; i += 2)
    {
        if( n % i == 0 )
        {
            return FALSE;
        }
    }

    return TRUE;
}

int FindNextPrime(int Current)
{
    if( IsPrime(Current) )
    {
        return Current;
    }

    Current = ROUND_UP(Current, 2) + 1;

    if( Current < 3 )
    {
        Current = 3;
    }

    do
    {
        if( IsPrime(Current) )
        {
            return Current;
        } else {
            /* Guard against signed overflow (which wraps to a negative value
               and would make IsPrime loop forever / invoke UB on sqrt). */
            if( Current > INT_MAX - 2 )
            {
                return -1;
            }
            Current += 2;
        }

    } while( TRUE );
}

uint32_t BKDRHash(const char* str, uint32_t Unused)
{
    uint32_t seed = 131; /* 31 131 1313 13131 131313 etc.. */
    uint32_t hash = 0;

    while( *str != '\0' )
    {
        hash = (hash * seed) + (*str);
        str++;
    }

    return hash;
}

void HexDump(const char *Data, int Length)
{
    int Itr;

    for( Itr = 0; Itr != Length; ++Itr )
    {
        printf("%x ", (unsigned char)Data[Itr]);
    }

    putchar('\n');
}

char *BinaryOutput(const char *Origin, int OriginLength, char *Buffer)
{
    int loop;

    /* Emit one '0'/'1' per bit, most-significant bit first. The loop bound
       was previously written as `loop <= 0` which is always false, so the
       function produced no output at all. It is now `loop >= 0`. */
    while( OriginLength != 0 )
    {
        for( loop = 7; loop >= 0; --loop )
        {
            if( (((int)*Origin) & (1 << loop)) == 0 )
            {
                *Buffer = '0';
            } else {
                *Buffer = '1';
            }

            ++Buffer;
        }

        --OriginLength;
        ++Origin;
    }

    *Buffer = '\0';
    return Buffer;
}

char *StringDup(const char *Str)
{
    char *New;

    if( Str == NULL )
    {
        return NULL;
    }

    New = malloc(strlen(Str) + 1);
    if( New != NULL )
    {
        strcpy(New, Str);
    }

    return New;
}

char *StrNpbrk(char *Str, const char *Ch)
{
    if( Str == NULL || Ch == NULL )
    {
        return Str;
    }

    while( *Str != '\0' && strchr(Ch, *Str) != NULL )
    {
        ++Str;
    }

    if( *Str == '\0' )
    {
        return NULL;
    } else {
        return Str;
    }

}

char *StrRNpbrk(char *Str, const char *Ch)
{
    char *LastCharacter;

    if( Str == NULL || Ch == NULL )
    {
        return Str;
    }

    LastCharacter = Str + strlen(Str) - 1;

    while( LastCharacter >= Str && strchr(Ch, *LastCharacter) != NULL )
    {
        --LastCharacter;
    }

    if( LastCharacter <  Str )
    {
        return NULL;
    } else {
        return LastCharacter;
    }

}

char *GoToNextNonSpace(const char *Here)
{
    return (char *)StrNpbrk((char *)Here, "\t ");
}

char *GoToPrevNonSpace(char *Here, const char *Start)
{
    if( Here == NULL || Start == NULL )
    {
        return Here;
    }

    for( ; Here >= Start && isspace((unsigned char)*Here); --Here );

    return Here;
}

int GetAddressLength(sa_family_t Family)
{
    switch( Family )
    {
        case AF_INET:
            return sizeof(struct sockaddr);
            break;

        case AF_INET6:
            return sizeof(struct sockaddr_in6);
            break;

        default:
            return -1;
            break;
    }
}

int SetProgramEnvironment(const char *Name, const char *Value)
{
#ifdef _WIN32
    return !SetEnvironmentVariable(Name, Value);
#else
#ifdef HAVE_SETENV
    return setenv(Name, Value, 1);
#else
    return 0;
#endif
#endif
}

int ExpandPath(char *String, int BufferLength)
{
#ifdef _WIN32
    char    TempStr[2048];
    int     State;

    State = ExpandEnvironmentStrings(String, TempStr, sizeof(TempStr) - 1);

    if( State == 0 || State >= (int)(sizeof(TempStr) - 1) )
    {
        return -1;
    }

    TempStr[sizeof(TempStr) - 1] = '\0';

    if( (int)strlen(TempStr) + 1 > BufferLength )
    {
        return -1;
    }

    strcpy(String, TempStr);

    return 0;
#else
#ifdef HAVE_WORDEXP
    wordexp_t Result;

    /* `wordfree()` must not be called on a `wordexp_t` that `wordexp()`
       did not fill in. */
    if( wordexp(String, &Result, 0) != 0 )
    {
        return -1;
    }

    /* An expansion may legitimately produce no word at all (for instance
       when the path only consists of an undefined variable). Dereferencing
       we_wordv[0] in that case reads a NULL pointer. */
    if( Result.we_wordc < 1 || Result.we_wordv[0] == NULL )
    {
        wordfree(&Result);
        return -1;
    }

    if( (int)strlen(Result.we_wordv[0]) + 1 <= BufferLength )
    {
        strcpy(String, Result.we_wordv[0]);
    }

    wordfree(&Result);
    return 0;
#else
    return 0;
#endif
#endif
}

int ExpandPathTo(char *Buffer, int BufferLength, const char *String)
{
    if( BufferLength <= 1 )
    {
        return -1;
    }
    strncpy(Buffer, String, BufferLength - 1);
    Buffer[BufferLength - 1] = 0;
    ReplaceStr(Buffer, "\"", "");

    return ExpandPath(Buffer, BufferLength);
}

char *GetLocalPathFromURL(const char *URL, char *Buffer, int BufferLength)
{
    const char *Itr;
#ifdef _WIN32
    char *Itr_Buffer;
#endif

    Itr = strstr(URL, "://");
    if( Itr == NULL )
    {
        return NULL;
    }

    ++Itr;
    for( ; *Itr == '/'; ++Itr );

#ifndef _WIN32
    --Itr;
#endif

    if( (int)strlen(Itr) + 1 > BufferLength )
    {
        return NULL;
    }

    strcpy(Buffer, Itr);

#ifdef _WIN32
    for( Itr_Buffer = Buffer; *Itr_Buffer != '\0'; ++Itr_Buffer )
    {
        if( *Itr_Buffer == '/' )
        {
            *Itr_Buffer = '\\';
        }
    }
#endif

    if( ExpandPath(Buffer, BufferLength) == 0 )
    {
        return Buffer;
    } else {
        return NULL;
    }

}

int CopyAFile(const char *Src, const char *Dst, BOOL Append)
{
    FILE *Src_Fp, *Dst_Fp;

    Src_Fp = fopen(Src, "r");
    if( Src_Fp == NULL )
    {
        return -1;
    }

    Dst_Fp = fopen(Dst, Append == TRUE ? "a+" : "w");
    if( Dst_Fp == NULL )
    {
        fclose(Src_Fp);
        return -2;
    }

    do{
        int ch;

        ch = fgetc(Src_Fp);
        if( ch != EOF && !feof(Src_Fp) )
        {
            fputc(ch, Dst_Fp);
        } else {
            break;
        }

    } while( TRUE );

    fclose(Src_Fp);
    fclose(Dst_Fp);

    return 0;
}

int FatalErrorDecideding(int LastError)
{
#ifdef _WIN32
    if( LastError == WSAEWOULDBLOCK || LastError == WSAEINTR || LastError == WSAEINPROGRESS )
    {
        return 0;
    }
#else
    if( LastError == EINTR || LastError == EAGAIN || LastError == EINPROGRESS )
    {
        return 0;
    }
#endif

    return -1;
}

BOOL ErrorOfVoidSelect(int LastError)
{
#ifdef _WIN32
    return LastError == WSAEINVAL;
#else
    return LastError == EINVAL;
#endif
}

int CountSubStr(const char *Src, const char *SubStr)
{
    int ret = 0;
    int SubStrLen = strlen(SubStr);
    const char *Itr;

    Itr = strstr(Src, SubStr);
    while( Itr != NULL )
    {
        ++ret;

        Itr = strstr(Itr + SubStrLen, SubStr);
    }

    return ret;
}

char *ReplaceStr(char *Src, const char *OriSubstr, const char *DesSubstr)
{
    int DesLen = strlen(DesSubstr);
    int OriLen = strlen(OriSubstr);

    char *Itr;

    Itr = strstr(Src, OriSubstr);
    while( Itr != NULL )
    {
        memmove(Itr + DesLen, Itr + OriLen, strlen(Itr + OriLen) + 1);

        memcpy(Itr, DesSubstr, DesLen);

        Itr = strstr(Itr + DesLen, OriSubstr);
    }

    return Src;
}

char *ReplaceStr_WithLengthChecking(char *Src,
                                    const char *OriSubstr,
                                    const char *DesSubstr,
                                    int SrcBufferLength
                                    )
{
    int TotalSpaceNeeded = TOTAL_SPACE_NEEDED(Src,
                                              strlen(OriSubstr),
                                              strlen(DesSubstr),
                                              CountSubStr(Src, OriSubstr)
                                              );

    if( TotalSpaceNeeded > SrcBufferLength )
    {
        return NULL;
    } else {
        return ReplaceStr(Src, OriSubstr, DesSubstr);
    }
}

/* Off by default on most *nix, or unsupported.
   Windows Vista and later support this. */
#if defined(_WIN32) && defined(IPV6_V6ONLY)
int SetSocketIPv6V6only(SOCKET sock, int on)
{
    return setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on));
}
#endif

int SetSocketNonBlock(SOCKET sock, BOOL NonBlocked)
{
#ifdef _WIN32
    unsigned long NonBlock = (NonBlocked == TRUE) ? 1 : 0;

    if( ioctlsocket(sock, FIONBIO, &NonBlock) != 0 )
    {
        return -1;
    } else {
        return 0;
    }
#else
    int Flags;

    Flags = fcntl(sock, F_GETFL, 0);
    if( Flags < 0 )
    {
        return -1;
    }

    /* Clearing O_NONBLOCK has to mask the bit off. `Flags | ~O_NONBLOCK`
       would instead turn on every other file status flag (O_APPEND,
       O_ASYNC, ...) on the socket. */
    if( NonBlocked == TRUE )
    {
        Flags |= O_NONBLOCK;
    } else {
        Flags &= ~O_NONBLOCK;
    }

    if( fcntl(sock, F_SETFL, Flags) < 0 )
    {
        return -1;
    }

    return 0;
#endif
}

int SetSocketTimeout(SOCKET Sock, int OptName, int Timeout)
{
#ifdef _WIN32
    DWORD t = Timeout;
#else
    struct timeval t = {Timeout / 1000, (Timeout % 1000) * 1000};
#endif

    return setsockopt(Sock, SOL_SOCKET, OptName, (void *)&t, sizeof(t));
}

BOOL SocketIsWritable(SOCKET sock, int Timeout)
{
    struct timeval TimeLimit = {Timeout / 1000, (Timeout % 1000) * 1000};
    fd_set rfd;

    if( sock == INVALID_SOCKET )
    {
        return FALSE;
    }

    FD_ZERO(&rfd);
    FD_SET(sock, &rfd);

    switch(select(sock + 1, NULL, &rfd, NULL, &TimeLimit))
    {
        case 0:
        case SOCKET_ERROR:
            return FALSE;
            break;

        default:
            return TRUE;
            break;
    }
}

BOOL SocketIsStillReadable(SOCKET Sock, int timeout)
{
    fd_set rfd;
    struct timeval TimeLimit = {timeout / 1000, (timeout % 1000) * 1000};

    FD_ZERO(&rfd);
    FD_SET(Sock, &rfd);

    switch(select(Sock + 1, &rfd, NULL, NULL, &TimeLimit))
    {
        case SOCKET_ERROR:
        case 0:
            return FALSE;
            break;
        case 1:
            return TRUE;
            break;
        default:
            return FALSE;
            break;
    }
}

void ClearTCPSocketBuffer(SOCKET Sock, int Length)
{
    char BlackHole[128];

    while( Length > 0 )
    {
        int UnitLength;

        UnitLength = recv(Sock,
                          BlackHole,
                          sizeof(BlackHole) < (size_t)Length ? sizeof(BlackHole) : (size_t)Length,
                          0
                          );

        if( UnitLength <= 0 )
        {
            return;
        }

        Length -= UnitLength;
    }
}

SOCKET TryBindLocal(BOOL Ipv6, int StartPort, Address_Type *Address)
{
    const char *Loopback = Ipv6 ? "[::1]" : "127.0.0.1";

    int MaxTime = 10000;

    Address_Type Address1;
    SOCKET ret = INVALID_SOCKET;

    do {
        AddressList_ConvertFromString(&Address1, Loopback, StartPort);

        ret = socket(Address1.family, SOCK_DGRAM, IPPROTO_UDP);
        if( ret == INVALID_SOCKET )
        {
            continue;
        }

        if( bind(ret,
                 (struct sockaddr *)&(Address1.Addr),
                 GetAddressLength(Address1.family)
                 )
           != 0 )
        {
            CLOSE_SOCKET(ret);
            ret = INVALID_SOCKET;
            continue;
        }

    } while( ret == INVALID_SOCKET && --MaxTime > 0 && ++StartPort > 0 );

    if( ret != INVALID_SOCKET && Address != NULL )
    {
        memcpy(Address, &Address1, sizeof(Address_Type));
    }

    return ret;
}

char *SplitNameAndValue(char *Line, const char *Delimiters)
{
    char *Delimiter = strpbrk(Line, Delimiters);

    if( Delimiter == NULL )
    {
        return NULL;
    }

    *Delimiter = '\0';

    return GoToNextNonSpace(Delimiter + 1);
}

char *GetPathPart(char *FullPath)
{
    char *SlashPos;

    SlashPos = strrchr(FullPath, PATH_SLASH_CH);

    if( SlashPos == NULL )
    {
        return NULL;
    }

    *(SlashPos + 1) = '\0';

    return FullPath;
}
