/*
 * Library routines
 *
 * Copyright (C) 2013 Craig Barratt.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

#include "backuppc.h"

char *BPC_TopDir;
static size_t BPC_TopDirSz;
char *BPC_PoolDir;
static size_t BPC_PoolDirSz;
char *BPC_CPoolDir;
static size_t BPC_CPoolDirSz;
char *BPC_PoolDir3;
static size_t BPC_PoolDir3Sz;
char *BPC_CPoolDir3;
static size_t BPC_CPoolDir3Sz;

int BPC_HardLinkMax   = 32000;
int BPC_PoolV3Enabled = 0;
int BPC_TmpFileUnique = -1;
int BPC_LogLevel      = 0;

static char *hexDigits = "0123456789abcdef";

void bpc_lib_conf_init(char *topDir, int hardLinkMax, int poolV3Enabled, int logLevel)
{
    if ( logLevel >= 8 ) bpc_logMsgf("bpc_lib_conf_init: topDir = %s, logLevel = %d\n", topDir, logLevel);

    bpc_snprintf(&BPC_TopDir,    &BPC_TopDirSz,    0, 1024, "%s",    topDir);
    bpc_snprintf(&BPC_CPoolDir,  &BPC_CPoolDirSz,  0, 1024, "%s/%s", BPC_TopDir, "cpool");
    bpc_snprintf(&BPC_CPoolDir3, &BPC_CPoolDir3Sz, 0, 1024, "%s/%s", BPC_TopDir, "cpool");
    bpc_snprintf(&BPC_PoolDir,   &BPC_PoolDirSz,   0, 1024, "%s/%s", BPC_TopDir, "pool");
    bpc_snprintf(&BPC_PoolDir3,  &BPC_PoolDir3Sz,  0, 1024, "%s/%s", BPC_TopDir, "pool");

    BPC_HardLinkMax   = hardLinkMax;
    BPC_PoolV3Enabled = poolV3Enabled;
    BPC_LogLevel      = logLevel;
}

void bpc_lib_setTmpFileUnique(int val)
{
    BPC_TmpFileUnique = val;
}

int bpc_lib_setLogLevel(int logLevel)
{
    if ( logLevel >= 0 ) {
        BPC_LogLevel = logLevel;
    }
    return BPC_LogLevel;
}

/*
 * Converts a byte to two ascii hex digits at outStr[0] and outStr[1].
 * Nothing is written at outStr[2]; ie: no NULL termination
 */
void bpc_byte2hex(char *outStr, int byte)
{
    outStr[0] = hexDigits[(byte >> 4) & 0xf];
    outStr[1] = hexDigits[(byte >> 0) & 0xf];
}

static uchar bpc_hexChar2nibble(char c)
{
    if ( '0' <= c && c <= '9' ) return c - '0';
    if ( 'A' <= c && c <= 'F' ) return 0xa + (c - 'A');
    if ( 'a' <= c && c <= 'f' ) return 0xa + (c - 'a');
    return 0;
}

uchar bpc_hexStr2byte(char c1, char c2)
{
    return (bpc_hexChar2nibble(c1) << 4) | bpc_hexChar2nibble(c2);
}

void bpc_digest_buffer2MD5(bpc_digest *digest, uchar *buffer, size_t bufferLen)
{
    md_context md5;
    md5_begin(&md5);
    md5_update(&md5, buffer, bufferLen);
    md5_result(&md5, digest->digest);
    digest->len = MD5_DIGEST_LEN;
}

void bpc_digest_append_ext(bpc_digest *digest, uint32 ext)
{
    int i;

    digest->len = 16;
    if ( ext == 0 ) return;
    for ( i = 24 ; i >= 0 ; i -= 8 ) {
        if ( ext >= (1U << i) ) {
            digest->digest[digest->len++] = (ext >> i) & 0xff;
        }
    }
}

/*
 * returns 0 if the two digests are equal, non-zero if they are not
 */
int bpc_digest_compare(bpc_digest *digest1, bpc_digest *digest2)
{
    if ( digest1->len != digest2->len ) return digest1->len - digest2->len;
    return memcmp(digest1->digest, digest2->digest, digest1->len);
}

void bpc_digest_digest2str(bpc_digest *digest, char *hexStr)
{
    int i;
    char *out = hexStr;

    for ( i = 0 ; i < digest->len ; i++ ) {
        bpc_byte2hex(out, digest->digest[i]);
        out += 2;
    }
    *out = '\0';
}

void bpc_digest_str2digest(bpc_digest *digest, char *hexStr)
{
    for ( digest->len = 0 ; hexStr[0] && hexStr[1] && digest->len < BPC_DIGEST_LEN_MAX ; hexStr += 2 ) {
        digest->digest[digest->len++] = bpc_hexStr2byte(hexStr[0], hexStr[1]);
    }
}

void bpc_digest_md52path(char *path, int compress, bpc_digest *digest)
{
    char *out;

    /*
     * MD5 digest of an empty file (ie, md5sum /dev/null)
     */
    static uchar emptyFileMD5[] = {
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
#if 0
    /*
     * Test code to create collisions in pool files.
     * If you turn on this test, you should also force the zeroLenMD5
     * digest comparison in bpc_poolWrite_write() to true.
     */
    bpc_digest fixedDigest = *digest;
    digest = &fixedDigest;
    memcpy(digest->digest, emptyFileMD5, sizeof(emptyFileMD5));
#endif
    if ( digest->len == sizeof(emptyFileMD5) && !memcmp(digest->digest, emptyFileMD5, sizeof(emptyFileMD5)) ) {
        strcpy(path, "/dev/null");
        return;
    }
    strncpy(path, compress ? BPC_CPoolDir : BPC_PoolDir, BPC_MAXPATHLEN - 32);
    path[BPC_MAXPATHLEN - 48] = '\0';
    out = path + strlen(path);
    *out++ = '/';
    bpc_byte2hex(out, digest->digest[0] & 0xfe); out += 2;
    *out++ = '/';
    bpc_byte2hex(out, digest->digest[1] & 0xfe); out += 2;
    *out++ = '/';
    bpc_digest_digest2str(digest, out);
}

void bpc_digest_md52path_v3(char *path, int compress, bpc_digest *digest)
{
    int i;
    char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
    uint32 ext = 0;
    char n0 = hexDigits[(digest->digest[0] >> 4) & 0xf];
    char n1 = hexDigits[(digest->digest[0] >> 0) & 0xf];
    char n2 = hexDigits[(digest->digest[1] >> 4) & 0xf];

    bpc_digest_digest2str(digest, hexStr);
    for ( i = 16 ; i < digest->len ; i++ ) {
        ext |= digest->digest[i - 16] << (8 * (i - 16));
    }
    if ( ext > 0 ) {
        snprintf(path, BPC_MAXPATHLEN, "%s/%c/%c/%c/%s_%d", compress ? BPC_CPoolDir3 : BPC_PoolDir3, n0, n1, n2, hexStr, ext);
    } else {
        snprintf(path, BPC_MAXPATHLEN, "%s/%c/%c/%c/%s", compress ? BPC_CPoolDir3 : BPC_PoolDir3, n0, n1, n2, hexStr);
    }
}

void bpc_digest_buffer2MD5_v3(bpc_digest *digest, uchar *buffer, size_t bufferLen)
{
    char lenStr[256];

    md_context md5;
    md5_begin(&md5);
    sprintf(lenStr, "%llu", (long long unsigned int)bufferLen);
    md5_update(&md5, (uchar*)lenStr, strlen(lenStr));
    if ( bufferLen > 262144 ) {
        /*
         * add the first and last 131072 bytes of the buffer,
         * up to 1MB.
         */
        int seekPosn = (bufferLen > 1048576 ? 1048576 : bufferLen) - 131072;
        md5_update(&md5, buffer, 131072);
        md5_update(&md5, buffer + seekPosn, 131072);
    } else {
        /*
         * add the whole buffer
         */
        md5_update(&md5, buffer, bufferLen);
    }
    md5_result(&md5, digest->digest);
    digest->len = MD5_DIGEST_LEN;
}

static void bpc_fileNameEltMangle2(char *path, int pathSize, char *pathUM, int stopAtSlash)
{
    if ( !*pathUM || (stopAtSlash && *pathUM == '/') ) {
        *path = '\0';
        return;
    }
    *path++ = 'f'; pathSize--;
    for ( ; *pathUM && pathSize > 4 ; ) {
        if ( stopAtSlash && *pathUM == '/' ) break;
        if ( *pathUM != '%' && *pathUM != '/' && *pathUM != '\n' && *pathUM != '\r' ) {
            *path++ = *pathUM++; pathSize--;
        } else {
            *path++ = '%'; pathSize--;
            bpc_byte2hex(path, *pathUM++);
            path += 2; pathSize -= 2;
        }
    }
    *path = '\0';
}

void bpc_fileNameEltMangle(char *path, int pathSize, char *pathUM)
{
    bpc_fileNameEltMangle2(path, pathSize, pathUM, 0);
}

void bpc_fileNameMangle(char *path, int pathSize, char *pathUM)
{
    char *p;

    for ( ; *pathUM && pathSize > 4 ; ) {
        int len;

        bpc_fileNameEltMangle2(path, pathSize, pathUM, 1);
        len = strlen(path);
        path += len; pathSize -= len;
        if ( !(p = strchr(pathUM, '/')) ) break;
        for ( pathUM = p + 1 ; *pathUM == '/' ; pathUM++ ) { }
        if ( *pathUM ) {
            *path++ = '/'; pathSize--;
        }
    }
    *path = '\0';
}

void bpc_bufferResize(void **bufPtr, size_t *bufLen, size_t needed, size_t incrLen)
{
    if ( !*bufPtr) {
        *bufLen = incrLen;
        *bufPtr = malloc(*bufLen);
    } else if ( needed >= *bufLen ) {
        *bufLen = needed + incrLen;
        *bufPtr = realloc(*bufPtr, *bufLen);
    }
    if ( !*bufPtr ) {
        fprintf(stderr, "bpc_bufferResize: panic: can't alloc %lu bytes\n", (unsigned long)*bufLen);
    }
}

int bpc_vsnprintf(char **buf, size_t *bufLen, unsigned int offset, size_t incrLen, char *fmt, va_list args)
{
    int strLen = strlen(fmt);

    do {
        va_list args2;
        va_copy(args2, args);

        bpc_bufferResize((void**)buf, bufLen, offset + strLen, incrLen);
        strLen = vsnprintf((*buf) + offset, *bufLen - offset, fmt, args2);
        va_end(args2);
    } while ( strLen >= 0 && offset + strLen >= *bufLen );
    return strLen;
}

int bpc_snprintf(char **buf, size_t *bufLen, unsigned int offset, size_t incrLen, char *fmt, ...)
{
    va_list args;
    int strLen;

    va_start(args, fmt);
    strLen = bpc_vsnprintf(buf, bufLen, offset, incrLen, fmt, args);
    va_end(args);
    return strLen;
}

/* 
 * Simple logging functions.  If you register callbacks, they will be called.
 * Otherwise, messages are accumulated, and a callback allows the
 * log strings to be fetched.
 *
 * We store the data in a single buffer of '\0'-terminated strings.
 */
typedef struct {
    char *mesg;
    size_t mesgSize;
    size_t mesgLen;
    unsigned long errorCnt;
} LogMsgData;

static LogMsgData LogData;
static void (*LogMsgCB)(int, char *mesg, size_t mesgLen);

void bpc_logMsgf(char *fmt, ...)
{
    int strLen, pad = 0;
    va_list args;
    va_start(args, fmt); 

    if ( BPC_TmpFileUnique >= 0 ) pad = 2;
    strLen = bpc_vsnprintf(&LogData.mesg, &LogData.mesgSize, LogData.mesgLen + pad, LogData.mesgSize > 8192 ? LogData.mesgSize : 8192, fmt, args);
    if ( strLen > 0 ) {
        if ( pad ) {
            LogData.mesg[LogData.mesgLen++] = BPC_TmpFileUnique ? 'G' : 'R';
            LogData.mesg[LogData.mesgLen++] = ' ';
        }
        LogData.mesgLen += strLen + 1;
    }
    if ( LogMsgCB ) {
        (*LogMsgCB)(0, LogData.mesg, LogData.mesgLen - 1);
        LogData.mesgLen = 0;
    }
    va_end(args);
}

/*
 * For now, this is just the same as bpc_logMsgf().  We can't call a common routine that
 * does the work, since args might need to be parsed twice when the buffer is grown.
 */
void bpc_logErrf(char *fmt, ...)
{
    int strLen, pad = 0;
    va_list args;
    va_start(args, fmt); 

    if ( BPC_TmpFileUnique >= 0 ) pad = 2;
    strLen = bpc_vsnprintf(&LogData.mesg, &LogData.mesgSize, LogData.mesgLen + pad, LogData.mesgSize > 8192 ? 2 * LogData.mesgSize : 8192, fmt, args);
    if ( strLen > 0 ) {
        if ( pad ) {
            LogData.mesg[LogData.mesgLen++] = BPC_TmpFileUnique ? 'G' : 'R';
            LogData.mesg[LogData.mesgLen++] = ' ';
        }
        LogData.mesgLen += strLen + 1;
    }
    if ( LogMsgCB ) {
        (*LogMsgCB)(0, LogData.mesg, LogData.mesgLen - 1);
        LogData.mesgLen = 0;
    }
    va_end(args);
}

void bpc_logMsgGet(char **mesg, size_t *mesgLen)
{
    *mesg    = LogData.mesg;
    *mesgLen = LogData.mesgLen;
    LogData.mesgLen = 0;
}

void bpc_logMsgErrorCntGet(unsigned long *errorCnt)
{
    *errorCnt = LogData.errorCnt;
    LogData.errorCnt = 0;
}

void bpc_logMsgCBSet(void (*cb)(int errFlag, char *mesg, size_t mesgLen))
{
    LogMsgCB = cb;
}
