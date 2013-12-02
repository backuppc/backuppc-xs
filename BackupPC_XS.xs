/*
 * XS glue for perl interface to BackupPC libraries.
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


#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <backuppc.h>

typedef bpc_fileZIO_fd          *BackupPC__XS__FileZIO;
typedef bpc_refCount_info       *BackupPC__XS__PoolRefCnt;
typedef bpc_poolWrite_info      *BackupPC__XS__PoolWrite;
typedef bpc_attrib_dir          *BackupPC__XS__Attrib;
typedef bpc_attribCache_info    *BackupPC__XS__AttribCache;

#define hv_get_int(hv, key, value)       { SV** svp = hv_fetch((hv), (key), strlen(key), 0); if ( svp && *svp ) (value) = SvIV(*svp); }
#define hv_get_uint(hv, key, value)      { SV** svp = hv_fetch((hv), (key), strlen(key), 0); if ( svp && *svp ) (value) = SvUV(*svp); }
#define hv_get_str(hv, key, value, len)  { SV** svp = hv_fetch((hv), (key), strlen(key), 0); if ( svp && *svp ) (value) = SvPV(*svp, len); }

static HV* convert_file2hv(bpc_attrib_file *file, char *fileName)
{
    HV *rh;
    size_t listLen, i;

    rh = newHV();
    (void)hv_store(rh, "uid", 3,      newSVuv(file->uid), 0);
    (void)hv_store(rh, "gid", 3,      newSVuv(file->gid), 0);
    (void)hv_store(rh, "name", 4,     newSVpvn(fileName, strlen(fileName)), 0);
    (void)hv_store(rh, "type", 4,     newSVuv(file->type), 0);
    (void)hv_store(rh, "mode", 4,     newSVuv(file->mode), 0);
    (void)hv_store(rh, "size", 4,     newSVuv(file->size), 0);
    (void)hv_store(rh, "mtime", 5,    newSVuv(file->mtime), 0);
    (void)hv_store(rh, "inode", 5,    newSVuv(file->inode), 0);
    (void)hv_store(rh, "nlinks", 6,   newSVuv(file->nlinks), 0);
    (void)hv_store(rh, "digest", 6,   newSVpvn((char*)file->digest.digest, file->digest.len), 0);
    (void)hv_store(rh, "compress", 8, newSVuv(file->compress), 0);

    if ( (listLen = bpc_attrib_xattrList(file, NULL, 0, 0)) > 0 ) {
        char *keys = malloc(listLen), *p;

        if ( keys && bpc_attrib_xattrList(file, keys, listLen, 0) > 0 ) {
            HV *rhAttr = newHV();
            for ( i = 0, p = keys ; i < listLen ; ) {
                int len = strlen(p);
                /*
                 * xattr keys include the \0 terminating byte in the length, so add 1 here,
                 * and subtract 1 in the hv_store() below.
                 */
                bpc_attrib_xattr *xattr = bpc_attrib_xattrGet(file, p, len + 1, 0);
                p += len + 1;
                i += len + 1;
                if ( !xattr ) continue;
                (void)hv_store(rhAttr, xattr->key.key, xattr->key.keyLen - 1, newSVpvn(xattr->value, xattr->valueLen), 0);
            }
            (void)hv_store(rh, "xattr", 5, newRV_noinc((SV*)rhAttr), 0);
        }
        if ( keys ) free(keys);
    }
    return rh;
}

static void convert_hv2file(HV *hv, bpc_attrib_file *file)
{
    char *digestStr = "";
    STRLEN digestLen = 0;
    SV** svp;

    hv_get_uint(hv, "uid", file->uid);
    hv_get_uint(hv, "gid", file->gid);
    hv_get_uint(hv, "type", file->type);
    hv_get_uint(hv, "mode", file->mode);
    hv_get_uint(hv, "size", file->size);
    hv_get_uint(hv, "mtime", file->mtime);
    hv_get_uint(hv, "inode", file->inode);
    hv_get_uint(hv, "nlinks", file->nlinks);
    hv_get_uint(hv, "compress", file->compress);
    hv_get_str(hv,  "digest", digestStr, digestLen);
    if ( 0 < digestLen && digestLen <= sizeof(file->digest.digest) ) {
        memcpy(file->digest.digest, digestStr, digestLen);
        file->digest.len = digestLen;
    } else {
        file->digest.len = 0;
    }
    if ( (svp = hv_fetch(hv, "xattr", 5, 0)) && *svp ) {
        HE *he;
        HV *hvXattr = (HV*)SvRV(*svp);
        /*
         * clear out the old xattrs, and copy in the new
         */
        bpc_attrib_xattrDeleteAll(file);
        hv_iterinit(hvXattr);
        while ( (he = hv_iternext(hvXattr)) ) {
            I32 keyLen;
            STRLEN valueLen;
            char *key = hv_iterkey(he, &keyLen), *value;
            SV *valSV = hv_iterval(hvXattr, he);

            value = SvPV(valSV, valueLen);
            bpc_attrib_xattrSetValue(file, key, keyLen, value, valueLen);
        }
    }
}

MODULE = BackupPC::XS		PACKAGE = BackupPC::XS::FileZIO

PROTOTYPES: DISABLE

BackupPC::XS::FileZIO
open(fileName, writeFile, compressLevel)
        char *fileName;
        int writeFile;
        int compressLevel;
    CODE:
    {
        RETVAL = calloc(1, sizeof(bpc_fileZIO_fd));
        if ( bpc_fileZIO_open(RETVAL, fileName, writeFile, compressLevel) < 0 ) {
            free(RETVAL);
            XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

BackupPC::XS::FileZIO
fdopen(stream, writeFile, compressLevel)
        FILE *stream;
        int writeFile;
        int compressLevel;
    CODE:
    {
        RETVAL = calloc(1, sizeof(bpc_fileZIO_fd));
        if ( bpc_fileZIO_fdopen(RETVAL, stream, writeFile, compressLevel) < 0 ) {
            free(RETVAL);
            XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(fd)
        BackupPC::XS::FileZIO fd;
    CODE:
        bpc_fileZIO_close(fd);
        free(fd);

void
close(fd)
        BackupPC::XS::FileZIO fd
    CODE:
    {
        bpc_fileZIO_close(fd);
    }

int
rewind(fd)
        BackupPC::XS::FileZIO fd
    CODE:
    {
        RETVAL = bpc_fileZIO_rewind(fd);
    }
    OUTPUT:
        RETVAL

int
write(fd, data)
        BackupPC::XS::FileZIO fd;
        SV *data;
    CODE:
    {
        char *str;
        STRLEN len;

        if ( SvROK(data) ) {
            str = SvPV(SvRV(data), len);
            RETVAL = bpc_fileZIO_write(fd, (unsigned char*)str, len);
        } else {
            RETVAL = -1;
        }
    }
    OUTPUT:
        RETVAL

int
read(fd, data, len)
        BackupPC::XS::FileZIO fd;
        SV *data;
        STRLEN len
    CODE:
    {
        char *str;
        SV *d;
        STRLEN dLen;

        if ( SvROK(data) ) {
            d = SvRV(data);
            if (! SvOK(d))
                sv_setpvs(d, "");
            SvGROW(d, len);
            str = SvPV(d, dLen);
            RETVAL = bpc_fileZIO_read(fd, (unsigned char*)str, len);
            SvCUR_set(d, RETVAL);
        } else {
            RETVAL = -1;
        }
    }
    OUTPUT:
        RETVAL

SV*
readLine(fd)
        BackupPC::XS::FileZIO fd;
    CODE:
    {
        char *str;
        size_t strLen;
        if ( bpc_fileZIO_readLine(fd, &str, &strLen) || !str ) XSRETURN_UNDEF;
        RETVAL = newSVpvn(str, strLen);
    }
    OUTPUT:
        RETVAL

void
writeTeeStderr(fd, tee)
        BackupPC::XS::FileZIO fd;
        int tee;
    CODE:
        bpc_fileZIO_writeTeeStderr(fd, tee);

MODULE = BackupPC::XS		PACKAGE = BackupPC::XS::PoolRefCnt

BackupPC::XS::PoolRefCnt
new(entryCnt = 65536)
        int entryCnt;
    CODE:
    {
        RETVAL = calloc(1, sizeof(bpc_refCount_info));
        bpc_poolRefInit((bpc_refCount_info*)RETVAL, entryCnt);
    }
    OUTPUT:
        RETVAL

void
DESTROY(info)
        BackupPC::XS::PoolRefCnt info;
    CODE:
    {
        bpc_poolRefDestroy(info);
        free(info);
    }

int
get(info, d)
        BackupPC::XS::PoolRefCnt info;
        SV *d;
    CODE:
    {
        bpc_digest digest;
        char *str;
        STRLEN len;
        int count;

        if ( !SvPOK(d) ) {
            XSRETURN_UNDEF;
        }
        str = SvPV(d, len);
        if ( 0 < len && len < sizeof(digest.digest) ) {
            memcpy(digest.digest, str, len);
            digest.len = len;
            if ( bpc_poolRefGet(info, &digest, &count) ) XSRETURN_UNDEF;
            RETVAL = count;
        } else {
            XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

int
set(info, d, count)
        BackupPC::XS::PoolRefCnt info;
        SV *d;
        int count;
    CODE:
    {
        bpc_digest digest;
        char *str;
        STRLEN len;

        if ( !SvPOK(d) ) {
            XSRETURN_UNDEF;
        }
        str = SvPV(d, len);
        if ( 0 < len && len < sizeof(digest.digest) ) {
            memcpy(digest.digest, str, len);
            digest.len = len;
            bpc_poolRefSet(info, &digest, count);
            RETVAL = count;
        } else {
            XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

int
delete(info, d)
        BackupPC::XS::PoolRefCnt info;
        SV *d;
    CODE:
    {
        bpc_digest digest;
        char *str;
        STRLEN len;

        if ( !SvPOK(d) ) {
            XSRETURN_UNDEF;
        }
        str = SvPV(d, len);
        if ( 0 < len && len < sizeof(digest.digest) ) {
            memcpy(digest.digest, str, len);
            digest.len = len;
            if ( bpc_poolRefDelete(info, &digest) ) XSRETURN_UNDEF;
            RETVAL = 1;
        } else {
            XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

int
incr(info, d, delta)
        BackupPC::XS::PoolRefCnt info;
        SV *d;
        int delta;
    CODE:
    {
        bpc_digest digest;
        char *str;
        STRLEN len;

        if ( !SvPOK(d) ) {
            XSRETURN_UNDEF;
        }
        str = SvPV(d, len);
        if ( 0 < len && len < sizeof(digest.digest) ) {
            memcpy(digest.digest, str, len);
            digest.len = len;
            RETVAL = bpc_poolRefIncr(info, &digest, delta);
        } else {
            XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

void
iterate(info, idx)
        BackupPC::XS::PoolRefCnt info;
        unsigned int idx;
    PREINIT:
        bpc_digest digest;
        int count;
    PPCODE:
    {
        if ( !bpc_poolRefIterate(info, &digest, &count, &idx) ) {
            EXTEND(SP, 3);
            PUSHs(sv_2mortal(newSVpvn((char*)digest.digest, digest.len)));
            PUSHs(sv_2mortal(newSViv(count)));
            PUSHs(sv_2mortal(newSViv(idx)));
        }
    }

int
read(info, fileName)
        BackupPC::XS::PoolRefCnt info;
        char *fileName;
    CODE:
        RETVAL = bpc_poolRefFileRead(info, fileName);
    OUTPUT:
        RETVAL

int
write(info, fileName)
        BackupPC::XS::PoolRefCnt info;
        char *fileName;
    CODE:
        RETVAL = bpc_poolRefFileWrite(info, fileName);
    OUTPUT:
        RETVAL

void
print(info)
        BackupPC::XS::PoolRefCnt info;
    CODE:
        bpc_poolRefCountPrint(info);

void
DeltaFileInit(hostDir)
        char *hostDir;
    CODE:
        bpc_poolRefDeltaFileInit(hostDir);

unsigned int
DeltaFileFlush()
    CODE:
        RETVAL = bpc_poolRefDeltaFileFlush();
    OUTPUT:
        RETVAL

void
DeltaUpdate(compress, d, count)
        int compress;
        SV *d;
        int count;
    CODE:
    {
        bpc_digest digest;
        char *str;
        STRLEN len;

        if ( SvPOK(d) ) {
            str = SvPV(d, len);
            if ( 0 < len && len < sizeof(digest.digest) ) {
                memcpy(digest.digest, str, len);
                digest.len = len;
                bpc_poolRefDeltaUpdate(compress, &digest, count);
            }
        }
    }

void
DeltaPrint()
    CODE:
        bpc_poolRefDeltaPrint();

MODULE = BackupPC::XS		PACKAGE = BackupPC::XS::PoolWrite

BackupPC::XS::PoolWrite
new(compressLevel, d = NULL)
        int  compressLevel;
        SV   *d;
    CODE:
    {
        int ret = 0;

        RETVAL = calloc(1, sizeof(bpc_poolWrite_info));
        if ( d && SvPOK(d) ) {
            bpc_digest digest;
            char *str;
            STRLEN len;

            str = SvPV(d, len);
            if ( 0 < len && len < sizeof(digest.digest) ) {
                memcpy(digest.digest, str, len);
                digest.len = len;
                ret = bpc_poolWrite_open(RETVAL, compressLevel, &digest);
            } else {
                ret = bpc_poolWrite_open(RETVAL, compressLevel, NULL);
            }
        } else {
            ret = bpc_poolWrite_open(RETVAL, compressLevel, NULL);
        }
        if ( ret ) {
            free(RETVAL);
            RETVAL = NULL;
        }
    }
    OUTPUT:
        RETVAL

void
DESTROY(info)
        BackupPC::XS::PoolWrite info;
    CODE:
    {
        bpc_poolWrite_cleanup(info);
        free(info);
    }

void
close(info)
        BackupPC::XS::PoolWrite info;
    PREINIT:
        int match;
        bpc_digest digest;
        off_t poolFileSize;
        int errorCnt;

    PPCODE:
    {
        bpc_poolWrite_close(info, &match, &digest, &poolFileSize, &errorCnt);
        EXTEND(SP, 4);
        PUSHs(sv_2mortal(newSViv(match)));
        PUSHs(sv_2mortal(newSVpvn((char*)digest.digest, digest.len)));
        PUSHs(sv_2mortal(newSViv(poolFileSize)));
        PUSHs(sv_2mortal(newSViv(errorCnt)));
    }

int
write(info, data)
        BackupPC::XS::PoolWrite info;
        SV *data;
    CODE:
    {
        char *str;
        STRLEN len;

        if ( SvROK(data) ) {
            str = SvPV(SvRV(data), len);
            RETVAL = bpc_poolWrite_write(info, (unsigned char*)str, len);
        } else {
            RETVAL = -1;
        }
    }
    OUTPUT:
        RETVAL

void
addToPool(info, fileName, v3PoolFile)
        BackupPC::XS::PoolWrite info;
        char *fileName;
        int v3PoolFile;
    CODE:
        bpc_poolWrite_addToPool(info, fileName, v3PoolFile);

MODULE = BackupPC::XS		PACKAGE = BackupPC::XS::Attrib

BackupPC::XS::Attrib
new(compressLevel)
        int compressLevel;
    CODE:
    {
        RETVAL = calloc(1, sizeof(bpc_attrib_dir));
        bpc_attrib_dirInit(RETVAL, compressLevel);
    }
    OUTPUT:
        RETVAL

void
DESTROY(dir)
        BackupPC::XS::Attrib dir;
    CODE:
    {
        bpc_attrib_dirDestroy(dir);
        free(dir);
    }

SV*
get(dir, fileName = NULL)
        BackupPC::XS::Attrib dir;
        char *fileName;
    CODE:
    {
        if ( fileName ) {
            bpc_attrib_file *file = bpc_attrib_fileGet(dir, fileName, 0);
            if ( !file ) XSRETURN_UNDEF;
            RETVAL = newRV_noinc((SV*)convert_file2hv(file, file->name));
        } else {
            ssize_t entrySize, i;

            RETVAL = NULL;
            if ( (entrySize = bpc_attrib_getEntries(dir, NULL, 0)) > 0 ) {
                char *entries = malloc(entrySize), *p;

                if ( entries && bpc_attrib_getEntries(dir, entries, entrySize) > 0 ) {
                    HV *rh = newHV();
                    for ( i = 0, p = entries ; i < entrySize ; ) {
                        int len = strlen(p);
                        bpc_attrib_file *file;

                        file = bpc_attrib_fileGet(dir, p, 0);
                        p += len + 1;
                        i += len + 1;
                        if ( !file ) continue;
                        (void)hv_store(rh, file->name, strlen(file->name), newRV_noinc((SV*)convert_file2hv(file, file->name)), 0);
                    }
                    RETVAL = newRV_noinc((SV*)rh);
                }
                if ( entries ) free(entries);
            }
            if ( !RETVAL ) XSRETURN_UNDEF;
        }
    }
    OUTPUT:
        RETVAL

int
set(dir, fileName, hv)
        BackupPC::XS::Attrib dir;
        char *fileName;
        HV *hv;
    CODE:
    {
        bpc_attrib_file *file = bpc_attrib_fileGet(dir, fileName, 0);

        RETVAL = file ? 1 : 0;
        if ( !file ) {
            file = bpc_attrib_fileGet(dir, fileName, 1);
            bpc_attrib_fileInit(file, fileName, 0);
        }
        convert_hv2file(hv, file);
    }
    OUTPUT:
        RETVAL

void
digest(dir)
        BackupPC::XS::Attrib dir;
    PREINIT:
    PPCODE:
    {
        bpc_digest *digest = bpc_attrib_dirDigestGet(dir);
        if ( digest && digest->len > 0 ) {
            EXTEND(SP, 1);
            PUSHs(sv_2mortal(newSVpvn((char*)digest->digest, digest->len)));
        }
    }

char*
errStr(void)
    CODE:
        RETVAL = "TODO";
    OUTPUT:
        RETVAL

int
count(dir)
        BackupPC::XS::Attrib dir;
    CODE:
        RETVAL = bpc_attrib_fileCount(dir);
    OUTPUT:
        RETVAL

void
delete(dir, fileName)
        BackupPC::XS::Attrib dir;
        char *fileName;
    CODE:
        bpc_attrib_fileDeleteName(dir, fileName);

int
read(dir, dirPath, attribFileName = "attrib")
        BackupPC::XS::Attrib dir;
        char *dirPath;
        char *attribFileName;
    CODE:
        if ( !*dirPath ) dirPath = NULL;
        RETVAL = !bpc_attrib_dirRead(dir, dirPath, attribFileName, 0);
    OUTPUT:
        RETVAL

int
write(dir, dirPath, attribFileName, d = NULL)
        BackupPC::XS::Attrib dir;
        char *dirPath;
        char *attribFileName;
        SV *d;
    CODE:
        if ( !*dirPath ) dirPath = NULL;
        if ( d && SvPOK(d) ) {
            bpc_digest digest;
            char *str;
            STRLEN len;

            str = SvPV(d, len);
            if ( 0 < len && len < sizeof(digest.digest) ) {
                memcpy(digest.digest, str, len);
                digest.len = len;
                RETVAL = !bpc_attrib_dirWrite(dir, dirPath, attribFileName, &digest);
            } else {
                RETVAL = !bpc_attrib_dirWrite(dir, dirPath, attribFileName, NULL);
            }
        } else {
            RETVAL = !bpc_attrib_dirWrite(dir, dirPath, attribFileName, NULL);
        }
    OUTPUT:
        RETVAL

char *
fileType2Text(type)
        int type;
    CODE:
        RETVAL = bpc_attrib_fileType2Text(type);
    OUTPUT:
        RETVAL

MODULE = BackupPC::XS		PACKAGE = BackupPC::XS::AttribCache

BackupPC::XS::AttribCache
new(host, backupNum, shareNameUM, compress)
        char *host;
        int backupNum;
        char *shareNameUM;
        int compress;
    CODE:
    {
        RETVAL = calloc(1, sizeof(bpc_attribCache_info));
        bpc_attribCache_init(RETVAL, host, backupNum, shareNameUM, compress);
    }
    OUTPUT:
        RETVAL

void
DESTROY(ac)
        BackupPC::XS::AttribCache ac;
    CODE:
    {
        bpc_attribCache_destroy(ac);
        free(ac);
    }

SV*
get(ac, fileName, allocateIfMissing = 0, dontReadInode = 0)
        BackupPC::XS::AttribCache ac;
        char *fileName;
        int allocateIfMissing;
        int dontReadInode;
    CODE:
    {
        bpc_attrib_file *file = bpc_attribCache_getFile(ac, fileName, allocateIfMissing, dontReadInode);

        if ( !file ) XSRETURN_UNDEF;

        RETVAL = newRV_noinc((SV*)convert_file2hv(file, file->name));
    }
    OUTPUT:
        RETVAL

int
set(ac, fileName, hv, dontOverwriteInode = 0)
        BackupPC::XS::AttribCache ac;
        char *fileName;
        HV *hv;
        int dontOverwriteInode;
    CODE:
    {
        bpc_attrib_file *file = bpc_attribCache_getFile(ac, fileName, 1, 0);

        convert_hv2file(hv, file);
        RETVAL = bpc_attribCache_setFile(ac, fileName, file, dontOverwriteInode);
    }
    OUTPUT:
        RETVAL

int
delete(ac, fileName)
        BackupPC::XS::AttribCache ac;
        char *fileName;
    CODE:
        RETVAL = bpc_attribCache_deleteFile(ac, fileName);
    OUTPUT:
        RETVAL

SV*
getInode(ac, inode, allocateIfMissing = 0)
        BackupPC::XS::AttribCache ac;
        unsigned long inode;
        int allocateIfMissing;
    CODE:
    {
        bpc_attrib_file *file = bpc_attribCache_getInode(ac, inode, allocateIfMissing);

        if ( !file ) XSRETURN_UNDEF;

        RETVAL = newRV_noinc((SV*)convert_file2hv(file, file->name));
    }
    OUTPUT:
        RETVAL

int
setInode(ac, inode, hv)
        BackupPC::XS::AttribCache ac;
        unsigned long inode;
        HV *hv;
    CODE:
    {
        bpc_attrib_file *file = bpc_attribCache_getInode(ac, inode, 1);

        convert_hv2file(hv, file);
        RETVAL = bpc_attribCache_setInode(ac, inode, file);
    }
    OUTPUT:
        RETVAL

int
deleteInode(ac, inode)
        BackupPC::XS::AttribCache ac;
        unsigned long inode;
    CODE:
        RETVAL = bpc_attribCache_deleteInode(ac, inode);
    OUTPUT:
        RETVAL

int
count(ac, path)
        BackupPC::XS::AttribCache ac;
        char *path;
    CODE:
        RETVAL = bpc_attribCache_getDirEntryCnt(ac, path);
    OUTPUT:
        RETVAL

SV*
getAll(ac, path, dontReadInode = 0)
        BackupPC::XS::AttribCache ac;
        char *path;
        int dontReadInode;
    CODE:
    {
        ssize_t entrySize, i;
        char pathCopy[BPC_MAXPATHLEN];

        snprintf(pathCopy, sizeof(pathCopy), "%s", path);
        RETVAL = NULL;
        if ( (entrySize = bpc_attribCache_getDirEntries(ac, pathCopy, NULL, 0)) > 0 ) {
            char *entries = malloc(entrySize), *p;

            if ( entries && bpc_attribCache_getDirEntries(ac, pathCopy, entries, entrySize) > 0 ) {
                HV *rh = newHV();
                for ( i = 0, p = entries ; i < entrySize ; ) {
                    int len = strlen(p);
                    char *fileNameSave = p;
                    char filePath[BPC_MAXPATHLEN];
                    bpc_attrib_file *file;

                    snprintf(filePath, sizeof(filePath), "%s/%s", path, p);
                    file = bpc_attribCache_getFile(ac, filePath, 0, dontReadInode);
                    p += len + 1 + sizeof(ino_t);
                    i += len + 1 + sizeof(ino_t);
                    if ( !file ) continue;
                    /* printf("Storing file name %s for path %s\n", fileNameSave, path); */
                    (void)hv_store(rh, fileNameSave, strlen(fileNameSave), newRV_noinc((SV*)convert_file2hv(file, fileNameSave)), 0);
                }
                RETVAL = newRV_noinc((SV*)rh);
            }
            if ( entries ) free(entries);
        }
        if ( !RETVAL ) XSRETURN_UNDEF;
    }
    OUTPUT:
        RETVAL

void
flush(ac, all = 1, path = NULL)
        BackupPC::XS::AttribCache ac;
        int all
        char *path;
    CODE:
        bpc_attribCache_flush(ac, all, path);

SV*
getFullMangledPath(ac, dirName)
        BackupPC::XS::AttribCache ac;
        char *dirName;
    CODE:
    {
        char path[MAXPATHLEN];
        bpc_attribCache_getFullMangledPath(ac, path, dirName, -1);
        RETVAL = newSVpvn(path, strlen(path));
    }
    OUTPUT:
        RETVAL

MODULE = BackupPC::XS		PACKAGE = BackupPC::XS::DirOps

int
path_create(path)
        char *path;
    CODE:
        RETVAL = bpc_path_create(path);
    OUTPUT:
        RETVAL

int
path_remove(path, compress)
        char *path;
        int compress;
    CODE:
        RETVAL = bpc_path_remove(path, compress);
    OUTPUT:
        RETVAL

int
refCountAll(path, compress)
        char *path;
        int compress;
    CODE:
        RETVAL = bpc_path_refCountAll(path, compress);
    OUTPUT:
        RETVAL

int
lockRangeFd(fd, offset, len, block)
        int fd;
        unsigned int offset;
        unsigned int len;
        int block;
    CODE:
        RETVAL = bpc_lockRangeFd(fd, offset, len, block);
    OUTPUT:
        RETVAL

int
unlockRangeFd(fd, offset, len)
        int fd;
        unsigned int offset;
        unsigned int len;
    CODE:
        RETVAL = bpc_unlockRangeFd(fd, offset, len);
    OUTPUT:
        RETVAL

int
lockRangeFile(lockFile, offset, len, block)
        char *lockFile;
        unsigned int offset;
        unsigned int len;
        int block;
    CODE:
        RETVAL = bpc_lockRangeFile(lockFile, offset, len, block);
    OUTPUT:
        RETVAL

void
unlockRangeFile(lockFd)
        int lockFd;
    CODE:
        bpc_unlockRangeFile(lockFd);
        
MODULE = BackupPC::XS		PACKAGE = BackupPC::XS::Lib

void
ConfInit(topDir, hardLinkMax, poolV3Enabled, logLevel = 0)
        char *topDir;
        int hardLinkMax;
        int poolV3Enabled;
        int logLevel;
    CODE:
        bpc_lib_conf_init(topDir, hardLinkMax, poolV3Enabled, logLevel);

SV*
logMsgGet()
    CODE:
    {
        char *mesg, *p;
        size_t mesgLen, i;
        AV *ra;

        RETVAL = NULL;
        bpc_logMsgGet(&mesg, &mesgLen);
        if ( mesgLen == 0 ) XSRETURN_UNDEF;

        ra = newAV();
        for ( i = 0, p = mesg ; i < mesgLen ; ) {
            int len = strlen(p);

            av_push(ra, newSVpvn(p, len));
            p += len + 1;
            i += len + 1;
        }
        RETVAL = newRV_noinc((SV*)ra);
    }
    OUTPUT:
        RETVAL

int
logErrorCntGet()
    CODE:
    {
        unsigned long errorCnt;
        bpc_logMsgErrorCntGet(&errorCnt);
        RETVAL = errorCnt;
    }
    OUTPUT:
        RETVAL

void
logLevelSet(logLevel)
        int logLevel;
    CODE:
        bpc_lib_setLogLevel(logLevel);
