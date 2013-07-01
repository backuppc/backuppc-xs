/*
 * Based on original rsync.h, which has these copyrights:
 *
 * Copyright (C) 1996, 2000 Andrew Tridgell
 * Copyright (C) 1996 Paul Mackerras
 * Copyright (C) 2001, 2002 Martin Pool <mbp@samba.org>
 * Copyright (C) 2003-2008 Wayne Davison
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

#include "config.h"

#ifndef __GNUC__
#define __attribute__(x)
#else
# if __GNUC__ <= 2
# define NORETURN
# endif
#endif

#define UNUSED(x) x __attribute__((__unused__))
#ifndef NORETURN
#define NORETURN __attribute__((__noreturn__))
#endif

#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_STRING_H
# if !defined STDC_HEADERS && defined HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if defined HAVE_MALLOC_H && (defined HAVE_MALLINFO || !defined HAVE_STDLIB_H)
#include <malloc.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#else
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <signal.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <errno.h>

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#if defined HAVE_LUTIMES || defined HAVE_UTIMENSAT
#define CAN_SET_SYMLINK_TIMES 1
#endif

#if defined HAVE_LCHOWN || defined CHOWN_MODIFIES_SYMLINK
#define CAN_CHOWN_SYMLINK 1
#endif

#if defined HAVE_LCHMOD || defined HAVE_SETATTRLIST
#define CAN_CHMOD_SYMLINK 1
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_MODE_H
/* apparently AIX needs this for S_ISLNK */
#ifndef S_ISLNK
#include <sys/mode.h>
#endif
#endif

/* these are needed for the uid/gid mapping code */
#include <pwd.h>
#include <grp.h>

#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <syslog.h>
#include <sys/file.h>

#ifdef HAVE_DIRENT_H
# include <dirent.h>
#else
# define dirent direct
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
# if !defined makedev && (defined mkdev || defined _WIN32 || defined __WIN32__)
#  define makedev mkdev
# endif
#elif defined MAJOR_IN_SYSMACROS
#include <sys/sysmacros.h>
#endif

#ifdef MAKEDEV_TAKES_3_ARGS
#define MAKEDEV(devmajor,devminor) makedev(0,devmajor,devminor)
#else
#define MAKEDEV(devmajor,devminor) makedev(devmajor,devminor)
#endif

#ifdef HAVE_COMPAT_H
#include <compat.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif

#if defined USE_ICONV_OPEN && defined HAVE_ICONV_H
#include <iconv.h>
#ifndef ICONV_CONST
#define ICONV_CONST
#endif
#else
#ifdef ICONV_CONST
#undef ICONV_CONST
#endif
#ifdef ICONV_OPTION
#undef ICONV_OPTION
#endif
#ifdef iconv_t
#undef iconv_t
#endif
#define iconv_t int
#endif

#include <assert.h>

#ifndef HAVE_ID_T
typedef unsigned int id_t;
#endif
#ifndef HAVE_PID_T
typedef int pid_t;
#endif
#ifndef HAVE_MODE_T
typedef unsigned int mode_t;
#endif
#ifndef HAVE_OFF_T
typedef long off_t;
#undef SIZEOF_OFF_T
#define SIZEOF_OFF_T SIZEOF_LONG
#endif
#ifndef HAVE_SIZE_T
typedef unsigned int size_t;
#endif

#define BOOL int

#ifndef uchar
#define uchar unsigned char
#endif

#ifdef SIGNED_CHAR_OK
#define schar signed char
#else
#define schar char
#endif

#ifndef int16
#if SIZEOF_INT16_T == 2
# define int16 int16_t
#else
# define int16 short
#endif
#endif

#ifndef uint16
#if SIZEOF_UINT16_T == 2
# define uint16 uint16_t
#else
# define uint16 unsigned int16
#endif
#endif

/* Find a variable that is either exactly 32-bits or longer.
 * If some code depends on 32-bit truncation, it will need to
 * take special action in a "#if SIZEOF_INT32 > 4" section. */
#ifndef int32
#if SIZEOF_INT32_T == 4
# define int32 int32_t
# define SIZEOF_INT32 4
#elif SIZEOF_INT == 4
# define int32 int
# define SIZEOF_INT32 4
#elif SIZEOF_LONG == 4
# define int32 long
# define SIZEOF_INT32 4
#elif SIZEOF_SHORT == 4
# define int32 short
# define SIZEOF_INT32 4
#elif SIZEOF_INT > 4
# define int32 int
# define SIZEOF_INT32 SIZEOF_INT
#elif SIZEOF_LONG > 4
# define int32 long
# define SIZEOF_INT32 SIZEOF_LONG
#else
# error Could not find a 32-bit integer variable
#endif
#else
# define SIZEOF_INT32 4
#endif

#ifndef uint32
#if SIZEOF_UINT32_T == 4
# define uint32 uint32_t
#else
# define uint32 unsigned int32
#endif
#endif

#if SIZEOF_OFF_T == 8 || !SIZEOF_OFF64_T || !defined HAVE_STRUCT_STAT64
#define OFF_T off_t
#define STRUCT_STAT struct stat
#define SIZEOF_CAPITAL_OFF_T SIZEOF_OFF_T
#else
#define OFF_T off64_t
#define STRUCT_STAT struct stat64
#define USE_STAT64_FUNCS 1
#define SIZEOF_CAPITAL_OFF_T SIZEOF_OFF64_T
#endif

/* CAVEAT: on some systems, int64 will really be a 32-bit integer IFF
 * that's the maximum size the file system can handle and there is no
 * 64-bit type available.  The rsync source must therefore take steps
 * to ensure that any code that really requires a 64-bit integer has
 * it (e.g. the checksum code uses two 32-bit integers for its 64-bit
 * counter). */
#if SIZEOF_INT64_T == 8
# define int64 int64_t
# define SIZEOF_INT64 8
#elif SIZEOF_LONG == 8
# define int64 long
# define SIZEOF_INT64 8
#elif SIZEOF_INT == 8
# define int64 int
# define SIZEOF_INT64 8
#elif SIZEOF_LONG_LONG == 8
# define int64 long long
# define SIZEOF_INT64 8
#elif SIZEOF_OFF64_T == 8
# define int64 off64_t
# define SIZEOF_INT64 8
#elif SIZEOF_OFF_T == 8
# define int64 off_t
# define SIZEOF_INT64 8
#elif SIZEOF_INT > 8
# define int64 int
# define SIZEOF_INT64 SIZEOF_INT
#elif SIZEOF_LONG > 8
# define int64 long
# define SIZEOF_INT64 SIZEOF_LONG
#elif SIZEOF_LONG_LONG > 8
# define int64 long long
# define SIZEOF_INT64 SIZEOF_LONG_LONG
#else
/* As long as it gets... */
# define int64 off_t
# define SIZEOF_INT64 SIZEOF_OFF_T
#endif

#if OLD_HARDCODED
typedef unsigned char uchar;

typedef unsigned int uint32;

typedef int int32;

typedef ssize_t int64;

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

#define STRUCT_STAT struct stat

#endif

#include "byteorder.h"
#include "md5/mdigest.h"
