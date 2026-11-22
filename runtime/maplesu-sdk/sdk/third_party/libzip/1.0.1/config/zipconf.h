#ifndef _HAD_ZIPCONF_H
#define _HAD_ZIPCONF_H

/*
   zipconf.h -- platform specific include file

   This file was generated automatically by lib/make_zipconf.sh
   (libzip 1.0.1) applied to this build's config.h, i.e. the autoconf/ndk
   flavour of the header, not the CMake flavour.
   Rationale (S2 evidence): the CMake flavour uses
     #define ZIP_INT64_MIN -0x8000000000000000LL
   whose constant has type `unsigned long long`, so `offset < ZIP_INT64_MIN`
   in zip_source_filep.c becomes an unsigned compare that is TRUE for every
   non-negative offset and cannot be folded away.  The vendor object's
   .text._zip_fseek is 68 B (no range check), which is only reachable when
   ZIP_INT64_MIN has a signed type -- i.e. INT64_MIN from <stdint.h>, which is
   what make_zipconf.sh emits.  See elf/logs/S2-03-zipconf-flavour.md.
 */

#define LIBZIP_VERSION "1.0.1"
#define LIBZIP_VERSION_MAJOR 1
#define LIBZIP_VERSION_MINOR 0
#define LIBZIP_VERSION_MICRO 1

#include <inttypes.h>

typedef int8_t zip_int8_t;
#define ZIP_INT8_MIN INT8_MIN
#define ZIP_INT8_MAX INT8_MAX

typedef uint8_t zip_uint8_t;
#define ZIP_UINT8_MAX UINT8_MAX

typedef int16_t zip_int16_t;
#define ZIP_INT16_MIN INT16_MIN
#define ZIP_INT16_MAX INT16_MAX

typedef uint16_t zip_uint16_t;
#define ZIP_UINT16_MAX UINT16_MAX

typedef int32_t zip_int32_t;
#define ZIP_INT32_MIN INT32_MIN
#define ZIP_INT32_MAX INT32_MAX

typedef uint32_t zip_uint32_t;
#define ZIP_UINT32_MAX UINT32_MAX

typedef int64_t zip_int64_t;
#define ZIP_INT64_MIN INT64_MIN
#define ZIP_INT64_MAX INT64_MAX

typedef uint64_t zip_uint64_t;
#define ZIP_UINT64_MAX UINT64_MAX

#endif /* zipconf.h */
