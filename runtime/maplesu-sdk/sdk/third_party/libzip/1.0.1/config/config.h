#ifndef HAD_CONFIG_H
#define HAD_CONFIG_H
#ifndef _HAD_ZIPCONF_H
#include "zipconf.h"
#endif
/* BEGIN DEFINES */
/* #undef HAVE__CLOSE */
/* #undef HAVE__DUP */
/* #undef HAVE__FDOPEN */
/* #undef HAVE__FILENO */
/* #undef HAVE__OPEN */
/* #undef HAVE__SNPRINTF */
/* #undef HAVE__STRDUP */
/* #undef HAVE__STRICMP */
#define HAVE_FSEEKO 1
#define HAVE_FTELLO 1
#define HAVE_OPEN 1
#define HAVE_MKSTEMP 1
#define HAVE_SNPRINTF 1
#define HAVE_SSIZE_T_LIBZIP 1
#define HAVE_STRCASECMP 1
#define HAVE_STRDUP 1
/* #undef HAVE_STRUCT_TM_TM_ZONE */
/* #undef HAVE_MOVEFILEEXA */
#define HAVE_STDBOOL_H 1
#define HAVE_STRINGS_H 1
#define HAVE_UNISTD_H 1
#define __INT8_LIBZIP 1
#define INT8_T_LIBZIP 1
#define UINT8_T_LIBZIP 1
#define __INT16_LIBZIP 1
#define INT16_T_LIBZIP 1
#define UINT16_T_LIBZIP 1
#define __INT32_LIBZIP 1
#define INT32_T_LIBZIP 1
#define UINT32_T_LIBZIP 1
#define __INT64_LIBZIP 1
#define INT64_T_LIBZIP 1
#define UINT64_T_LIBZIP 1
#define SIZEOF_OFF_T 8
#define SIZE_T_LIBZIP 8
#define SSIZE_T_LIBZIP 8
/* #undef HAVE_DIRENT_H */
/* #undef HAVE_NDIR_H */
/* #undef HAVE_SYS_DIR_H */
/* #undef HAVE_SYS_NDIR_H */
/* END DEFINES */
#define PACKAGE "libzip"
#define VERSION "1.0.1"

#ifndef HAVE_SSIZE_T_LIBZIP
#  if SIZE_T_LIBZIP == INT_LIBZIP
typedef int ssize_t;
#  elif SIZE_T_LIBZIP == LONG_LIBZIP
typedef long ssize_t;
#  elif SIZE_T_LIBZIP == LONG_LONG_LIBZIP
typedef long long ssize_t;
#  else
#error no suitable type for ssize_t found
#  endif
#endif

#endif /* HAD_CONFIG_H */
