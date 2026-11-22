#pragma once
#include <sys/types.h>
using uid_t = unsigned int;
#define _SC_PAGESIZE 30
#define getpid metadata_test_getpid
extern "C" pid_t metadata_test_getpid();
extern "C" uid_t getuid();
extern "C" long sysconf(int);
