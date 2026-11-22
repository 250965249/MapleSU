#pragma once
#include "module_err_def.h"
#include "aarch64_asm_helper.h"
#include "module_base_kernel_mem.h"
#include "module_base_kernel_symbol_kaddr.h"
#include "module_base_kernel_func_executor.h"
#include <string>
namespace kernel_module { bool is_kernel_version_less(const char*); }
#if defined(_WIN32)
#define _SC_PAGESIZE 30
extern "C" long sysconf(int);
#endif
