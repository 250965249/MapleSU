#pragma once
#include "module_err_def.h"
namespace kernel_module::export_symbol {
template<class... T> inline void set_memory_ro(T...) {}
template<class... T> inline void set_memory_rw(T...) {}
template<class... T> inline void set_memory_x(T...) {}
template<class... T> inline void aarch64_insn_patch_text(T...) {}
namespace linux_above_6_12_0 { template<class... T> inline void execmem_free(T...) {} }
namespace linux_older { template<class... T> inline void module_memfree(T...) {} }
}
