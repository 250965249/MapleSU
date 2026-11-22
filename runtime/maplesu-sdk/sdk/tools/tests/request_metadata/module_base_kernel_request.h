#pragma once
#include "module_err_def.h"
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
namespace kernel_module {
inline const char* current_module_root_key() {
    return __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
}
KModErr request_kernel_read_mem(uint64_t,void*,uint32_t);
KModErr request_kernel_alloc_mem(uint32_t,uint64_t&);
KModErr request_kernel_write_mem(uint64_t,const void*,uint32_t);
}
