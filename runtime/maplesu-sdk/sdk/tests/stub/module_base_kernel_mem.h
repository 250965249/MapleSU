// R5 host test —— module_base_kernel_mem.h 的主机侧替身。
// ABI 与 include/module_base_kernel_mem.h 逐条一致（枚举底层类型、12 个函数签名），
// 只是去掉了 <unistd.h>/<fcntl.h> 这些 Android/POSIX 专属头，保证主机可编译。
#pragma once

#include <cstdint>

#include "module_err_def.h"

namespace kernel_module {

enum class KernMemProt : uint8_t {
    KMP_RO,  // 只读区域
    KMP_RW,  // 可读写区域
    KMP_X    // 仅执行区域
};

KModErr alloc_kernel_mem(uint32_t size, uint64_t& out_kaddr);
KModErr free_kernel_mem(uint64_t kaddr);
KModErr read_kernel_mem(uint64_t kaddr, void* buf, uint32_t size);
KModErr write_kernel_mem(uint64_t kaddr, const void* buf, uint32_t size,
                         KernMemProt prot = KernMemProt::KMP_RW);
KModErr fill00_kernel_mem(uint64_t kaddr, uint32_t size, KernMemProt prot = KernMemProt::KMP_RW);
KModErr read_kernel_mem_atomic32(uint64_t kaddr, uint32_t& out_val);
KModErr read_kernel_mem_atomic64(uint64_t kaddr, uint64_t& out_val);
KModErr write_kernel_rw_mem_atomic32(uint64_t kaddr, uint32_t val);
KModErr write_kernel_rw_mem_atomic64(uint64_t kaddr, uint64_t val);
KModErr set_kernel_mem_protection(uint64_t kaddr, uint64_t size, KernMemProt prot);
KModErr get_kernel_base_vaddr(uint64_t& result);
uint32_t get_page_size();

}  // namespace kernel_module
