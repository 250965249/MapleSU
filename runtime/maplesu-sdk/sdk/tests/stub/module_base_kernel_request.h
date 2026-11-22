// R5 host test —— module_base_kernel_request.h 的主机侧替身。
// 只保留 m024 实际调用的三条通道入口（签名与 sdk/include 版本一致）。
#pragma once

#include <cstdint>

#include "module_err_def.h"

namespace kernel_module {

KModErr request_kernel_alloc_mem(uint32_t size, uint64_t& out_kaddr);
KModErr request_kernel_write_mem(uint64_t kaddr, const void* buf, uint32_t size);
KModErr request_kernel_read_mem(uint64_t kaddr, void* buf, uint32_t size);

}  // namespace kernel_module
