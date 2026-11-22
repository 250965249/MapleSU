// R5 host test —— module_base_kernel_func_executor.h 的主机侧替身。
// 只保留 m024 实际调用的执行器入口（真实符号属成员 m025）。
#pragma once

#include <cstdint>
#include <vector>

#include "module_err_def.h"

namespace kernel_module {

// 把生成的字节流送到内核执行，并把 shellcode 的返回值带回 out_result。
KModErr execute_kernel_asm_func(const std::vector<uint8_t>& buf, uint64_t& out_result);

}  // namespace kernel_module
