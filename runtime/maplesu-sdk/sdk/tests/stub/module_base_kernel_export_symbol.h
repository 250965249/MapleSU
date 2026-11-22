// R5 host test —— module_base_kernel_export_symbol.h 的主机侧替身。
// 只保留 m024 实际用到的内核导出符号封装（签名与真实头逐条一致）。
#pragma once

#include <cstdint>

#include "module_err_def.h"
#include "r5_probe.h"

namespace kernel_module {
namespace export_symbol {
using namespace asmjit::a64;

// int set_memory_ro(unsigned long addr, int numpages)
void set_memory_ro(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages);
void set_memory_ro(Assembler* a, KModErr& out_err, GpX addr, GpW numpages);

// int set_memory_rw(unsigned long addr, int numpages)
void set_memory_rw(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages);
void set_memory_rw(Assembler* a, KModErr& out_err, GpX addr, GpW numpages);

// int set_memory_x(unsigned long addr, int numpages)
void set_memory_x(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages);
void set_memory_x(Assembler* a, KModErr& out_err, GpX addr, GpW numpages);

// int aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt)
void aarch64_insn_patch_text(Assembler* a, KModErr& out_err, GpX addrs, GpX insns, GpW cnt);

namespace linux_older {
// void module_memfree(void *module_region)
void module_memfree(Assembler* a, KModErr& out_err, GpX module_region);
}  // namespace linux_older

namespace linux_above_6_12_0 {
// void execmem_free(void *ptr)
void execmem_free(Assembler* a, KModErr& out_err, GpX ptr);
}  // namespace linux_above_6_12_0

}  // namespace export_symbol
}  // namespace kernel_module
