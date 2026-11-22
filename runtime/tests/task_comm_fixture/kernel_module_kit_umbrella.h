#pragma once
#include "module_err_def.h"
#include <cstdint>
#include <vector>
namespace asmjit::a64 {
struct GpX { unsigned id; };
inline constexpr GpX x0{0};
struct Assembler {};
}
struct aarch64_asm_ctx {
    asmjit::a64::Assembler* assembler();
    bool has_error();
};
aarch64_asm_ctx init_aarch64_asm();
std::vector<uint8_t> aarch64_asm_to_bytes(asmjit::a64::Assembler*);
namespace kernel_module {
void arm64_module_asm_func_start(asmjit::a64::Assembler*);
void arm64_module_asm_func_end(asmjit::a64::Assembler*, asmjit::a64::GpX);
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&, uint64_t&);
KModErr read_kernel_mem(uint64_t, void*, uint32_t);
KModErr get_task_struct_comm_offset(uint32_t&);
namespace export_symbol {
void get_current(asmjit::a64::Assembler*, asmjit::a64::GpX);
}
}
