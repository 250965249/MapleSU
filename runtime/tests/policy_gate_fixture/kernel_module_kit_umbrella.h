// SDK I/O and assembler fixture for host-side gate planning/failure tests only.
// Actual ARM64 instruction emission is verified separately against the real SDK.
#pragma once
#include "module_err_def.h"
#include <cerrno>
#include <cstdint>
#include <vector>

namespace policy_fixture {
inline bool assembly_error = false;
inline bool finished = false;
inline bool continue_original = true;
inline int64_t return_value = 0;
}
namespace asmjit {
struct Imm { int64_t value; explicit Imm(int64_t v) : value(v) {} };
namespace a64 {
inline constexpr unsigned x0 = 0;
struct Assembler {
    void mov(unsigned reg, Imm value) {
        if (reg != 0) policy_fixture::assembly_error = true;
        policy_fixture::return_value = value.value;
    }
};
}
}
struct aarch64_asm_ctx {
    asmjit::a64::Assembler a;
    auto assembler() { return &a; }
    bool has_error() const { return policy_fixture::assembly_error; }
};
inline aarch64_asm_ctx init_aarch64_asm() {
    policy_fixture::finished = false;
    return {};
}
inline std::vector<uint8_t> aarch64_asm_to_bytes(const asmjit::a64::Assembler*) {
    return policy_fixture::finished ? std::vector<uint8_t>{1, 2, 3, 4} : std::vector<uint8_t>{};
}
namespace kernel_module {
using HookHandle = void*;
inline void arm64_before_hook_start(asmjit::a64::Assembler*) {}
inline void arm64_before_hook_end(asmjit::a64::Assembler*, bool continuation) {
    policy_fixture::finished = true;
    policy_fixture::continue_original = continuation;
}
KModErr kallsyms_lookup_name(const char*, uint64_t&);
KModErr read_kernel_mem(uint64_t, void*, uint32_t);
KModErr install_kernel_function_before_hook(uint64_t, const std::vector<uint8_t>&,
                                           HookHandle* = nullptr);
}
