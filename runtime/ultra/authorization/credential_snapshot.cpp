#include <atomic>
#include "kernel_module_kit_umbrella.h"

// read_kernel_mem sends one request per byte. Compare the complete pointer pair
// inside one kernel execution, after that request has committed its private cred.
extern "C" __attribute__((visibility("hidden")))
KModErr maplesu_find_real_cred_offset(uint32_t* output) {
    static std::atomic<uint32_t> cached{0};
    const auto known = cached.load(std::memory_order_relaxed);
    if (known) { *output = known; return KModErr::OK; }
    uint32_t comm = 0;
    auto error = kernel_module::get_task_struct_comm_offset(comm);
    if (is_failed(error)) return error;
    if (comm < 24) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    using namespace kernel_module;
    using namespace asmjit::a64;
    auto context = init_aarch64_asm();
    auto a = context.assembler();
    arm64_module_asm_func_start(a);
    export_symbol::get_current(a, x9);
    a->add(x9, x9, asmjit::Imm(comm - 24));
    a->ldr(x10, ptr(x9));
    a->ldr(x11, ptr(x9, 8));
    a->ldr(x12, ptr(x9, 16));
    const auto earlier = a->newLabel(), done = a->newLabel();
    a->mov(x0, xzr);
    a->cmp(x11, x12);
    a->b(CondCode::kNE, earlier);
    a->cbz(x11, earlier);
    a->mov(x0, asmjit::Imm(comm - 16));
    a->b(done);
    a->bind(earlier);
    a->cmp(x10, x11);
    a->b(CondCode::kNE, done);
    a->cbz(x11, done);
    a->mov(x0, asmjit::Imm(comm - 24));
    a->bind(done);
    arm64_module_asm_func_end(a, x0);
    const auto bytes = aarch64_asm_to_bytes(a);
    if (context.has_error() || bytes.empty()) return KModErr::ERR_MODULE_ASM;
    uint64_t offset = 0;
    error = execute_kernel_asm_func(bytes, offset);
    if (is_failed(error)) return error;
    if (!offset || (offset != comm - 24 && offset != comm - 16))
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    cached.store(static_cast<uint32_t>(offset), std::memory_order_relaxed);
    *output = static_cast<uint32_t>(offset);
    return KModErr::OK;
}
