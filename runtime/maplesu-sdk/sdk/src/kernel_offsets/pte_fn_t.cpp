// pte fn t implementation.
//
#include <cstddef>
#include <cstdint>
#include <functional>

// symbol-lookup guard SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8;
// internal-linkage-free inline class, so its ctor/dtor are weak symbols and the
#define SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 \
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8
#include "kernel_module_kit_umbrella.h"
#undef SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703

// get_offset_cache()/put_offset_cache() are provided by module_base_offset_cache.o
// are plain `declare i64 @_ZN13kernel_module16get_offset_cacheEPKcRj` /
// `...put_offset_cacheEPKcj`).  The offsets group declares them once here.
#include "offsets_internal.h"

// get_kernel_shellcode_u64_result()
//
// aarch64 asmjit context, emit the caller-supplied body between the standard
// arm64_module_asm_func_start() prologue and the ret selected by the body
// (default x0), then execute the resulting machine code in kernel mode and
// publish its X0 return value.  An emitter failure aborts before
// arm64_module_asm_func_end(), so no half-open prologue is ever executed.
static KModErr get_kernel_shellcode_u64_result(
        std::function<KModErr(asmjit::a64::Assembler*, asmjit::a64::GpX&)> emitter,
        uint64_t& out_result) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    asmjit::a64::Assembler* a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);

    asmjit::a64::GpX return_reg = asmjit::a64::regs::x0;
    KModErr err = emitter(a, return_reg);
    if (is_failed(err)) {
        return err;
    }
    kernel_module::arm64_module_asm_func_end(a, return_reg);

    std::vector<uint8_t> func_bytes = aarch64_asm_to_bytes(a);
    return kernel_module::execute_kernel_asm_func(func_bytes, out_result);
}

// safe_read_kaddr()
//
// Reads `size` bytes from an arbitrary kernel address by emitting a kernel-mode
// call to copy_from_kernel_nofault(dst = staging buffer, src = kaddr, size)
// succeeded; the return value carries the alloc/asm/exec/mem errors.
//
// allocated once and freed once on every path.  A read-back failure returns
// that error directly; otherwise a failing free is reported before a failing
// shellcode execution error.
static KModErr safe_read_kaddr(uint64_t kaddr, bool& ok, void* out_buf, size_t size) {
    ok = false;

    uint64_t dst_kaddr = 0;
    KModErr err = kernel_module::alloc_kernel_mem(static_cast<uint32_t>(size), dst_kaddr);
    if (is_failed(err)) {
        return err;
    }

    // x11 = source kernel address (the KCFI hash slot, entry - 4), then the
    // resolved copy_from_kernel_nofault(dst, src, 4); the primitive's return
    // value stays in x0, which is what the shellcode hands back to us.
    uint64_t exec_result = 0;
    err = get_kernel_shellcode_u64_result(
            [kaddr, dst_kaddr, size](asmjit::a64::Assembler* a,
                                     asmjit::a64::GpX& return_reg) -> KModErr {
                asmjit::a64::GpX dst = asmjit::a64::regs::x10;
                aarch64_asm_mov_x(a, dst, dst_kaddr);
                asmjit::a64::GpX src = asmjit::a64::regs::x11;
                aarch64_asm_mov_x(a, src, kaddr);

                KModErr call_err = KModErr::ERR_MODULE_PARAM;
                kernel_module::export_symbol::copy_from_kernel_nofault(
                        a, call_err, dst, src, static_cast<uint64_t>(size));
                if (is_ok(call_err)) {
                    return_reg = asmjit::a64::regs::x0;
                }
                return call_err;
            },
            exec_result);

    if (is_ok(err)) {
        KModErr read_err = kernel_module::read_kernel_mem(
                dst_kaddr, out_buf, static_cast<uint32_t>(size));
        if (is_failed(read_err)) {
            kernel_module::free_kernel_mem(dst_kaddr);
            return read_err;
        }
    }

    KModErr free_err = kernel_module::free_kernel_mem(dst_kaddr);
    if (is_failed(free_err)) {
        return free_err;
    }
    if (is_failed(err)) {
        return err;
    }

    ok = (exec_result == 0);
    return KModErr::OK;
}

// The sibling members read 64-bit scalars through this wrapper; it forwards to
// the byte-wise routine above with the exact width of T.
template <typename T>
static KModErr safe_read_kaddr_t(uint64_t kaddr, bool& ok, T& out) {
    return safe_read_kaddr(kaddr, ok, &out, sizeof(T));
}

namespace kernel_module {

KModErr get_pte_fn_t_kcfi_hash(uint32_t& out_hash) {
    KModErr err = get_offset_cache("pte_fn_t_kcfi_hash", out_hash);
    if (is_ok(err)) {
        return err;
    }

    // their KCFI hash is the hash of the pte_fn_t type on this kernel build.
    static const char* const target_syms[] = {
            "change_page_range",
            "kasan_populate_vmalloc_pte",
            "kasan_depopulate_vmalloc_pte",
    };
    constexpr uint64_t target_sym_count = sizeof(target_syms) / sizeof(target_syms[0]);

    for (uint64_t i = 0; i < target_sym_count; ++i) {
        // duration of the kallsyms lookup by the RAII guard.
        uint64_t sym_kaddr = 0;
        {
            SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 guard;
            kallsyms_lookup_name(target_syms[i], sym_kaddr);
        }

        if (sym_kaddr < 4) {
            continue;
        }

        uint32_t kcfi_hash = 0;
        bool read_ok = false;
        err = safe_read_kaddr(sym_kaddr - 4, read_ok, &kcfi_hash, sizeof(kcfi_hash));
        if (is_failed(err)) {
            return err;
        }

        if (!read_ok || kcfi_hash == 0) {
            continue;
        }

        // getter's return value.
        out_hash = kcfi_hash;
        return put_offset_cache("pte_fn_t_kcfi_hash", kcfi_hash);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

}  // namespace kernel_module
