// Private owner for one kernel virtual-memory range obtained from vmalloc().
//
// The guard owns the address it currently holds.  Installing a new address
// first releases the old one through an in-kernel vfree() call generated with
// the kit's asmjit emitter, then records the new (address, size) pair.  The
// destructor releases whatever is still owned.  Every method is inline so the
// member translation unit carries the only copy, exactly like the frozen
// build's private helper header.
//
// This header is an implementation detail of
// module_base_kernel_physical_addr.cpp; it is not part of the public API.
#pragma once

#include <cstdint>
#include <functional>
#include <vector>

// Emits one AArch64 routine that only needs the assembler, runs it in kernel
// mode with the standard prologue/epilogue, and reports the kit error.  The
// routine is only finished when the emitter succeeded, so a failed emit never
// reaches the kernel.  The routine's x0 is not consumed.
static KModErr __attribute__((always_inline)) run_kernel_routine(
        std::function<KModErr(asmjit::a64::Assembler*)> gen) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    asmjit::a64::Assembler* a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);

    KModErr err = gen(a);
    if (is_failed(err)) {
        return err;
    }

    kernel_module::arm64_module_asm_func_end(a);
    uint64_t result = 0;
    std::vector<uint8_t> func_bytes = aarch64_asm_to_bytes(a);
    return kernel_module::execute_kernel_asm_func(func_bytes, result);
}

// Switches the kit's symbol-lookup diagnostics off for the lifetime of the
// object when they were on, and restores them on destruction.  The frozen
// member carries this hash suffix for the private copy of the guard (the
// public runtime-helper header carries the 8dfccc suffix for the same class).
class SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 final {
public:
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8() noexcept {
        active_ = get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3();
        if (active_) {
            set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(false);
        }
    }
    ~SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8() noexcept {
        if (active_) {
            set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(true);
        }
    }
    DISABLE_COPY_MOVE(SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8);

private:
    bool active_ = false;
};

struct vmalloc_guard {
    uint64_t kaddr;
    uint64_t size;

    vmalloc_guard(uint64_t new_kaddr, uint64_t new_size) : kaddr(0), size(0) {
        reset(new_kaddr, new_size);
    }

    ~vmalloc_guard() {
        reset(0, 0);
    }

    // Releases the held address (if any) and installs the new pair.  A zero
    // address means "hold nothing"; the size is stored only as bookkeeping.
    void reset(uint64_t new_kaddr, uint64_t new_size) {
        const uint64_t old_kaddr = kaddr;
        if (old_kaddr) {
            kaddr = 0;
            size = 0;
            kernel_vfree(old_kaddr);
        }
        if (new_kaddr) {
            kaddr = new_kaddr;
            size = new_size;
        }
    }

    // Calls the kernel's vfree(address) from a generated kernel-side routine.
    // A zero address is a no-op success.
    static KModErr kernel_vfree(uint64_t target) {
        if (target == 0) {
            return KModErr::OK;
        }
        return run_kernel_routine([target](asmjit::a64::Assembler* a) -> KModErr {
            KModErr call_err = KModErr::OK;
            kernel_module::export_symbol::vfree(a, call_err, target);
            return call_err;
        });
    }
};
