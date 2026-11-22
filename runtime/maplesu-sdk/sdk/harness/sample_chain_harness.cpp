// MapleSU Pro SDK - sample-chain link harness (consumer stand-in).
//
// This is NOT a production entry point and it is never packaged. It exists so
// `build.py --link-sample` can prove the whole chain closes at link time:
//
//     kernel request  ->  mem permission  ->  write  ->  icache sync  ->  publish
//     (ordinal 23)        (ordinal 24)       (24)      (ordinal 34)     (ordinal 29)
//
// The harness calls every hop of that chain through the same declarations the
// production consumers use:
//   * kernel-memory and hook APIs come from the published kit headers
//     (module_base_kernel_mem.h / module_base_kernel_func_hook.h), i.e. exactly
//     what pro/bridge/native_lib_pro.cpp sees;
//   * the kit-internal entries that have no public header (request_kernel_*,
//     icache_invalidate_all_cpus, install_kfunc_*_with_buf) are declared here
//     with the signatures measured on the baseline members. Those declarations
//     are the ABI contract the sample chain must satisfy.
//
// Linking this file with -Wl,--no-undefined is the acceptance test: if any hop
// of the chain is missing from the four source-built objects, the link fails
// instead of silently falling back to a prebuilt copy.
//
// The function is never executed by the build. It allocates nothing, so it is
// safe to call on a host under a test double as well.

#include "kernel_module_kit_umbrella.h"

#include <cstdint>
#include <vector>

namespace kernel_module {

// --- kit-internal entries, no public header ---------------------------------
KModErr request_kernel_alloc_mem(uint32_t size, uint64_t& out_kaddr);
KModErr request_kernel_read_mem(uint64_t kaddr, void* buf, uint32_t size);
KModErr request_kernel_write_mem(uint64_t kaddr, const void* buf, uint32_t size);
KModErr request_kernel_set_suid_sgid(uint32_t suid, uint32_t sgid);
KModErr icache_invalidate_all_cpus();

KModErr install_kfunc_before_hook_with_buf(uint64_t kaddr, const void* shellcode, uint32_t size,
                                           HookContext** out_hook);
KModErr install_kfunc_after_hook_with_buf(uint64_t kaddr, const void* shellcode, uint32_t size,
                                          HookContext** out_hook);

}  // namespace kernel_module

extern "C" __attribute__((visibility("default"))) int maplesu_sample_chain_probe(
    uint64_t target_kaddr, void* scratch, uint32_t size) {
    using namespace kernel_module;

    // Hop 1 - kernel request: allocate the staging buffer the chain will patch.
    uint64_t staging = 0;
    if (auto e = request_kernel_alloc_mem(size, staging); is_failed(e)) return static_cast<int>(to_num(e));

    // Hop 2 - memory permission: the target page must be writable before the patch.
    if (auto e = set_kernel_mem_protection(target_kaddr, size, KernMemProt::KMP_RW); is_failed(e))
        return static_cast<int>(to_num(e));

    // Hop 3 - write: the patch bytes land in kernel text (KMP_X) or data (KMP_RW).
    if (auto e = write_kernel_mem(target_kaddr, scratch, size, KernMemProt::KMP_X); is_failed(e))
        return static_cast<int>(to_num(e));

    // Hop 4 - cache synchronisation: make the written instructions visible on
    // every CPU before anything jumps to them.
    if (auto e = icache_invalidate_all_cpus(); is_failed(e)) return static_cast<int>(to_num(e));

    // Hop 5 - publication: install the branch and hand the hook record out.
    static const uint8_t kBranch[4] = {0x00, 0x00, 0x00, 0x14};
    HookContext* hook = nullptr;
    if (auto e = install_kfunc_before_hook_with_buf(target_kaddr, kBranch, sizeof(kBranch), &hook);
        is_failed(e))
        return static_cast<int>(to_num(e));
    if (hook) (void)uninstall_kernel_hook(hook);

    // Read-back leg of the same chain, so ordinal 23's read entry is exercised too.
    if (auto e = request_kernel_read_mem(target_kaddr, scratch, size); is_failed(e))
        return static_cast<int>(to_num(e));

    (void)request_kernel_set_suid_sgid(0, 0);
    (void)request_kernel_write_mem(target_kaddr, scratch, size);
    return 0;
}
