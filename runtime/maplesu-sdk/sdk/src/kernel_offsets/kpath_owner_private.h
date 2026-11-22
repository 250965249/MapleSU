// Shared path ownership. Include after the existing probe execution helpers.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace {

struct kpath {
    uint64_t mnt;
    uint64_t dentry;
};

[[maybe_unused]] static KModErr release_kpath_page(uint64_t page, bool owns_path) noexcept {
    KModErr put_error = KModErr::OK;
    const char* put_stage = "setup/transport";
    if (owns_path) {
        try {
            put_error = exec_kernel_shellcode_no_result([page](asmjit::a64::Assembler* a) -> KModErr {
                KModErr error = KModErr::ERR_MODULE_PARAM;
                kernel_module::export_symbol::path_put(a, error, page);
                return error;
            });
        } catch (...) {
            put_error = KModErr::ERR_MODULE_ASM;
            put_stage = "exception";
        }
        if (is_failed(put_error)) {
            std::fprintf(stderr, "MapleSU path cleanup: path_put %s status=%lld\n",
                         put_stage, static_cast<long long>(put_error));
        }
    }
    KModErr free_error = KModErr::OK;
    try {
        free_error = kernel_module::free_kernel_mem(page);
    } catch (...) {
        free_error = KModErr::ERR_MODULE_ALLOC_MEM;
    }
    if (is_failed(free_error)) {
        std::fprintf(stderr, "MapleSU path cleanup: free_kernel_mem status=%lld\n",
                     static_cast<long long>(free_error));
    }
    return is_failed(put_error) ? put_error : free_error;
}

struct scoped_kpath {
    kpath kp{};
    uint64_t kaddr = 0;

    scoped_kpath() = default;
    scoped_kpath(const scoped_kpath&) = delete;
    scoped_kpath& operator=(const scoped_kpath&) = delete;

    KModErr reset() noexcept {
        const uint64_t page = kaddr;
        kaddr = 0;
        kp = kpath{};
        return page ? release_kpath_page(page, true) : KModErr::OK;
    }

    ~scoped_kpath() { (void)reset(); }
};

static_assert(sizeof(kpath) == 16, "kernel struct path is two arm64 pointers");
static_assert(offsetof(scoped_kpath, kaddr) == 16, "path owner field layout");
static_assert(sizeof(scoped_kpath) == 24, "path owner stays 24 bytes");

[[maybe_unused]] static KModErr acquire_kpath(const std::string& path, scoped_kpath& output) {
    uint64_t page = 0;
    const uint32_t page_size = kernel_module::get_page_size();
    KModErr error = kernel_module::alloc_kernel_mem(page_size, page);
    if (is_failed(error)) return error;
    struct StagingOwner {
        uint64_t page;
        ~StagingOwner() { if (page) (void)release_kpath_page(page, false); }
    } staging{page};

    error = kernel_module::fill00_kernel_mem(page, page_size, kernel_module::KernMemProt::KMP_RW);
    if (is_failed(error)) return error;

    uint64_t result = 0;
    error = get_kernel_shellcode_u64_result(
        [&path, page](asmjit::a64::Assembler* a, asmjit::a64::GpX& return_reg) -> KModErr {
            KModErr emit_error = KModErr::ERR_MODULE_PARAM;
            aarch64_asm_set_x_cstr_ptr(a, asmjit::a64::regs::x10, path);
            kernel_module::export_symbol::kern_path(a, emit_error, asmjit::a64::regs::x10,
                kernel_module::export_symbol::LookupFlags::LOOKUP_FOLLOW, page);
            if (is_ok(emit_error)) return_reg = asmjit::a64::regs::x0;
            return emit_error;
        }, result);
    if (is_failed(error)) {
        std::fprintf(stderr, "MapleSU path: kern_path setup/transport status=%lld\n",
                     static_cast<long long>(error));
        return error;
    }
    const int32_t runtime_status = static_cast<int32_t>(static_cast<uint32_t>(result));
    if (runtime_status != 0) {
        std::fprintf(stderr, "MapleSU path: kern_path runtime status=%d\n", runtime_status);
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    scoped_kpath candidate;
    candidate.kaddr = page;
    staging.page = 0;
    error = kernel_module::read_kernel_mem(page, &candidate.kp, sizeof(candidate.kp));
    if (is_failed(error)) return error;

    error = output.reset();
    if (is_failed(error)) return error;
    output.kp = candidate.kp;
    output.kaddr = candidate.kaddr;
    candidate.kaddr = 0;
    candidate.kp = kpath{};
    return KModErr::OK;
}

}  // namespace
