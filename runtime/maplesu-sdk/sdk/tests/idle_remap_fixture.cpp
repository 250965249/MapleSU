#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <functional>
#include <map>
#include <new>
#include <string>
#include <vector>
#include "module_err_def.h"

namespace asmjit { namespace a64 {
struct GpX {};
struct Assembler {};
inline GpX x0, x10, x11, x12, x13, x14;
}}
namespace asmjit { using Assembler = a64::Assembler; }
using namespace asmjit::a64;
struct State {
    int step = 0, fail_step = 0, applies = 0, fail_apply = 0;
    uint64_t next = 0x10000, trampoline = 0;
    bool alias = false, throw_build = false;
    bool unwinding = false;
    int throw_cleanup = 0, cleanup_throws = 0;
    std::map<uint64_t, uint32_t> live;
    std::vector<std::string> operations;
} state;
static KModErr operation(const char* name) {
    state.operations.emplace_back(name);
    if (state.unwinding && ((state.throw_cleanup == 1 && !std::strcmp(name, "free")) ||
            (state.throw_cleanup == 2 && !std::strcmp(name, "protect")))) {
        ++state.cleanup_throws;
        throw std::bad_alloc();
    }
    return ++state.step == state.fail_step ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK;
}
namespace kernel_module {
enum class KernMemProt { KMP_RW, KMP_X };
class CleanupReceiptScope {};
static KModErr kallsyms_lookup_name(const char*, uint64_t& out) {
    out = 0x1000; return operation("lookup");
}
static KModErr alloc_kernel_mem(uint32_t size, uint64_t& out) {
    auto error = operation("alloc"); if (error != KModErr::OK) return error;
    out = state.next; state.next += 0x10000; state.live[out] = size;
    if (!state.trampoline) state.trampoline = out;
    return KModErr::OK;
}
static KModErr free_kernel_mem(uint64_t addr) {
    auto error = operation("free"); if (error == KModErr::OK) state.live.erase(addr); return error;
}
static KModErr set_kernel_mem_protection(uint64_t, uint64_t, KernMemProt) { return operation("protect"); }
static KModErr write_kernel_mem(uint64_t, const void*, uint32_t, KernMemProt) { return operation("write"); }
static KModErr get_pte_fn_t_kcfi_hash(uint32_t& out) { out = 1; return operation("kcfi"); }
namespace export_symbol {
static void apply_to_page_range(Assembler*, KModErr& error, GpX, GpX, GpX, GpX, GpX) {
    error = KModErr::OK;
}
}}
static const char* kInitMmSymbol = "init_mm";
static const char* kApplyToPageRange1ErrFmt = "save failed %ld\n";
static const char* kApplyToPageRange2ErrFmt = "alias failed %ld\n";
static void aarch64_asm_mov_x(Assembler*, GpX, uint64_t) {}
static std::vector<uint8_t> make_pte_fn_save_shellcode(uint32_t) {
    if (state.throw_build) { state.unwinding = true; throw std::bad_alloc(); }
    return {1,2,3,4};
}
static std::vector<uint8_t> make_pte_fn_restore_shellcode(uint32_t) { return {1,2,3,4}; }
struct aarch64_asm_ctx { Assembler storage; Assembler* assembler() { return &storage; } };
static aarch64_asm_ctx init_aarch64_asm() { return {}; }
static void aarch64_asm_dsb_ishst(Assembler*) {}
static void aarch64_asm_tlbi_vmalle1is(Assembler*) {}
static void aarch64_asm_dsb_ish(Assembler*) {}
static void aarch64_asm_isb(Assembler*) {}
static std::vector<uint8_t> aarch64_asm_to_bytes(Assembler*) { return {1,2,3,4}; }
namespace kernel_module {
static void arm64_module_asm_func_start(Assembler*) {}
static void arm64_module_asm_func_end(Assembler*) {}
static KModErr execute_kernel_asm_func(const std::vector<uint8_t>&, uint64_t&) {
    return operation("flush");
}
}
static KModErr get_kernel_shellcode_u64_result(std::function<KModErr(Assembler*, GpX&)> emit, uint64_t& result) {
    Assembler assembler; GpX reg;
    const auto error = emit(&assembler, reg);
    if (error != KModErr::OK) return error;
    ++state.applies;
    // apply_to_page_range may update a prefix before returning an error.
    if (state.applies == 2) state.alias = true;
    const auto transport = operation("apply");
    result = state.applies == state.fail_apply ? static_cast<uint64_t>(-5) : 0;
    return transport;
}

// EXACT_REMAP_FUNCTION

int main(int argc, char** argv) {
    std::set_terminate([] { std::_Exit(86); });
    if (argc == 2) {
        state = {};
        state.throw_build = true;
        state.throw_cleanup = !std::strcmp(argv[1], "--free-unwind") ? 1 : 2;
        uint64_t end = 0;
        bool original_caught = false;
        try { (void)remap_kernel_exec_range(0x200000, 65536, end); }
        catch (const std::bad_alloc&) { original_caught = true; }
        const int expected_throws = state.throw_cleanup == 1 ? 3 : 1;
        const size_t expected_live = state.throw_cleanup == 1 ? 3 : 1;
        const bool ok = original_caught && state.cleanup_throws == expected_throws &&
            state.live.size() == expected_live;
        std::printf("idle-remap unwind=%s original=%d attempts=%d live=%zu passed=%d\n",
            argv[1], original_caught, state.cleanup_throws, state.live.size(), ok);
        return ok ? 0 : 1;
    }
    int failed = 0, cases = 0;
    uint64_t end = 0;
    state = {};
    const auto success = remap_kernel_exec_range(0x200000, 65536, end);
    const int steps = state.step;
    if (success != KModErr::OK || state.live.size() != 1 || !state.live.count(state.trampoline)) {
        std::printf("FAIL success path retains only aliased trampoline\n"); ++failed;
    }
    ++cases;
    for (int fault = 1; fault <= steps; ++fault) {
        state = {}; state.fail_step = fault;
        const auto error = remap_kernel_exec_range(0x200000, 65536, end);
        // The one failing free/protection may retain its allocation. Earlier failures must reclaim all other allocations.
        const auto failed_op = state.operations.at(fault - 1);
        const size_t expected_max = state.alias ? 1 : 0;
        const bool cleanup_failure = failed_op == "free" || (state.alias && failed_op == "protect");
        if (error == KModErr::OK || state.live.size() > expected_max + (cleanup_failure ? 1 : 0) ||
            (state.alias && !state.live.count(state.trampoline))) {
            std::printf("FAIL step=%d op=%s live=%zu alias=%d error=%d\n", fault, failed_op.c_str(), state.live.size(), state.alias, static_cast<int>(error));
            ++failed;
        }
        ++cases;
    }
    for (int apply = 1; apply <= 2; ++apply) {
        state = {}; state.fail_apply = apply;
        const auto error = remap_kernel_exec_range(0x200000, 65536, end);
        if (error != KModErr::ERR_MODULE_IDLE_MEM_REMAP || state.live.size() != (state.alias ? 1 : 0) ||
            (state.alias && !state.live.count(state.trampoline))) {
            std::printf("FAIL apply=%d live=%zu alias=%d\n", apply, state.live.size(), state.alias); ++failed;
        }
        ++cases;
    }
    state = {}; state.throw_build = true;
    bool caught = false;
    try { (void)remap_kernel_exec_range(0x200000, 65536, end); }
    catch (const std::bad_alloc&) { caught = true; }
    if (!caught || !state.live.empty()) {
        std::printf("FAIL assembler allocation exception live=%zu\n", state.live.size()); ++failed;
    }
    ++cases;
    std::printf("idle-remap cases=%d failed=%d\n", cases, failed);
    return failed ? 1 : 0;
}
