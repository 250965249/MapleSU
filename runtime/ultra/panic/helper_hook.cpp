#include <atomic>
#include <cstdint>
#include <new>
#include <cstddef>
#include "module_err_def.h"

struct HookContext {
    uint64_t entry;
    uint32_t original;
    uint64_t trampoline;
    uint64_t size;
    uint8_t enabled;
    uint64_t disable_flag;
};
static_assert(sizeof(HookContext) == 48);
static_assert(offsetof(HookContext, disable_flag) == 40);
extern "C" int64_t original_read_kernel_mem(uint64_t, void*, uint32_t);
extern "C" int64_t original_write_kernel_mem(uint64_t, const void*, uint32_t, uint8_t);

namespace {
constexpr int64_t AsmError = to_num(KModErr::ERR_MODULE_ASM);
constexpr int64_t ParamError = to_num(KModErr::ERR_MODULE_PARAM);
constexpr int64_t NoMemory = to_num(KModErr::ERR_NO_MEM);
constexpr int64_t Duplicate = to_num(KModErr::ERR_MODULE_DUPLICATE);
constexpr int64_t MustUninstall = to_num(KModErr::ERR_MODULE_MUST_UNINSTALL);
std::atomic_flag publishing = ATOMIC_FLAG_INIT;
std::atomic<bool> pending{false};
HookContext pending_record{};
struct PublicationGuard {
    ~PublicationGuard() { publishing.clear(std::memory_order_release); }
};
}
extern "C" int maplesu_helper_pending_hook(HookContext* out) noexcept {
    if (!out || !pending.load(std::memory_order_acquire)) return 0;
    *out = pending_record;
    return 1;
}
extern "C" int64_t maplesu_helper_publish_hook(
    uint64_t entry, const uint32_t* branch, uint32_t original, uint64_t trampoline,
    uint64_t size, uint64_t flag, HookContext** output) noexcept {
    if (output) *output = nullptr;
    if (!branch || !flag) return ParamError;
    if (publishing.test_and_set(std::memory_order_acquire)) return Duplicate;
    PublicationGuard release;
    if (pending.load(std::memory_order_acquire)) return MustUninstall;
    HookContext* context;
    try { context = new HookContext{entry, original, trampoline, size, 0, flag}; }
    catch (...) { return NoMemory; }
    bool attempted = false;
    int64_t failure = AsmError;
    try {
        uint32_t before = 0;
        failure = original_read_kernel_mem(entry, &before, sizeof(before));
        if (failure != 0) { delete context; return failure; }
        if (before != original) { delete context; return Duplicate; }
        const uint8_t bypass = 1;
        failure = original_write_kernel_mem(flag, &bypass, sizeof(bypass), 1);
        if (failure != 0) { delete context; return failure; }
        attempted = true;
        failure = original_write_kernel_mem(entry, branch, sizeof(*branch), 2);
        if (failure == 0) {
            uint32_t after = 0;
            failure = original_read_kernel_mem(entry, &after, sizeof(after));
            if (failure == 0 && after != *branch) failure = AsmError;
        }
        if (failure == 0) {
            const uint8_t activate = 0;
            failure = original_write_kernel_mem(flag, &activate, sizeof(activate), 1);
        }
        if (failure == 0) {
            context->enabled = 1;
            if (output) *output = context; else delete context;
            return 0;
        }
    } catch (...) { failure = AsmError; }
    if (!attempted) { delete context; return failure; }
    // Published kernel allocations remain live even when rollback succeeds.
    bool disabled = false, restored = false;
    try {
        const uint8_t bypass = 1;
        disabled = original_write_kernel_mem(flag, &bypass, sizeof(bypass), 1) == 0;
    } catch (...) {}
    try {
        const auto rollback = original_write_kernel_mem(entry, &original, sizeof(original), 2);
        uint32_t observed = 0;
        const auto readback = original_read_kernel_mem(entry, &observed, sizeof(observed));
        restored = rollback == 0 && readback == 0 && observed == original;
    } catch (...) {}
    if (restored) { delete context; return failure; }
    context->enabled = disabled ? 0 : 1;
    pending_record = *context;
    pending.store(true, std::memory_order_release);
    if (output) *output = context; else delete context;
    return MustUninstall;
}
