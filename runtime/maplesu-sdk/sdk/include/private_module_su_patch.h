// One synchronous SU Hook group; no public class or HookContext layout changes.
#pragma once
#include "module_base_kernel_func_hook.h"
#include <cstdio>
#include <vector>
namespace default_modules::module_su_redirect {
struct SuPatchBatch {
    uint64_t entries[13] = {};
    std::vector<uint8_t> payloads[13];
    uint32_t count = 0;
    bool readers_retired = true;
};
KModErr begin_su_patch_batch(SuPatchBatch& batch);
KModErr end_su_patch_batch(SuPatchBatch& batch, bool commit);
class SuPatchBatchGuard {
public:
    KModErr begin() {
        const auto error = begin_su_patch_batch(batch_);
        active_ = is_ok(error);
        return error;
    }
    KModErr finish(KModErr primary) {
        if (!active_) return primary;
        active_ = false;
        const auto cleanup = end_su_patch_batch(batch_, is_ok(primary));
        if (is_failed(primary) && is_failed(cleanup))
            std::printf("SU Hook rollback: %s\n", to_string(cleanup).c_str());
        return is_failed(primary) ? primary : cleanup;
    }
    bool readers_retired() const noexcept { return batch_.readers_retired; }
    ~SuPatchBatchGuard() { if (active_) (void)end_su_patch_batch(batch_, false); }
    SuPatchBatchGuard() = default;
    SuPatchBatchGuard(const SuPatchBatchGuard&) = delete;
    SuPatchBatchGuard& operator=(const SuPatchBatchGuard&) = delete;
private:
    SuPatchBatch batch_{};
    bool active_ = false;
};
} // namespace default_modules::module_su_redirect
