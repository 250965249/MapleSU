// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <array>
#include <sys/types.h>
#include "kernel_payload_loader.h"
#include "module_policy_config.h"
#include "../../../jailbreak-providers/root-loader/policy_hook_abi.h"

namespace maplesu::module_policy {
// Control fd is process-local; the sidecar retains no pointer into this object.
// It never emits SDK dispatch bytes or replays failed calls through another Root.
class HookKernelIo final : public PolicyKernelIo {
public:
    HookKernelIo();
    ~HookKernelIo() override;
    HookKernelIo(const HookKernelIo&) = delete;
    HookKernelIo& operator=(const HookKernelIo&) = delete;
    void select_bundle(const KernelPolicyBundle& bundle) override;
    void progress(std::string_view phase) noexcept override;
    uint64_t lookup(const char* name) override;
    uint64_t allocate(uint32_t size) override;
    void release(uint64_t address) override;
    void read(uint64_t address, std::span<uint8_t> bytes) override;
    void write(uint64_t address, std::span<const uint8_t> bytes) override;
    uint64_t call(uint64_t function, std::span<const uint64_t> args) override;
    std::vector<uint8_t> dispatch(unsigned operation, uint64_t predicate,
        uint64_t handler, uint64_t activation) override;
    void activate(uint64_t address, bool enabled) override;
    void hook(uint64_t address, const std::vector<uint8_t>& descriptor) override;
    msu_policy_hook_request query();
    // Resolve resident state after a controller exit; never allocate again.
    void resume(bool enabled);
    void abort() override;
    ssize_t write_policy(int fd, const void* bytes, size_t size);
private:
    int fd_ = -1;
    uint64_t handles_offset_ = 0, transition_offset_ = 0, transition_ = 0, fork_guard_offset_ = 0, image_base_ = 0;
    uint64_t predicate_ = 0;
    uint64_t prepare_offset_ = 0, activation_ = 0;
    uint64_t module_write_offset_ = 0, policyload_offset_ = 0, reload_offset_ = 0;
    std::array<msu_policy_hook_dispatch, MSU_POLICY_HOOK_COUNT> entries_{};
    msu_policy_hook_request transact(msu_policy_hook_request request);
};
bool hook_policy_backend_present();
unsigned prepare_hook_kernel_policy(Mode mode, bool allow_unverified);
// Validates only state published by this boot's temporary backend.
State observe_hook_policy_state(State state, bool hook_owned);
}
