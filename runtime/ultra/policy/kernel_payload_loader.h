#pragma once
#include "kernel_layout.h"
#include "kernel_payload.h"
#include <array>
#include <string_view>

namespace maplesu::module_policy {
struct KernelNativeCodeAbi {
    std::string name;
    std::vector<std::array<uint8_t, 16>> entries;
};
struct KernelPolicyCompatibility {
    std::string kernel_series;
    std::vector<std::pair<std::string, std::string>> config;
    std::vector<std::vector<std::pair<std::string, std::string>>> equivalent_configs;
    std::vector<KernelFunctionAbi> functions;
    std::vector<KernelNativeCodeAbi> native_code;
    std::vector<std::string> declaration_configs = {};
};
struct KernelPolicyBundle {
    std::span<const uint8_t> image;
    std::string_view build_id;
    uint32_t page_size;
    bool dynamic_scs;
    const char* cache_function;
    std::array<std::array<uint8_t, 16>, 9> hook_code;
    std::vector<LayoutType> (*layout)();
    const char* scs_function = nullptr;
    uint8_t scs_arguments = 2;
    bool alternatives_returns_status = false;
    const KernelPolicyCompatibility* compatibility = nullptr;
    std::string_view kernel_series = {};
};
// Bind compiled field slots in the userspace image before its first kernel
// allocation. Returns false for legacy static payloads, which keep exact checks.
bool bind_policy_payload_layout(PolicyPayload& payload, const std::vector<LayoutType>& reference,
                                const std::vector<uint8_t>& btf,
                                const std::vector<KernelFunctionAbi>& functions = {});
// The only kernel boundary. The production adapter uses the existing SDK; tests
// inject failures at these same boundaries without touching a device.
struct PolicyKernelIo {
    virtual ~PolicyKernelIo() = default;
    // A transport may impose additional requirements on the selected payload.
    virtual void select_bundle(const KernelPolicyBundle&) {}
    // Persisted before mutations so a reboot retains the last attempted phase.
    virtual void progress(std::string_view) noexcept {}
    virtual uint64_t lookup(const char* name) = 0;
    virtual uint64_t allocate(uint32_t size) = 0;
    virtual void release(uint64_t address) = 0;
    virtual void read(uint64_t address, std::span<uint8_t> bytes) = 0;
    virtual void write(uint64_t address, std::span<const uint8_t> bytes) = 0;
    virtual uint64_t call(uint64_t function, std::span<const uint64_t> args) = 0;
    virtual std::vector<uint8_t> dispatch(unsigned operation, uint64_t predicate, uint64_t handler, uint64_t activation) = 0;
    virtual void activate(uint64_t address, bool enabled) = 0;
    virtual void hook(uint64_t address, const std::vector<uint8_t>& bytes) = 0;
    // Optional transport-owned rollback for staged or partial registrations.
    virtual void abort() {}
};
unsigned install_policy_view(const KernelPolicyBundle& bundle, std::string_view build_id,
                             uint32_t page_size, const std::vector<uint8_t>& btf, PolicyKernelIo& io,
                             std::string_view release = {}, std::string_view config = {}, bool allow_unverified = false);
// Verify image, layout, imports and entry bytes without allocations, writes or
// kernel execution. Live SCS state is checked by installation, not this probe.
void preflight_policy_view(const KernelPolicyBundle& bundle, std::string_view build_id,
                           uint32_t page_size, const std::vector<uint8_t>& btf, PolicyKernelIo& io,
                           std::string_view release = {}, std::string_view config = {}, bool allow_unverified = false);
std::span<const KernelPolicyBundle> kernel_policy_bundles();
unsigned prepare_policy_view_with(PolicyKernelIo& io, bool preflight_only, bool allow_unverified = false);
bool hidden_kernel_policy_supported();
unsigned preflight_hidden_kernel_policy();
unsigned prepare_hidden_kernel_policy(bool allow_unverified = false);
void cancel_hidden_kernel_policy();
std::vector<uint8_t> emit_policy_query_dispatch(unsigned operation, uint64_t predicate, uint64_t handler, uint64_t activation = 0);
}
