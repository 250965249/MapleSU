#pragma once
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <vector>

namespace maplesu::module_policy {
struct PayloadSegment {
    uint32_t offset, size, flags;
};
struct PayloadRelocation {
    uint32_t offset, type;
    uint64_t value;
    std::string symbol;
};
struct PolicyPayload {
    std::vector<uint8_t> image;
    std::vector<PayloadSegment> segments;
    std::vector<PayloadRelocation> relocations;
    std::map<std::string, uint32_t> exports;
    uint32_t alternatives = 0, alternative_bytes = 0, page_size = 0;
    uint32_t scs_frames = 0, scs_frame_bytes = 0;
    uint64_t base = 0;
};
std::string kernel_build_id(std::span<const uint8_t> notes);

// Strict parser for our build output, not a general-purpose ELF/dlopen loader.
// Both operations touch userspace buffers only; all imports must resolve first.
PolicyPayload parse_policy_payload(std::span<const uint8_t> bytes, uint32_t page_size);
// Prevalidate the native arm64 dynamic-SCS parser's supported EH-frame subset.
// Returns code offsets whose PACIASP/AUTIASP must be rewritten by the kernel.
std::vector<uint32_t> policy_scs_patch_sites(const PolicyPayload& payload);
void relocate_policy_payload(PolicyPayload& payload, uint64_t base,
                             const std::map<std::string, uint64_t>& imports);
}
