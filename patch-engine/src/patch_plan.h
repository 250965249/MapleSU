#pragma once
#include "maplesu_driver.h"
#include <cstdint>
#include <vector>

namespace maplesu {
struct PatchEdit {
    size_t offset;
    std::vector<uint8_t> expected;
    std::vector<uint8_t> replacement;
};
struct PatchPlan {
    std::vector<PatchEdit> edits;
    size_t credential_slot;
};
// Does not generate credentials, write files or approve a flashable candidate.
PatchPlan make_patch_plan(const std::vector<char>& input, KernelSymbolOffset symbols);
std::vector<char> apply_plan_for_validation(const std::vector<char>& input, const PatchPlan& plan);
// The runtime consumes 48 ASCII characters and removes the final character;
// the kernel slot therefore holds the first 47 characters followed by NUL.
std::vector<char> apply_plan_with_credential(const std::vector<char>& input, const PatchPlan& plan,
                                            const std::vector<uint8_t>& credential);
}
