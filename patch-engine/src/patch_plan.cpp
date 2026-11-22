#include "patch_plan.h"
#include <algorithm>
#include <stdexcept>

namespace maplesu {
std::vector<char> apply_plan_for_validation(const std::vector<char>& input, const PatchPlan& plan) {
    if (plan.edits.empty()) throw std::runtime_error("PATCH_PLAN_EMPTY");
    size_t previous_end = 64;
    for (const auto& edit : plan.edits) {
        if (edit.offset < previous_end || edit.expected.empty() || edit.expected.size() != edit.replacement.size() ||
            edit.offset > input.size() || edit.expected.size() > input.size() - edit.offset)
            throw std::runtime_error("PATCH_WRITE_RANGE_INVALID");
        if (!std::equal(edit.expected.begin(), edit.expected.end(), input.begin() + edit.offset,
                        [](uint8_t a, char b) { return a == static_cast<uint8_t>(b); }))
            throw std::runtime_error("PATCH_PREIMAGE_CHANGED");
        previous_end = edit.offset + edit.expected.size();
    }
    auto output = input;
    for (const auto& edit : plan.edits)
        std::copy(edit.replacement.begin(), edit.replacement.end(), output.begin() + edit.offset);
    return output;
}

std::vector<char> apply_plan_with_credential(const std::vector<char>& input, const PatchPlan& plan,
                                            const std::vector<uint8_t>& credential) {
    if (ROOT_KEY_LEN != 48 || credential.size() != ROOT_KEY_LEN ||
        !std::all_of(credential.begin(), credential.end(), [](uint8_t c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        })) throw std::runtime_error("PATCH_CREDENTIAL_INVALID");
    size_t owners = 0;
    for (const auto& edit : plan.edits) {
        if (plan.credential_slot >= edit.offset &&
            plan.credential_slot - edit.offset <= edit.replacement.size() &&
            ROOT_KEY_LEN <= edit.replacement.size() - (plan.credential_slot - edit.offset)) {
            const auto begin = edit.replacement.begin() + plan.credential_slot - edit.offset;
            if (!std::all_of(begin, begin + ROOT_KEY_LEN, [](uint8_t c) { return c == 0; }))
                throw std::runtime_error("PATCH_CREDENTIAL_SLOT_INVALID");
            ++owners;
        }
    }
    if (owners != 1) throw std::runtime_error("PATCH_CREDENTIAL_SLOT_INVALID");
    auto output = apply_plan_for_validation(input, plan);
    if (plan.credential_slot > output.size() || ROOT_KEY_LEN > output.size() - plan.credential_slot)
        throw std::runtime_error("PATCH_CREDENTIAL_SLOT_INVALID");
    std::copy(credential.begin(), credential.end() - 1, output.begin() + plan.credential_slot);
    output[plan.credential_slot + ROOT_KEY_LEN - 1] = 0;
    return output;
}

PatchPlan make_patch_plan(const std::vector<char>& input, KernelSymbolOffset symbols) {
    const auto require_region = [&](const SymbolRegion& region) {
        if (!region.valid() || region.offset % 4 || region.size % 4 || region.offset > input.size() ||
            region.size > input.size() - region.offset)
            throw std::runtime_error("PATCH_SYMBOL_RANGE_INVALID");
    };
    for (const auto& region : {symbols.avc_denied, symbols.audit_log_start, symbols.filldir64,
                              symbols.compat_filldir, symbols.sys_getuid, symbols.prctl_get_seccomp})
        require_region(region);
    for (const auto& region : {symbols.__do_execve_file, symbols.do_execveat_common, symbols.do_execve_common,
                              symbols.do_execveat, symbols.do_execve, symbols.die, symbols.__drm_puts_coredump,
                              symbols.__drm_printfn_coredump, symbols.__cfi_check, symbols.kti_randomize_init}) {
        if (region.offset) require_region(region);
    }
    PatchKernelOffset offsets;
    if (!parser_cred_offset(input, symbols.sys_getuid, offsets.cred_offset) ||
        !parse_cred_uid_offset(input, symbols.sys_getuid, offsets.cred_offset, offsets.cred_uid_offset) ||
        !parser_seccomp_offset(input, symbols.prctl_get_seccomp, offsets.seccomp_offset))
        throw std::runtime_error("PATCH_STRUCTURE_UNRESOLVED");
    parser_huawei_kti_addr(input, symbols.kti_randomize_init, offsets.huawei_kti_addr);
    std::vector<patch_bytes_data> generated;
    cfi_bypass(input, symbols, generated);
    huawei_bypass(input, symbols, generated);
    const auto result = patch_kernel_handler(input, offsets, symbols, generated);
    if (!result.patched || !result.root_key_start || generated.empty())
        throw std::runtime_error("PATCH_GENERATION_FAILED");
    PatchPlan plan{{}, result.root_key_start};
    for (const auto& change : generated) {
        const size_t size = change.str_bytes.size() / 2;
        if (change.str_bytes.empty() || change.str_bytes.size() % 2 || !change.write_addr ||
            change.write_addr > input.size() || size > input.size() - change.write_addr)
            throw std::runtime_error("PATCH_WRITE_RANGE_INVALID");
        PatchEdit edit{change.write_addr, {}, {}};
        edit.expected.assign(input.begin() + change.write_addr, input.begin() + change.write_addr + size);
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::runtime_error("PATCH_ENCODING_INVALID");
        };
        for (size_t i = 0; i < change.str_bytes.size(); i += 2)
            edit.replacement.push_back((nibble(change.str_bytes[i]) << 4) | nibble(change.str_bytes[i + 1]));
        plan.edits.push_back(std::move(edit));
    }
    std::sort(plan.edits.begin(), plan.edits.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });
    size_t previous_end = 64;
    bool slot_found = false;
    for (const auto& edit : plan.edits) {
        if (edit.offset < previous_end) throw std::runtime_error("PATCH_WRITES_OVERLAP");
        previous_end = edit.offset + edit.replacement.size();
        if (plan.credential_slot >= edit.offset && plan.credential_slot <= previous_end &&
            ROOT_KEY_LEN <= previous_end - plan.credential_slot) {
            const auto begin = edit.replacement.begin() + plan.credential_slot - edit.offset;
            slot_found = std::all_of(begin, begin + ROOT_KEY_LEN, [](uint8_t c) { return c == 0; });
        }
    }
    if (!slot_found) throw std::runtime_error("PATCH_CREDENTIAL_SLOT_INVALID");
    return plan;
}
}
