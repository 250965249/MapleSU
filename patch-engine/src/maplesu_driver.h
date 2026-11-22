#pragma once
#include "patch_kernel_root.h"
#include "analyze/symbol_analyze.h"

// Types and entry points extracted from the official standalone main translation unit.
struct PatchKernelOffset {
    size_t cred_offset = 0;
    size_t cred_uid_offset = 0;
    size_t seccomp_offset = 0;
    uint64_t huawei_kti_addr = 0;
};
struct PatchKernelResult {
    bool patched = false;
    size_t root_key_start = 0;
};
bool parser_cred_offset(const std::vector<char>&, const SymbolRegion&, size_t&);
bool parse_cred_uid_offset(const std::vector<char>&, const SymbolRegion&, size_t, size_t&);
bool parser_seccomp_offset(const std::vector<char>&, const SymbolRegion&, size_t&);
bool parser_huawei_kti_addr(const std::vector<char>&, const SymbolRegion&, uint64_t&);
void cfi_bypass(const std::vector<char>&, KernelSymbolOffset&, std::vector<patch_bytes_data>&);
void huawei_bypass(const std::vector<char>&, KernelSymbolOffset&, std::vector<patch_bytes_data>&);
PatchKernelResult patch_kernel_handler(const std::vector<char>&, const PatchKernelOffset&,
                                      KernelSymbolOffset&, std::vector<patch_bytes_data>&);
