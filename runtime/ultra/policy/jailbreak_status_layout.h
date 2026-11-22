#pragma once
#include "../../../jailbreak-providers/root-loader/selinux_hide_abi.h"
#include <cstdint>
#include <vector>

namespace maplesu::module_policy {
// Resolve from this boot's BTF, then validate the exact native ABI before use.
msu_selinux_layout resolve_jailbreak_status_layout(const std::vector<uint8_t>& btf,
                                                  uint32_t page_bytes);
msu_selinux_layout resolve_jailbreak_status_anchors(const msu_selinux_anchors& anchors,
                                                   uint32_t page_bytes);
}
