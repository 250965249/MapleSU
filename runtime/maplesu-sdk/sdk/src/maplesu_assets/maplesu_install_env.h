// MapleSU install env implementation.
//
#pragma once

#include <string>

#include "maplesu_install_core.h"
#include "private_maple_runtime.h"

namespace maplesu::sdk {
namespace env {

inline const char* current_module_root_key() {
    return __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
}

inline std::string kernel_file_dir_name() {
    const char* key = current_module_root_key();
    if (key == nullptr) return {};
    return std::string(key).substr(0, core::kRootKeyDirChars);
}

// Kernel-owned files use the first 16 key characters without the system suffix.
inline std::string kernel_file_dir_path() {
    const std::string dir_name = kernel_file_dir_name();
    if (dir_name.empty()) return {};
    std::string out;
    out.reserve(core::kRootKeyDirChars + 8);
    out.append("/data/");
    out.append(dir_name);
    out.push_back('/');
    return out;
}

inline std::string kernel_file_path(const char* component, const char* subdir = nullptr) {
    std::string path = kernel_file_dir_path();
    if (path.empty() || component == nullptr) return {};
    if (subdir != nullptr) path.append(subdir).push_back('/');
    return path + component;
}

}  // namespace env
}  // namespace maplesu::sdk
