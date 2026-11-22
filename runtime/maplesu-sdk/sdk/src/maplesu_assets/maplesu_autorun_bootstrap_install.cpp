// MapleSU autorun bootstrap install implementation.
//
#include "maplesu/compat/persisted_inputs.h"
#include "kernel_module_kit_umbrella.h"

#include "maplesu_payload_assets.h"   // maplesu::sdk::autorun_bootstrap_file_data
#include "maplesu_install_core.h"
#include "maplesu_install_env.h"
#include "maplesu_install_platform.h"
#include "maplesu_sdk/maplesu_installer.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <new>
#include <string>

namespace maplesu::sdk {
namespace {

using core::err_t;

const char autorun_bootstrap_static_inline_root_key[core::kFeatureTokenSize] =
    "5d31494d2e18e3fdef2afaf740b0febc19229cb292f57ebc3bc1c96c6d70b709"
    "8d2dc1f356b733e8c999e6ac85bdca24c8c74f03ae7d5b2a402e96804576e925";

static_assert(sizeof(autorun_bootstrap_file_data) == kAutorunBootstrapPayloadSize || !kPayloadsReal,
              "autorun_bootstrap_file_data must be the payload size pinned in ASSETS.json");

std::string get_autorun_bootstrap_path() { return env::kernel_file_path("init"); }

err_t publish_bootstrap(const std::string& path, const char* key) {
    std::unique_ptr<char[]> payload(new (std::nothrow) char[sizeof(autorun_bootstrap_file_data)]);
    if (!payload) return core::kErrPayloadAlloc;
    memcpy(payload.get(), autorun_bootstrap_file_data, sizeof(autorun_bootstrap_file_data));
    std::unique_ptr<char[]> replacement(new (std::nothrow) char[core::kFeatureTokenSize]);
    if (!replacement) return core::kErrTokenBufAlloc;
    memset(replacement.get(), 0, core::kFeatureTokenSize);
    const std::size_t copy_len = std::min<std::size_t>(core::kFeatureTokenSize - 1,
                                                    std::strlen(key) + 1);
    strncpy(replacement.get(), key, copy_len);
    bool found = false;
    if (sizeof(autorun_bootstrap_file_data) >= core::kFeatureTokenSize) {
        for (std::size_t i = 0; i <= sizeof(autorun_bootstrap_file_data) - core::kFeatureTokenSize;
             ++i) {
            if (memcmp(payload.get() + i, autorun_bootstrap_static_inline_root_key,
                       core::kFeatureTokenSize) == 0) {
                memcpy(payload.get() + i, replacement.get(), copy_len);
                found = true;
            }
        }
    }
    if (!found) return core::kErrTokenBufAlloc;
    return static_cast<err_t>(maplesu_publish_executable(
        path.c_str(), payload.get(), sizeof(autorun_bootstrap_file_data), core::kSelinuxKernel));
}

err_t reset_flag_file(const char* suffix) {
    const err_t set_root_err =
        static_cast<err_t>(default_modules::module_root::set_current_root(true));
    if (set_root_err != core::kOk) return set_root_err;

    const std::string base = get_autorun_bootstrap_path();
    if (base.empty()) return core::kErrModuleParam;
    const std::string flag_path = base + suffix;

    if (!platform::create_empty_file(flag_path.c_str())) return core::kErrCreateEmptyFile;  // -19935
    if (!platform::set_file_selinux_access_mode(flag_path.c_str(), core::kSelinuxKernel)) {
        return core::kErrSetSelinux;                                                     // -19915
    }
    return core::kOk;
}

}  // namespace

__attribute__((visibility("hidden"))) KModErr unsafe_reset_autorun_bootstrap_safe_flag() {
    return static_cast<KModErr>(reset_flag_file(".safe_flag"));
}

__attribute__((visibility("hidden"))) KModErr unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag() {
    return static_cast<KModErr>(reset_flag_file(".boot_session.duplicate"));
}

__attribute__((visibility("hidden"))) KModErr unsafe_install_autorun_bootstrap() {
    const KModErr set_root_err = default_modules::module_root::set_current_root(true);
    if (set_root_err != KModErr::OK) return set_root_err;

    const std::string path = get_autorun_bootstrap_path();
    if (path.empty()) return static_cast<KModErr>(core::kErrModuleParam);

    const char* key = env::current_module_root_key();
    if (key == nullptr || key[0] == '\0') return static_cast<KModErr>(core::kErrModuleParam);

    const err_t publish_err = publish_bootstrap(path, key);
    if (publish_err != core::kOk) return static_cast<KModErr>(publish_err);
    if (!platform::set_file_selinux_access_mode(path.c_str(), core::kSelinuxKernel))
        return KModErr::ERR_SET_FILE_SELINUX;

    const std::string state_files[] = {path + ".running.lock", path + ".boot_session.work",
                                      path + ".log", path + ".log.last", path + ".log.crash",
                                      env::kernel_file_path(maplesu::compat::kEnvironmentVersionFile)};
    for (unsigned i = 0; i < 5; ++i) {
        if (!platform::create_empty_file(state_files[i].c_str()))
            return static_cast<KModErr>(core::kErrCreateEmptyFile);
    }
    const MapleSUSdkVersion version = get_sdk_version();
    const std::string version_text = std::to_string(version.major) + "." +
                                     std::to_string(version.minor) + "." +
                                     std::to_string(version.patch);
    if (!platform::write_file_direct(state_files[5].c_str(),
                                     reinterpret_cast<const unsigned char*>(version_text.data()),
                                     version_text.size()))
        return static_cast<KModErr>(core::kErrWriteFile);
    constexpr char initial_log[] = "[FATAL] autorun_bootstrap: NEVER EXECUTED";
    if (!platform::write_file_direct(state_files[2].c_str(),
                                     reinterpret_cast<const unsigned char*>(initial_log),
                                     sizeof(initial_log) - 1))
        return static_cast<KModErr>(core::kErrWriteFile);
    for (const std::string& file : state_files) {
        if (!platform::set_file_selinux_access_mode(file.c_str(), core::kSelinuxKernel))
            return KModErr::ERR_SET_FILE_SELINUX;
    }
    const KModErr duplicate_err = unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag();
    if (duplicate_err != KModErr::OK) return duplicate_err;
    return unsafe_reset_autorun_bootstrap_safe_flag();
}

}  // namespace maplesu::sdk

//     mov x8, x0 ; b maplesu::sdk::get_autorun_bootstrap_path()
// i.e. a C-linkage alias of the internal path getter, returning std::string
// through the sret pointer.  Kept for ABI compatibility with the kit that calls
// it to locate the installed helper.
extern "C" __attribute__((visibility("hidden")))
void maplesu_installed_helper_path(std::string* out) {
    if (out == nullptr) return;
    *out = maplesu::sdk::env::kernel_file_path("init");
}
