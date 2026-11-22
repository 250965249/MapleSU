// MapleSU unsafe resetprop install implementation.
//
#include "kernel_module_kit_umbrella.h"
#include "maplesu_payload_assets.h"
#include "private_maple_runtime.h"
#include "installer_ir/executable_publish.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace maplesu::sdk {
namespace {

static_assert(sizeof(resetprop_file_data) == kResetpropPayloadSize || !kPayloadsReal,
              "resetprop_file_data must be exactly the payload size pinned in ASSETS.json");

// First 16 characters of the current root key.
std::string get_kernel_file_dir_name() {
    return std::string(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW())
        .substr(0, FOLDER_HEAD_ROOT_KEY_LEN);
}

// Directory name used for runtime-owned files: the root key head plus its first
// character.
std::string get_system_file_dir_name() {
    std::string head = get_kernel_file_dir_name();
    return head + head[0];
}

}  // namespace

// Publishes the resetprop payload under /data/<dir name>/ and tags it so the
// kernel side can execute it.
KModErr unsafe_install_resetprop() {
    const KModErr set_root_err = default_modules::module_root::set_current_root(true);
    if (set_root_err != KModErr::OK) return set_root_err;

    char path_buf[1024] = {0};
    snprintf(path_buf, sizeof(path_buf), "/data/%s/", get_system_file_dir_name().c_str());

    const std::string target_path =
        std::filesystem::path(std::string(path_buf)) / std::filesystem::path("resetprop");

    const KModErr publish_result =
        maplesu_publish_executable(target_path.c_str(), resetprop_file_data,
                                   sizeof(resetprop_file_data), "u:object_r:system_file:s0");
    if (publish_result != KModErr::OK) return publish_result;

    if (chmod(target_path.c_str(), 0777) != 0) return KModErr::ERR_SET_FILE_SELINUX;
    if (setxattr(target_path.c_str(), "security.selinux", "u:object_r:system_file:s0", 26, 0) != 0)
        return KModErr::ERR_SET_FILE_SELINUX;
    return KModErr::OK;
}

}  // namespace maplesu::sdk
