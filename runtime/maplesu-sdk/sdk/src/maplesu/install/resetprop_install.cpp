#include "kernel_module_kit_umbrella.h"
#include "../../maplesu_assets/maplesu_payload_assets.h"
#include "private_maple_runtime.h"
#include "executable_publish.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace maplesu::compat {
namespace {

using maplesu::sdk::kPayloadsReal;
using maplesu::sdk::kResetpropPayloadSize;
using maplesu::sdk::resetprop_file_data;

const char* current_root_key() {
    return __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
}

KModErr enable_install_root() {
    return default_modules::module_root::set_current_root(true);
}

}  // namespace
}  // namespace maplesu::compat

namespace maplesu::install {
namespace {

static_assert(sizeof(compat::resetprop_file_data) == compat::kResetpropPayloadSize ||
                  !compat::kPayloadsReal,
              "resetprop payload must match the selected asset size");

std::string get_kernel_file_dir_name() {
    return std::string(compat::current_root_key()).substr(0, FOLDER_HEAD_ROOT_KEY_LEN);
}

std::string get_system_file_dir_name() {
    std::string head = get_kernel_file_dir_name();
    return head + head[0];
}

KModErr resetprop() {
    const KModErr set_root_err = compat::enable_install_root();
    if (set_root_err != KModErr::OK) return set_root_err;

    char path_buf[1024] = {0};
    snprintf(path_buf, sizeof(path_buf), "/data/%s/", get_system_file_dir_name().c_str());

    const std::string target_path =
        std::filesystem::path(std::string(path_buf)) / std::filesystem::path("resetprop");

    const KModErr publish_result =
        maplesu_publish_executable(target_path.c_str(), compat::resetprop_file_data,
                                   sizeof(compat::resetprop_file_data), "u:object_r:system_file:s0");
    if (publish_result != KModErr::OK) return publish_result;

    if (chmod(target_path.c_str(), 0777) != 0) return KModErr::ERR_SET_FILE_SELINUX;
    if (setxattr(target_path.c_str(), "security.selinux", "u:object_r:system_file:s0", 26, 0) != 0)
        return KModErr::ERR_SET_FILE_SELINUX;
    return KModErr::OK;
}

}  // namespace
}  // namespace maplesu::install

namespace maplesu::sdk {

KModErr unsafe_install_resetprop() {
    return maplesu::install::resetprop();
}

}  // namespace maplesu::sdk

#include "../compat/install_resetprop_exports_legacy_abi.h"
