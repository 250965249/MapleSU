// MapleSU unsafe webui loader install implementation.
//
// Publishes the module web UI loader below the runtime modules directory.
#include "kernel_module_kit_umbrella.h"

#include "maplesu_payload_assets.h"
#include "private_maple_runtime.h"
#include "installer_ir/executable_publish.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <new>
#include <string>
#include <string_view>

#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace maplesu::sdk {
namespace {

// Installer error codes (kit error space).
constexpr KModErr kOk = KModErr::OK;
constexpr KModErr kErrPayloadAlloc = static_cast<KModErr>(-19905);
constexpr KModErr kErrTokenMissing = static_cast<KModErr>(-19907);
constexpr KModErr kErrSetFileSelinux = KModErr::ERR_SET_FILE_SELINUX;

// Equal-length feature token embedded in the payload; at install time every
// occurrence is overwritten with the current root key.
const char static_inline_webui_loader_rootkey[4096] =
    "8ba9d457344d22b85d3e7f7263c3dd04d9effeb1becb41a806eaaa9926087fae"
    "49c43c1c3d64c98333e8017195c6ab7bfe7e72a99c4530b267705824e5d6e700";

constexpr char kSelinuxXattr[] = "security.selinux";
constexpr char kSelinuxSystemFile[] = "u:object_r:system_file:s0";
constexpr char kDataDirFormat[] = "/data/%s/";
constexpr unsigned long kDataDirBufSize = 1024;
constexpr unsigned long kRootKeyHeadLen = 16;
constexpr unsigned int kExecMode0777 = 0777;

// Replaces every in-place occurrence of the 4096-byte feature token with the
// NUL-padded root key.  The replacement never changes the payload length.
bool replace_feature_string_in_buf(const char* feature_string_buf,
                                   unsigned long feature_string_buf_size,
                                   std::string_view new_key, char* buf,
                                   unsigned long buf_size) {
    if (feature_string_buf_size == 0 || buf_size < feature_string_buf_size) return false;
    bool write = false;
    std::shared_ptr<char> sp_new_feature(
        new (std::nothrow) char[feature_string_buf_size], std::default_delete<char[]>());
    if (sp_new_feature) {
        memset(sp_new_feature.get(), 0, feature_string_buf_size);
        std::size_t copy_len = new_key.length() + 1;
        copy_len = std::min(static_cast<std::size_t>(feature_string_buf_size - 1), copy_len);
        strncpy(sp_new_feature.get(), new_key.data(), copy_len);

        for (std::size_t i = 0; i <= buf_size - feature_string_buf_size; i++) {
            char* desc = buf;
            desc += i;
            if (memcmp(desc, feature_string_buf, feature_string_buf_size) == 0) {
                memcpy(desc, sp_new_feature.get(), copy_len);
                write = true;
            }
        }
    }
    return write;
}

// First 16 characters of the current root key.
std::string get_kernel_file_dir_name() {
    const char* root_key = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    const std::string head = std::string(root_key).substr(0, kRootKeyHeadLen);
    return head + head[0];
}

// "/data/<dir>/modules/" -- the modules directory shared by the kit.
std::string get_module_file_dir_path() {
    char path_buf[kDataDirBufSize] = {0};
    snprintf(path_buf, sizeof(path_buf), kDataDirFormat, get_kernel_file_dir_name().c_str());
    return (std::filesystem::path(std::string(path_buf)) / "modules" /
            std::filesystem::path(""))
        .string();
}

// "/data/<dir>/modules/webui_loader" -- the installed loader program.
std::string get_webui_loader_path() {
    return (std::filesystem::path(get_module_file_dir_path()) / "webui_loader").string();
}

// Sets the executable mode and the system_file SELinux label the kernel side
// requires before it will run the program.
bool set_file_selinux_access_mode(const char* file_path) {
    if (chmod(file_path, kExecMode0777) != 0) {
        return false;
    }
    if (setxattr(file_path, kSelinuxXattr, kSelinuxSystemFile, sizeof(kSelinuxSystemFile), 0) !=
        0) {
        return false;
    }
    return true;
}

}  // namespace

// Writes the loader program, replaces its feature token with the root key and
// labels the result so the kernel side can execute it.
KModErr unsafe_install_webui_loader() {
    const KModErr set_root_err = default_modules::module_root::set_current_root(true);
    if (set_root_err != kOk) return set_root_err;

    const std::string target_path = get_webui_loader_path();
    const char* target = target_path.c_str();

    KModErr err = kOk;
    {
        std::shared_ptr<char> sp_loader_data(
            new (std::nothrow) char[sizeof(webui_loader_data)],
            std::default_delete<char[]>());
        if (!sp_loader_data) return kErrPayloadAlloc;
        memcpy(sp_loader_data.get(), webui_loader_data, sizeof(webui_loader_data));

        if (!replace_feature_string_in_buf(
                static_inline_webui_loader_rootkey, sizeof(static_inline_webui_loader_rootkey),
                __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(),
                sp_loader_data.get(), sizeof(webui_loader_data))) {
            return kErrTokenMissing;
        }

        err = maplesu_publish_executable(target, sp_loader_data.get(),
                                         sizeof(webui_loader_data), kSelinuxSystemFile);
    }

    if (err == kOk) {
        (void)::chmod(target_path.c_str(), kExecMode0777);
        if (!set_file_selinux_access_mode(target_path.c_str())) {
            err = kErrSetFileSelinux;
        }
    }
    return err;
}

}  // namespace maplesu::sdk
