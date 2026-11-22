// MapleSU module implementation.
//
#define module_desc public_packed_module_desc
#define module_record public_packed_module_record
#include "kernel_module_kit_umbrella.h"
#undef module_desc
#undef module_record
#include <cstddef>
namespace maplesu::sdk {
struct module_desc {
    char name[1024] = {}, version[1024] = {}, desc[4096] = {}, author[1024] = {};
    char id32[1024] = {}, update_json[1024] = {};
    bool web_ui = false;
    MapleSUSdkVersion min_sdk_ver = {};
};
struct module_record { module_desc desc; ModuleRunState state = ModuleRunState::NotRunning; };
static_assert(sizeof(module_desc) == 9232 && alignof(module_desc) == 4);
static_assert(offsetof(module_desc, min_sdk_ver) == 9220 && sizeof(module_record) == 9236);
}

#include <cstring>
#include <string>
#include <vector>

// 安装期注入的私有 helper（名字带固定 hash 后缀，见 private_desc_parser.h:40）。
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(
    const char* root_key);

namespace maplesu::sdk {
namespace {

// ROOT 密钥文本的长度窗口：16 <= len < 1024。
//   %len = strnlen(%key, 1024)
//   %t   = add i64 %len, -1024
//   %bad = icmp ult i64 %t, -1008     ; 只有 len ∈ [0,15] 或 len == 1024 时为真
constexpr size_t kRootKeyMaxLen = 1024;
constexpr size_t kRootKeyMinLen = 16;

KModErr check_root_key(const char* root_key) __attribute__((always_inline)) {
    if (root_key == nullptr) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const size_t len = strnlen(root_key, kRootKeyMaxLen);
    if (len < kRootKeyMinLen || len >= kRootKeyMaxLen) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    return KModErr::OK;
}

}  // namespace

// 注意：声明必须留在 maplesu::sdk（非匿名）命名空间，否则 mangling 变
KModErr safe_parse_module_desc_from_zip_file(const char* module_zip_path,
                                            module_desc& out_desc);
KModErr safe_get_all_modules(std::vector<module_record>& out_list);
KModErr safe_install_module(const char* module_zip_path, bool dev_run_once,
                            std::string& out_reason);
KModErr safe_uninstall_module(const char* mod_id32);

KModErr parse_module_desc_from_zip_file(const char* root_key,
                                        const char* module_zip_path,
                                        module_desc& out_desc) {
    RETURN_IF_ERROR(check_root_key(root_key));
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);
    return safe_parse_module_desc_from_zip_file(module_zip_path, out_desc);
}

KModErr get_all_modules_with_cb(const char* root_key,
                                void (*cb)(const module_record*)) {
    RETURN_IF_ERROR(check_root_key(root_key));
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    std::vector<module_record> list;
    KModErr err = safe_get_all_modules(list);
    if (is_failed(err)) {
        return err;
    }
    for (const module_record& record : list) {
        cb(&record);
    }
    return KModErr::OK;
}

KModErr install_module_with_cb(const char* root_key, const char* module_zip_path,
                               void (*cb)(const char* reason)) {
    RETURN_IF_ERROR(check_root_key(root_key));
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    std::string out_reason;
    KModErr err = safe_install_module(module_zip_path, /*dev_run_once=*/false, out_reason);
    if (err == KModErr::ERR_MODULE_REJECT_INSTALL) {
        cb(out_reason.c_str());
    }
    return err;
}

KModErr install_module_dev_run_once_with_cb(const char* root_key,
                                            const char* module_zip_path,
                                            void (*cb)(const char* reason)) {
    RETURN_IF_ERROR(check_root_key(root_key));
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    std::string out_reason;
    KModErr err = safe_install_module(module_zip_path, /*dev_run_once=*/true, out_reason);
    if (err == KModErr::ERR_MODULE_REJECT_INSTALL) {
        cb(out_reason.c_str());
    }
    return err;
}

KModErr uninstall_module(const char* root_key, const char* mod_id32) {
    RETURN_IF_ERROR(check_root_key(root_key));
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);
    return safe_uninstall_module(mod_id32);
}

}  // namespace maplesu::sdk
