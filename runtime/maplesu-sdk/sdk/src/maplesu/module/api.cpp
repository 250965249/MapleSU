#include "../compat/module_api_legacy_abi.h"
#include "../compat/module_carrier_conversion.h"
#include "operations.h"
#include "maplesu_module_install_private.h"
#include "maplesu_request_private.h"

#include <cstring>
#include <string>
#include <vector>

namespace maplesu::module {
namespace {

// ROOT 密钥文本的长度窗口：16 <= len < 1024。
//   %len = strnlen(%key, 1024)
//   %t   = add i64 %len, -1024
//   %bad = icmp ult i64 %t, -1008     ; 只有 len ∈ [0,15] 或 len == 1024 时为真
constexpr size_t kRootKeyMaxLen = 1024;
constexpr size_t kRootKeyMinLen = 16;

KModErr check_root_key(const char* root_key) __attribute__((always_inline)) {
    const auto auth = kernel_module::maplesu_request_auth_state();
    if (!kernel_module::maplesu_request_auth_usable(auth)) return KModErr::ERR_MODULE_ROOT_KEY;
    if (auth & 1) return KModErr::OK;
    if (root_key == nullptr) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const size_t len = strnlen(root_key, kRootKeyMaxLen);
    if (len < kRootKeyMinLen || len >= kRootKeyMaxLen) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    return KModErr::OK;
}

KModErr parse_module_desc_from_zip_file(const char* root_key,
                                        const char* module_zip_path,
                                        Descriptor& out_desc) {
    RETURN_IF_ERROR(check_root_key(root_key));
    if (!kernel_module::maplesu_request_owner_mode()) compat::set_current_root_key(root_key);
    return maplesu::module::safe_parse_module_desc_from_zip_file(module_zip_path, out_desc);
}

template <typename Callback>
KModErr get_all_modules_with_cb(const char* root_key, Callback cb) {
    RETURN_IF_ERROR(check_root_key(root_key));
    if (!kernel_module::maplesu_request_owner_mode()) compat::set_current_root_key(root_key);

    std::vector<Record> list;
    KModErr err = maplesu::module::safe_get_all_modules(list);
    if (err != KModErr::OK) {
        return err;
    }
    for (const Record& record : list) {
        cb(record);
    }
    return KModErr::OK;
}

KModErr install_module_with_cb(const char* root_key, const char* module_zip_path,
                               void (*cb)(const char* reason)) {
    RETURN_IF_ERROR(check_root_key(root_key));
    if (!kernel_module::maplesu_request_owner_mode()) compat::set_current_root_key(root_key);

    std::string out_reason;
    KModErr err = maplesu::module_install::safe_install_module(module_zip_path, /*dev_run_once=*/false, out_reason);
    if (err == KModErr::ERR_MODULE_REJECT_INSTALL) {
        cb(out_reason.c_str());
    }
    return err;
}

KModErr install_module_dev_run_once_with_cb(const char* root_key,
                                            const char* module_zip_path,
                                            void (*cb)(const char* reason)) {
    RETURN_IF_ERROR(check_root_key(root_key));
    if (!kernel_module::maplesu_request_owner_mode()) compat::set_current_root_key(root_key);

    std::string out_reason;
    KModErr err = maplesu::module_install::safe_install_module(module_zip_path, /*dev_run_once=*/true, out_reason);
    if (err == KModErr::ERR_MODULE_REJECT_INSTALL) {
        cb(out_reason.c_str());
    }
    return err;
}

KModErr uninstall_module(const char* root_key, const char* mod_id32) {
    RETURN_IF_ERROR(check_root_key(root_key));
    if (!kernel_module::maplesu_request_owner_mode()) compat::set_current_root_key(root_key);
    return maplesu::module_install::safe_uninstall_module(mod_id32);
}

}  // namespace
}  // namespace maplesu::module

namespace maplesu::module_install {
KModErr install_with_completion(const char* root_key, const char* archive, bool run_once,
                               std::string& reason, InstallCompletion& completion) {
    completion = {};
    reason.clear();
    RETURN_IF_ERROR(maplesu::module::check_root_key(root_key));
    if (!kernel_module::maplesu_request_owner_mode()) compat::set_current_root_key(root_key);
    return safe_install_module(archive, run_once, reason, completion);
}
}  // namespace maplesu::module_install

namespace maplesu::sdk {
KModErr parse_module_desc_from_zip_file(const char* root_key, const char* module_zip_path,
                                        module_desc& out_desc) {
    maplesu::module::Descriptor parsed;
    const KModErr err = maplesu::module::parse_module_desc_from_zip_file(root_key, module_zip_path, parsed);
    if (err == KModErr::OK) maplesu::compat::copy_module_descriptor(out_desc, parsed);
    return err;
}
KModErr get_all_modules_with_cb(const char* root_key, void (*cb)(const module_record*)) {
    return maplesu::module::get_all_modules_with_cb(root_key,
        [cb](const maplesu::module::Record& record) {
            module_record converted;
            maplesu::compat::copy_module_record(converted, record);
            cb(&converted);
        });
}
KModErr install_module_with_cb(const char* root_key, const char* module_zip_path,
                               void (*cb)(const char* reason)) {
    return maplesu::module::install_module_with_cb(root_key, module_zip_path, cb);
}
KModErr install_module_dev_run_once_with_cb(const char* root_key, const char* module_zip_path,
                                            void (*cb)(const char* reason)) {
    return maplesu::module::install_module_dev_run_once_with_cb(root_key, module_zip_path, cb);
}
KModErr uninstall_module(const char* root_key, const char* mod_id32) {
    return maplesu::module::uninstall_module(root_key, mod_id32);
}
}  // namespace maplesu::sdk

#include "../compat/module_api_exports_legacy_abi.h"
