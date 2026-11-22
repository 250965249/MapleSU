#pragma once

#include "../../../include/maplesu_storage_private.h"
#include <cstring>

extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c();
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();

namespace maplesu::compat {

__attribute__((visibility("hidden")))
inline KModErr current_legacy_storage_context(storage::StorageContext& out) {
    if (kernel_module::maplesu_request_owner_mode()) return KModErr::ERR_MODULE_PARAM;
    const char* module = __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c();
    const size_t module_length = module ? strnlen(module, 1024) : 0;
    if (module_length && module_length < 1024) out.module_id.assign(module, module_length);
    const char* key = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    const size_t key_length = key ? strnlen(key, 1024) : 0;
    if (!key_length || key_length == 1024) return KModErr::ERR_MODULE_ROOT_KEY;
    const size_t prefix_length = key_length < 16 ? key_length : 16;
    std::memcpy(out.locator.kernel_component, key, prefix_length);
    out.locator.kernel_component[prefix_length] = 0;
    std::memcpy(out.locator.system_component, key, prefix_length);
    out.locator.system_component[prefix_length] = key[0];
    out.locator.system_component[prefix_length + 1] = 0;
    return KModErr::OK;
}

} // namespace maplesu::compat
