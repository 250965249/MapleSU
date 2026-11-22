#pragma once
#include "maplesu/compat/native_module_abi.h"
#include "module_err_def.h"
#include <cstring>
#include <string>

namespace maplesu::compat {
using native_module::kModuleEntrySymbol;
inline std::string legacy_module_directory(const char* key, bool system, const char* data_root) {
    if (!key || strnlen(key, 49) != 48) return {};
    std::string directory = std::string(data_root) + "/" + std::string(key, 16);
    if (system) directory += key[0];
    return directory + "/";
}
inline KModErr invoke_legacy_module_entry(void* function, const char* key,
                                        const char* directory, int& result) {
    if (!key || strnlen(key, 49) != 48) return KModErr::ERR_MODULE_ROOT_KEY;
    using Entry = int (*)(const char*, const char*);
    result = reinterpret_cast<Entry>(function)(key, directory);
    return KModErr::OK;
}
}
