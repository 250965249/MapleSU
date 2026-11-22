#pragma once

#include "maplesu/compat/native_module_abi.h"
#include <tuple>
#include <cstdint>
#include <string>
#include <vector>
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_module.h"

namespace maplesu::module_runtime {

// The legacy module ABI is kept at this boundary only.
inline constexpr char kEntrySymbol[] = maplesu::compat::native_module::kModuleEntrySymbol;
struct Result {
    KModErr loader = KModErr::OK;
    int entry = 0;
    bool skipped = false;
};
struct Record {
    std::string id;
    Result result;
};

std::string system_directory(const char* key);
std::string private_directory(const char* key, const char* id);
Result execute(const maplesu::sdk::module_desc& desc, const char* key);
KModErr run_batch(const char* key, const maplesu::sdk::MapleSUSdkVersion& version,
                 std::vector<Record>& results);
Result run_single(const char* key, const char* id,
                  const maplesu::sdk::MapleSUSdkVersion& version);

}  // namespace maplesu::module_runtime
