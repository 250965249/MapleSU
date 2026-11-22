#pragma once

#include <tuple>
#include <cstdint>
#include <string>
#include <vector>
#include "module_err_def.h"
#include "types.h"

namespace maplesu::module_runtime {

struct Result {
    KModErr loader = KModErr::OK;
    int entry = 0;
    bool skipped = false;
};
struct Record {
    std::string id;
    Result result;
};
struct BatchResult {
    KModErr first_error = KModErr::OK;
    KModErr bootstrap_error = KModErr::OK;
};

std::string system_directory(const char* key);
std::string private_directory(const char* key, const char* id);
Result execute(const module::Descriptor& desc, const char* key);
KModErr run_batch(const char* key, const module::SdkVersion& version,
                 std::vector<Record>& results);
BatchResult run_boot_batch(const char* key, const module::SdkVersion& version,
                           std::vector<Record>& results);
Result run_single(const char* key, const char* id,
                  const module::SdkVersion& version);

}  // namespace maplesu::module_runtime
