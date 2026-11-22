#pragma once

#include "cJSON.h"
#include "module_err_def.h"

#include <string>

namespace maplesu::ultra {

// MapleSU extensions stay at the consumer boundary so the frozen SDK header
// retains its original enum and inline-code contract.
inline std::string sdk_error_name(KModErr error) {
    switch (to_num(error)) {
        case -21001: return "ERR_SU_DELIVERY_INCOMPLETE";
        case -21002: return "ERR_BOOTSTRAP_NOT_READY";
        default: return error == KModErr::ERR_MAPLESU_ENV_NOT_INSTALL
            ? "ERR_MAPLESU_ENV_UNPREPARED" : to_string(error);
    }
}

inline void write_sdk_error_receipt(cJSON* root, KModErr error, const std::string& reason) {
    const auto name = sdk_error_name(error);
    cJSON_AddStringToObject(root, "sdkError", name.c_str());
    cJSON_AddNumberToObject(root, "sdkErrorCode", static_cast<double>(to_num(error)));
    if (!reason.empty()) cJSON_AddStringToObject(root, "reason", reason.c_str());
    cJSON_ReplaceItemInObject(root, "ok", cJSON_CreateFalse());
}

} // namespace maplesu::ultra
