// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include "cJSON.h"
#include "../../maplesu-sdk/sdk/src/module/su_redirect_tu/su_auth_result_private.h"
#include <string>

namespace maplesu::ultra {

inline cJSON* write_authorization_result(cJSON* root, const su_auth::ResultV1& result) {
    if (!root) return nullptr;
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (!data) {
        data = cJSON_CreateObject();
        if (!data) return nullptr;
        if (!cJSON_AddItemToObject(root, "data", data)) { cJSON_Delete(data); return nullptr; }
    }
    cJSON_DeleteItemFromObjectCaseSensitive(data, "authorizationResult");
    cJSON* detail = cJSON_AddObjectToObject(data, "authorizationResult");
    if (!detail) return nullptr;
    const bool available = (result.flags & su_auth::kResultAvailable) != 0;
    // Publish commit facts before optional diagnostics; a later allocation failure
    // leaves partial facts attached, but never reports a complete/successful receipt.
    if (!cJSON_AddNumberToObject(detail, "schemaVersion", 1) ||
        !cJSON_AddBoolToObject(detail, "operationResultAvailable", available) ||
        !cJSON_AddNumberToObject(detail, "operation", result.operation) ||
        !cJSON_AddStringToObject(detail, "resultCode", std::to_string(result.resultCode).c_str()) ||
        !cJSON_AddNumberToObject(detail, "commitState", result.commitState) ||
        !cJSON_AddNumberToObject(detail, "restoreState", result.restoreState) ||
        !cJSON_AddNumberToObject(detail, "deliveryState", result.deliveryState)) return nullptr;
    if (available) {
        if (!cJSON_AddStringToObject(detail, "primaryErrorCode", std::to_string(result.primaryErrorCode).c_str()) ||
            !cJSON_AddNumberToObject(detail, "primaryPhase", result.primaryPhase) ||
            !cJSON_AddNumberToObject(detail, "recoveryCount", result.recoveryCount) ||
            !cJSON_AddNumberToObject(detail, "recoveryTotal", result.recoveryTotal)) return nullptr;
        cJSON* recovery = cJSON_AddArrayToObject(detail, "recovery");
        if (!recovery) return nullptr;
        for (size_t index = 0; index < result.recoveryCount && index < result.recovery.size(); ++index) {
            cJSON* record = cJSON_CreateObject();
            if (!record) return nullptr;
            if (!cJSON_AddItemToArray(recovery, record)) { cJSON_Delete(record); return nullptr; }
            if (!cJSON_AddNumberToObject(record, "phase", result.recovery[index].phase) ||
                !cJSON_AddStringToObject(record, "errorCode", std::to_string(result.recovery[index].errorCode).c_str())) return nullptr;
        }
    }
    cJSON* transport = cJSON_AddObjectToObject(detail, "transport");
    if (!transport || !cJSON_AddNumberToObject(transport, "status", result.transportStatus) ||
        !cJSON_AddNumberToObject(transport, "errno", result.transportErrno) ||
        !cJSON_AddNumberToObject(transport, "childWaitStatus", result.childWaitStatus) ||
        !cJSON_AddBoolToObject(transport, "valid", result.childWaitStatusValid != 0) ||
        !cJSON_AddBoolToObject(detail, "diagnosticsComplete", available && !(result.flags & su_auth::kRecoveryOverflow))) return nullptr;
    return data;
}

// Other operation data is invalid after the outer process guard fails. The
// explicit result still records what that same operation reported before it failed.
inline void retain_authorization_result_on_process_failure(cJSON* root) {
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON* detail = cJSON_GetObjectItemCaseSensitive(data, "authorizationResult");
    if (!cJSON_IsObject(detail)) {
        cJSON_DeleteItemFromObjectCaseSensitive(root, "data");
        return;
    }
    for (cJSON* item = data->child; item;) {
        cJSON* next = item->next;
        if (item != detail) cJSON_Delete(cJSON_DetachItemViaPointer(data, item));
        item = next;
    }
}

} // namespace maplesu::ultra
