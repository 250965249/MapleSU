// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include "../../maplesu-sdk/sdk/include/maplesu_request_private.h"

namespace maplesu {

class __attribute__((visibility("hidden"))) RequestAuthModeScope final {
public:
    explicit RequestAuthModeScope(kernel_module::RequestAuthMode requested) {
        using namespace kernel_module;
        const auto state = maplesu_request_auth_state();
        if (!maplesu_request_auth_usable(state)) {
            error_ = KModErr::ERR_MODULE_TEST_CHANNEL;
            return;
        }
        previous_ = (state & 1) ? RequestAuthMode::ManagerOwner : RequestAuthMode::LegacyKey;
        if (previous_ == requested) return;
        error_ = maplesu_request_set_auth_mode(requested);
        changed_ = !is_failed(error_);
    }
    ~RequestAuthModeScope() { (void)restore(); }
    RequestAuthModeScope(const RequestAuthModeScope&) = delete;
    RequestAuthModeScope& operator=(const RequestAuthModeScope&) = delete;
    KModErr error() const { return error_; }
    KModErr restore() {
        if (!changed_) return KModErr::OK;
        changed_ = false;
        kernel_module::CleanupReceiptScope diagnostic;
        return kernel_module::maplesu_request_set_auth_mode(previous_);
    }

private:
    kernel_module::RequestAuthMode previous_ = kernel_module::RequestAuthMode::LegacyKey;
    KModErr error_ = KModErr::OK;
    bool changed_ = false;
};

struct ManagerOwnerIdentity {
    KModErr error = KModErr::OK;
    uint32_t full_uid = 0;
    uint32_t epoch = 0;
    maplesu_host_instance host{};
};

inline ManagerOwnerIdentity query_manager_owner_identity() {
    using namespace kernel_module;
    RequestAuthModeScope mode(RequestAuthMode::ManagerOwner);
    ManagerOwnerIdentity result;
    result.error = mode.error();
    if (is_failed(result.error)) return result;
    maplesu_metadata_owner_v3 metadata{};
    uint64_t descriptor = 0;
    RequestOwnerBinding binding{};
    result.error = maplesu_request_owner_channel(metadata, descriptor, binding);
    const auto restore = mode.restore();
    if (is_failed(result.error)) return result;
    if (is_failed(restore)) {
        result.error = restore;
        return result;
    }
    result.full_uid = metadata.owner_full_uid;
    result.epoch = metadata.owner_epoch;
    result.host = metadata.host;
    return result;
}

} // namespace maplesu
