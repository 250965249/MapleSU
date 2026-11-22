// Consume the boot-owned mirror of the sole durable v3 authority.
#pragma once
#include "maplesu_request_private.h"
#include "su_uid_profile_private.h"
#include "su_uid_copies.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <new>

namespace maplesu::su_auth::detail {
inline bool owner_runtime_package_valid(const char* package) {
    if (!package || !*package) return false;
    for (size_t i = 0; i < sizeof(UidProfileV1::package); ++i) {
        const unsigned char c = package[i];
        if (!c) return true;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_')) return false;
    }
    return false;
}

inline KModErr owner_runtime_rows(uint64_t revision, maplesu_uid_metadata_v3& metadata,
                                 std::vector<maplesu_uid_record_v3>& rows) {
    try {
        // One bounded read holds one immutable table; no count/read race or retry.
        rows.resize(MAPLESU_UID_SNAPSHOT_MAX_RECORDS);
    } catch (const std::bad_alloc&) {
        errno = ENOMEM;
        return KModErr::ERR_NO_MEM;
    }
    const auto error = kernel_module::maplesu_request_owner_runtime_uid_readback(
        revision, metadata, rows.data(), static_cast<uint32_t>(rows.size()));
    if (is_failed(error)) return error;
    rows.resize(metadata.count); // The typed reader validates the entire output.
    return KModErr::OK;
}

inline KModErr owner_runtime_sync(uint32_t uid, const char* package, bool allow,
                                 ResultV1& result) {
    // This call has no receipt for the preceding durable transaction. A mirror
    // COMMITTED effect must never manufacture a durable ResultV1 commit fact.
    result.commitState = static_cast<uint32_t>(Commit::Unknown);
    const auto error = kernel_module::maplesu_request_owner_runtime_uid_sync(uid);
    if (is_failed(error)) return fail(result, error, Phase::WriterControlPublish);
    const auto sync = kernel_module::maplesu_request_management_reply();
    KModErr observed;
    int observed_errno;
    {
        // Verification is a separate READ. Preserve the original mutation's
        // raw status/effects/revision, including on verification failure.
        kernel_module::CleanupReceiptScope keep_sync_receipt;
        maplesu_uid_metadata_v3 metadata{};
        std::vector<maplesu_uid_record_v3> rows;
        // Successful unchanged sync also supplies its actual held revision.
        observed = owner_runtime_rows(sync.result, metadata, rows);
        if (is_ok(observed) && package) {
            const auto row = std::find_if(rows.begin(), rows.end(), [uid](const auto& value) {
                return value.full_uid == uid;
            });
            if (row == rows.end()) {
                errno = ENOENT;
                observed = KModErr::ERR_MODULE_SU_LIST_NOT_FOUND;
            } else if (row->decision != static_cast<uint32_t>(allow)) {
                errno = ESTALE;
                observed = ERR_SU_DELIVERY_INCOMPLETE;
            } else if (!row->package[0]) {
                // Current registry rows may omit the protected member name.
                // Never substitute the caller's package for that missing fact.
                errno = EOPNOTSUPP;
                observed = KModErr::ERR_MODULE_TEST_CHANNEL;
            } else if (!owner_runtime_package_valid(row->package) ||
                       std::strcmp(row->package, package)) {
                errno = ESTALE;
                observed = ERR_SU_DELIVERY_INCOMPLETE;
            }
        }
        observed_errno = errno;
    }
    if (is_failed(observed)) {
        errno = observed_errno;
        return fail(result, observed, Phase::WriterTableVerify);
    }
    // This sync and its same-revision readback verified the runtime mirror.
    set_delivery(result, Delivery::Open);
    return finish(result, KModErr::OK);
}

inline KModErr owner_runtime_profiles(void (*callback)(const UidProfileV1*)) {
    if (!callback) {
        errno = EINVAL;
        return KModErr::ERR_MODULE_PARAM;
    }
    maplesu_uid_metadata_v3 metadata{};
    std::vector<maplesu_uid_record_v3> rows;
    const auto error = owner_runtime_rows(0, metadata, rows);
    if (is_failed(error)) return error;
    // Validate every name before emitting anything; denies and secondary-user
    // full UIDs remain present. No legacy allowlist or raw memory is consulted.
    for (const auto& row : rows) {
        if (!owner_runtime_package_valid(row.package)) {
            errno = row.package[0] ? EBADMSG : EOPNOTSUPP;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
    }
    kernel_module::CleanupReceiptScope keep_read_receipt;
    for (const auto& row : rows) {
        UidProfileV1 profile{};
        profile.uid = row.full_uid;
        profile.allow = row.decision;
        std::memcpy(profile.package, row.package, sizeof(profile.package));
        callback(&profile);
    }
    return KModErr::OK;
}
} // namespace maplesu::su_auth::detail
