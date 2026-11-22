// Boot-session state machine.
//
// The SDK reads four files to decide whether the environment is Running, Fault
// or Unknown; this file is the only writer of those files.  The contract is:
//
//   <helper>.safe_flag             one byte: '1' initialising, '2' success,
//                                  '3' protection mode
//   <helper>.boot_session.duplicate  current boot id, written before the
//                                  protection decision
//   <helper>.boot_session.completed  boot id of the session that committed '2'
//   <helper>.boot_session.work       boot id of a successfully published boot
//   <helper>.boot_fail_protect       presence (any content) keeps protection
//
// A boot that fails must leave protection written and must never publish the
// work receipt; the work receipt is the only evidence the SDK accepts for a
// Running environment.
#include "private/helper_core.h"

extern "C" int maplesu_bootstrap_finish(const char*, helper_i64);

namespace {

int open_state(struct helper_context* context, const char* suffix, helper_u32 flags,
               helper_u32 mode) {
    char path[HELPER_PATH_MAX];
    if (helper_state_path(context, suffix, path, sizeof(path)) != HELPER_OK)
        return HELPER_E_NAMETOOLONG;
    return context->ops.open_path(path, flags, mode);
}

// Reads a small state file and validates that it is the root-owned, single-link
// regular file the installer created.  Missing files are reported as zero
// bytes, not as errors, because a first boot starts from install-time empties.
int read_state(struct helper_context* context, const char* suffix, char* out,
               helper_u32 capacity, helper_u32* length) {
    *length = 0;
    const int fd = open_state(context, suffix,
                              HELPER_OPEN_READ | HELPER_OPEN_NOFOLLOW | HELPER_OPEN_NONBLOCK, 0);
    if (fd == HELPER_E_NOENT) return HELPER_OK;
    if (fd < 0) return fd;
    struct helper_stat_info info;
    int result = context->ops.fstat(fd, &info);
    if (result == HELPER_OK && (!info.is_reg || info.uid != 0 || info.nlink != 1))
        result = HELPER_E_INVAL;
    if (result == HELPER_OK && info.size > capacity)
        result = HELPER_E_OVERFLOW;
    if (result == HELPER_OK) {
        const long long count = context->ops.read(fd, out, static_cast<helper_u32>(info.size));
        if (count < 0)
            result = static_cast<int>(count);
        else if (static_cast<helper_u64>(count) != info.size)
            result = HELPER_E_IO;
        else
            *length = static_cast<helper_u32>(count);
    }
    if (context->ops.close(fd) != HELPER_OK && result == HELPER_OK) result = HELPER_E_IO;
    return result;
}

// Writes exactly `length` bytes at offset zero of an existing-or-new state
// file.  The file is never truncated: a failed write keeps the previous byte,
// so a crash cannot lose the protection marker.
int write_state(struct helper_context* context, const char* suffix, const void* data,
                helper_u32 length) {
    const int fd = open_state(context, suffix,
                              HELPER_OPEN_WRITE | HELPER_OPEN_CREATE | HELPER_OPEN_NOFOLLOW |
                                  HELPER_OPEN_NONBLOCK,
                              0600);
    if (fd < 0) return fd;
    struct helper_stat_info info;
    int result = context->ops.fstat(fd, &info);
    if (result == HELPER_OK &&
        (!info.is_reg || info.uid != 0 || info.nlink != 1 || (info.size != 0 && info.size != length)))
        result = HELPER_E_INVAL;
    if (result == HELPER_OK) {
        const long long count = context->ops.write(fd, data, length);
        if (count < 0)
            result = static_cast<int>(count);
        else if (static_cast<helper_u32>(count) != length)
            result = HELPER_E_IO;
    }
    if (result == HELPER_OK && context->ops.fsync(fd) != HELPER_OK) result = HELPER_E_IO;
    if (context->ops.close(fd) != HELPER_OK && result == HELPER_OK) result = HELPER_E_IO;
    return result;
}

int write_safe_flag(struct helper_context* context, char value) {
    return write_state(context, HELPER_SUFFIX_SAFE_FLAG, &value, 1);
}

// A receipt holds the boot id plus the trailing newline, exactly 37 bytes.
int write_receipt(struct helper_context* context, const char* suffix) {
    char receipt[HELPER_RECEIPT_LEN];
    helper_memcopy(receipt, context->boot_id, HELPER_BOOT_ID_LEN);
    receipt[HELPER_BOOT_ID_LEN] = '\n';
    return write_state(context, suffix, receipt, HELPER_RECEIPT_LEN);
}

int read_safe_flag(struct helper_context* context, char* value, int* present) {
    char data[2];
    helper_u32 length = 0;
    *present = 0;
    *value = 0;
    const int result = read_state(context, HELPER_SUFFIX_SAFE_FLAG, data, sizeof(data), &length);
    if (result != HELPER_OK) return result;
    if (length == 0) return HELPER_OK;
    if (length != 1) return HELPER_E_INVAL;
    *value = data[0];
    *present = 1;
    return HELPER_OK;
}

int protection_enabled(struct helper_context* context, int* enabled) {
    *enabled = 0;
    char path[HELPER_PATH_MAX];
    const int path_result = helper_state_path(context, HELPER_SUFFIX_FAIL_PROTECT, path, sizeof(path));
    if (path_result != HELPER_OK) return path_result;
    const int fd = context->ops.open_path(path,
        HELPER_OPEN_READ | HELPER_OPEN_NOFOLLOW | HELPER_OPEN_NONBLOCK, 0);
    if (fd == HELPER_E_NOENT) return HELPER_OK;
    if (fd < 0) return fd;
    struct helper_stat_info info;
    int result = context->ops.fstat(fd, &info);
    if (result == HELPER_OK && !info.is_reg) result = HELPER_E_INVAL;
    const int closed = context->ops.close(fd);
    if (result == HELPER_OK && closed != HELPER_OK) result = closed;
    if (result == HELPER_OK) *enabled = 1;
    return result;
}

}  // namespace

void helper_log(struct helper_context* context, const char* text) {
    if (context == 0 || context->ops.log_line == 0 || text == 0) return;
    context->ops.log_line(text);
}

void helper_log_pair(struct helper_context* context, const char* prefix, const char* value) {
    char line[HELPER_PATH_MAX];
    helper_u32 length = 0;
    line[0] = '\0';
    if (helper_append(line, sizeof(line), &length, prefix) != HELPER_OK) return;
    if (helper_append(line, sizeof(line), &length, value) != HELPER_OK) return;
    helper_log(context, line);
}

void helper_log_error(struct helper_context* context, const char* prefix, helper_i64 error) {
    char value[24];
    if (helper_format_i64(value, sizeof(value), error) != HELPER_OK) return;
    helper_log_pair(context, prefix, value);
}

int helper_session_begin(struct helper_context* context, int* action) {
    *action = HELPER_SESSION_NORMAL;
    char flag = 0;
    int present = 0;
    const int read_result = read_safe_flag(context, &flag, &present);
    if (read_result != HELPER_OK) return read_result;
    if (present && flag != '1' && flag != '2' && flag != '3') return HELPER_E_INVAL;

    char receipt[HELPER_RECEIPT_LEN];
    helper_u32 length = 0;
    int result = read_state(context, HELPER_SUFFIX_WORK, receipt, sizeof(receipt), &length);
    if (result != HELPER_OK) return result;
    const int work_current = length == HELPER_RECEIPT_LEN && receipt[HELPER_BOOT_ID_LEN] == '\n' &&
        helper_memeq(receipt, context->boot_id, HELPER_BOOT_ID_LEN);
    // A module mutation may clear safe_flag after a completed bootstrap. It does
    // not erase a later explicit failure ('3'), or prove that a new attempt ('1')
    // completed. Both success receipts must belong to this boot.
    if (work_current && (!present || flag == '2')) {
        result = read_state(context, HELPER_SUFFIX_COMPLETED, receipt, sizeof(receipt), &length);
        if (result != HELPER_OK) return result;
        if (length == HELPER_RECEIPT_LEN && receipt[HELPER_BOOT_ID_LEN] == '\n' &&
            helper_memeq(receipt, context->boot_id, HELPER_BOOT_ID_LEN)) {
            // Repair clears both safe and duplicate; module mutation only
            // clears safe. Do not let old success receipts erase that intent.
            if (!present) {
                result = read_state(context, HELPER_SUFFIX_DUPLICATE, receipt, sizeof(receipt), &length);
                if (result != HELPER_OK) return result;
                if (length && (length != HELPER_RECEIPT_LEN || receipt[HELPER_BOOT_ID_LEN] != '\n' ||
                    !helper_memeq(receipt, context->boot_id, HELPER_BOOT_ID_LEN))) return HELPER_E_INVAL;
            }
            if (present || length) {
                *action = HELPER_SESSION_COMPLETED;
                return HELPER_OK;
            }
        }
    }

    result = read_state(context, HELPER_SUFFIX_DUPLICATE, receipt, sizeof(receipt), &length);
    if (result != HELPER_OK) return result;
    const int attempted = length == HELPER_RECEIPT_LEN && receipt[HELPER_BOOT_ID_LEN] == '\n' &&
        helper_boot_id_valid(receipt, HELPER_BOOT_ID_LEN);
    if (length != 0 && !attempted) return HELPER_E_INVAL;
    const int same_boot = attempted && helper_memeq(receipt, context->boot_id, HELPER_BOOT_ID_LEN);
    const int previous_failed = present && (flag == '3' || (flag == '1' && attempted));
    int protection = 0;
    if (previous_failed) {
        result = protection_enabled(context, &protection);
        if (result != HELPER_OK) return result;
    }
    // A bare install-time marker is not a failed boot. An incomplete attempt in
    // this boot is also not evidence of a reboot caused by initialization. Keep
    // its evidence and require the existing explicit recovery action to retry.
    if (present && flag == '1' && same_boot && protection)
        return HELPER_E_AGAIN;

    // The duplicate guard is written before the protection branch: the SDK only
    // reports Fault when this file belongs to the current boot.
    const int duplicate = write_receipt(context, HELPER_SUFFIX_DUPLICATE);
    if (duplicate != HELPER_OK) return duplicate;

    if (previous_failed) {
        helper_log(context, "bootstrap last failed");
        const int protected_write = write_safe_flag(context, '3');
        if (protected_write != HELPER_OK) return protected_write;
        if (protection) {
            *action = HELPER_SESSION_PROTECTED;
            return HELPER_OK;
        }
        // Protection was switched off by the user: retry this boot, but mark it
        // again as initialising so a crash re-enters protection next time.
        *action = HELPER_SESSION_RETRY;
        return write_safe_flag(context, '1');
    }

    *action = HELPER_SESSION_NORMAL;
    return write_safe_flag(context, '1');
}

int helper_session_publish(struct helper_context* context, const char* suffix,
                           const void* data, helper_u32 length) {
    if (!context->ops.renameat || !context->ops.unlinkat) return HELPER_E_NOSYS;
    char path[HELPER_PATH_MAX], pending[HELPER_PATH_MAX];
    int result = helper_state_path(context, suffix, path, sizeof(path));
    if (result != HELPER_OK) return result;
    helper_u32 size = helper_strlen(path);
    helper_memcopy(pending, path, size + 1);
    result = helper_append(pending, sizeof(pending), &size, ".pending");
    if (result != HELPER_OK) return result;
    helper_u32 split = helper_strlen(path);
    while (split && path[split - 1] != '/') --split;
    if (!split || !path[split]) return HELPER_E_INVAL;
    char parent[HELPER_PATH_MAX];
    const helper_u32 parent_length = split > 1 ? split - 1 : split;
    helper_memcopy(parent, path, parent_length);
    parent[parent_length] = 0;
    const int dir = context->ops.open_path(parent,
        HELPER_OPEN_READ | HELPER_OPEN_DIRECTORY | HELPER_OPEN_NOFOLLOW, 0);
    if (dir < 0) return dir;
    helper_stat_info info;
    result = context->ops.fstat(dir, &info);
    if (result == HELPER_OK && (!info.is_dir || info.uid)) result = HELPER_E_INVAL;
    if (result == HELPER_OK) {
        const int stale = context->ops.open_path(pending,
            HELPER_OPEN_READ | HELPER_OPEN_NOFOLLOW | HELPER_OPEN_NONBLOCK, 0);
        if (stale >= 0) {
            result = context->ops.fstat(stale, &info);
            if (result == HELPER_OK && (!info.is_reg || info.uid || info.nlink != 1)) result = HELPER_E_INVAL;
            if (context->ops.close(stale) != HELPER_OK && result == HELPER_OK) result = HELPER_E_IO;
            if (result == HELPER_OK) result = context->ops.unlinkat(dir, pending + split, 0);
        } else if (stale != HELPER_E_NOENT) result = stale;
    }
    if (result == HELPER_OK) {
        const int fd = context->ops.open_path(pending, HELPER_OPEN_WRITE | HELPER_OPEN_CREATE |
            HELPER_OPEN_EXCL | HELPER_OPEN_NOFOLLOW | HELPER_OPEN_NONBLOCK, 0600);
        if (fd < 0) result = fd;
        else {
            result = context->ops.fstat(fd, &info);
            if (result == HELPER_OK && (!info.is_reg || info.uid || info.nlink != 1 || info.size)) result = HELPER_E_INVAL;
            if (result == HELPER_OK) {
                const long long written = context->ops.write(fd, data, length);
                result = written < 0 ? static_cast<int>(written) :
                    (static_cast<helper_u64>(written) == length ? HELPER_OK : HELPER_E_IO);
            }
            if (result == HELPER_OK && context->ops.fsync(fd) != HELPER_OK) result = HELPER_E_IO;
            if (context->ops.close(fd) != HELPER_OK && result == HELPER_OK) result = HELPER_E_IO;
            if (result == HELPER_OK) result = context->ops.renameat(dir, pending + split, dir, path + split);
            if (result == HELPER_OK && context->ops.fsync(dir) != HELPER_OK) result = HELPER_E_IO;
            if (result != HELPER_OK) (void)context->ops.unlinkat(dir, pending + split, 0);
        }
    }
    if (context->ops.close(dir) != HELPER_OK && result == HELPER_OK) result = HELPER_E_IO;
    return result;
}

int helper_session_finish(struct helper_context* context) {
    char path[HELPER_PATH_MAX];
    const int result = helper_state_path(context, HELPER_SUFFIX_SAFE_FLAG, path, sizeof(path));
    if (result != HELPER_OK) return result;
    // Reuse the maintained same-fd commit, completion receipt and EINTR handling.
    if (maplesu_bootstrap_finish(path, 0) != 0) return HELPER_E_IO;
    char receipt[HELPER_RECEIPT_LEN];
    helper_memcopy(receipt, context->boot_id, HELPER_BOOT_ID_LEN);
    receipt[HELPER_BOOT_ID_LEN] = '\n';
    return helper_session_publish(context, HELPER_SUFFIX_WORK, receipt, sizeof(receipt));
}

int helper_session_fail(struct helper_context* context, helper_i64 error) {
    const int protection = write_safe_flag(context, '3');
    helper_log_error(context, "load_module_main -> rc=", error);
    if (protection != HELPER_OK)
        helper_log_error(context, "bootstrap protection marker rc=", protection);
    else
        helper_log(context, "bootstrap protection retained");
    return HELPER_EXIT_PROTECTED;
}
