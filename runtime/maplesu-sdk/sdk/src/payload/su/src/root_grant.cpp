// su -- root handshake and process identity implementation.
//
#include "root_grant.h"
#include "../su_session_receipt.h"
#include "module_err_def.h"
#include "maplesu_root_private.h"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace maplesu::payload::su {
namespace {

static_assert(sizeof(msu_su_session_receipt) == 64, "su receipt ABI size");

// An incomplete scan must never turn a revoked session into a legacy grant.
bool find_session_fd(int& session_fd) {
    DIR* directory = ::opendir("/proc/self/fd");
    if (directory == nullptr) return false;
    const int directory_fd = ::dirfd(directory);
    int error = directory_fd < 0 ? errno : 0;
    constexpr char name[] = "anon_inode:[" MSU_SU_SESSION_NAME "]";
    while (error == 0) {
        errno = 0;
        const struct dirent* entry = ::readdir(directory);
        if (entry == nullptr) {
            error = errno;
            break;
        }
        char* end = nullptr;
        const long number = std::strtol(entry->d_name, &end, 10);
        if (errno == ERANGE || end == entry->d_name || *end != '\0' ||
            number < 0 || number > INT_MAX || number == directory_fd) continue;
        char target[sizeof(name)];
        const ssize_t length = ::readlinkat(directory_fd, entry->d_name,
                                            target, sizeof(target));
        if (length < 0) {
            error = errno;
            break;
        }
        if (length == static_cast<ssize_t>(sizeof(name) - 1) &&
            std::memcmp(target, name, length) == 0) {
            session_fd = static_cast<int>(number);
            break;
        }
    }
    if (::closedir(directory) != 0 && error == 0) error = errno;
    if (error == 0) return true;
    if (session_fd >= 0) ::close(session_fd);
    errno = error;
    return false;
}

bool validate_session_receipt(int fd) {
    const int flags = ::fcntl(fd, F_GETFD);
    if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) return false;
    msu_su_session_receipt receipt{};
    const int result = ::ioctl(fd, MSU_SU_SESSION_CONSUME, &receipt);
    if (result < 0) return false; // One consume only, including EINTR.
    if (result != 0 || receipt.magic != MSU_SU_SESSION_MAGIC ||
        receipt.version != MSU_SU_SESSION_VERSION || receipt.bytes != sizeof(receipt) ||
        receipt.state != (MSU_SU_SESSION_APPLIED | MSU_SU_SESSION_EXECUTED |
                          MSU_SU_SESSION_CONSUMED) || receipt.error != 0 ||
        receipt.reserved[0] != 0 || receipt.reserved[1] != 0) {
        errno = EPROTO;
        return false;
    }
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (::getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        ::getresgid(&real_gid, &effective_gid, &saved_gid) != 0) return false;
    if (receipt.target_uid != real_uid || receipt.target_uid != effective_uid ||
        receipt.target_uid != saved_uid || receipt.target_gid != real_gid ||
        receipt.target_gid != effective_gid || receipt.target_gid != saved_gid) {
        errno = EPERM;
        return false;
    }
    return true;
}

bool key_is_well_formed(const char* root_key) {
    if (root_key == nullptr) return false;
    const size_t length = strnlen(root_key, 1024);
    return length >= 16 && length < 1024;
}

}  // namespace

bool acquire_root(const char* root_key) {
    int session_fd = -1;
    if (!find_session_fd(session_fd)) return false;
    if (session_fd >= 0) {
        const bool valid = validate_session_receipt(session_fd);
        const int error = errno;
        if (::close(session_fd) != 0 && valid) return false;
        errno = error;
        return valid;
    }
    if (getuid() == 0 && geteuid() == 0) return true;
    if (!key_is_well_formed(root_key)) {
        errno = EINVAL;
        return false;
    }

    // The installed gateway accepts the SDK's complete authenticated requests,
    // not the historical truncated-key exec path. Use this generation's actual
    // credential/environment implementation; the private UID copy still owns
    // access, and inherited native sessions never enter this legacy branch.
    errno = 0;
    if (default_modules::module_root::set_current_root_for_su(root_key) != KModErr::OK) {
        if (!errno) errno = EPERM;
        return false;
    }
    if (getuid() != 0 || geteuid() != 0) { errno = EPERM; return false; }
    return true;
}

bool set_identity(unsigned int uid, unsigned int gid,
                  const std::vector<gid_t>& groups) {
    if (setgroups(groups.size(), groups.empty() ? nullptr : groups.data()) != 0) return false;
    if (setresgid(gid, gid, gid) != 0) return false;
    if (setresuid(uid, uid, uid) != 0) return false;
    return true;
}

bool join_global_mount_namespace() {
    const int mount_namespace = ::open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (mount_namespace < 0) return false;
    const int joined = ::setns(mount_namespace, CLONE_NEWNS);
    const int error = errno;
    ::close(mount_namespace);
    errno = error;
    return joined == 0;
}

}  // namespace maplesu::payload::su
