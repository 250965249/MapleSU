// Shared executable publisher of the kit runtime.
//
// Publishes one runtime program below a directory: stages it under a temporary
// name with an exclusive create, labels the new inode, then moves the finished
// file into place so a reader never observes a partially written program.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace {

// Publisher error codes (kit error space).
constexpr long long kOk = 0;
constexpr long long kErrModuleParam = -20000;    // null argument
constexpr long long kErrSetFileSelinux = -19915; // chmod / SELinux label failed
constexpr long long kErrOpenDir = -19930;        // staging directory not usable
constexpr long long kErrWriteFile = -19933;      // write / fsync / rename failed
constexpr long long kErrOpenFile = -19934;       // staging file not usable

// Published programs are owner-only.
constexpr unsigned int kHardenedFileMode = 0700;
constexpr unsigned long kStagingAttempts = 32;
constexpr char kSelinuxXattr[] = "security.selinux";
constexpr char kStagingPrefix[] = ".maplesu-exec-";

struct Fd {
    int value;
    ~Fd() {
        if (value >= 0) close(value);
    }
};

struct Staging {
    int directory;
    std::string name;
    ~Staging() {
        if (!name.empty()) unlinkat(directory, name.c_str(), 0);
    }
};

// Stages `bytes` in the already-open directory, labels the new inode and moves
// it into place.  The temporary name uses O_EXCL so concurrent writers cannot
// collide.
long long publish_at(int directory, const char* name, const void* bytes, unsigned long size,
                     const char* context) {
    struct stat st {};
    if (fstat(directory, &st) != 0 || st.st_uid != 0) return kErrOpenDir;
    if (fstatat(directory, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1) return kErrOpenFile;
    } else if (errno != ENOENT) {
        return kErrOpenFile;
    }

    Staging staging{directory, {}};
    Fd output{-1};
    for (unsigned attempt = 0; attempt < kStagingAttempts; ++attempt) {
        const std::string candidate =
            kStagingPrefix + std::to_string(getpid()) + "-" + std::to_string(attempt);
        output.value = openat(directory, candidate.c_str(),
                              O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (output.value >= 0) {
            staging.name = candidate;
            break;
        }
        if (errno != EEXIST) return kErrOpenFile;
    }
    if (output.value < 0) return kErrOpenFile;

    std::size_t written = 0;
    while (written < size) {
        const ssize_t count =
            write(output.value, static_cast<const char*>(bytes) + written, size - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return kErrWriteFile;
        written += static_cast<std::size_t>(count);
    }
    if (fchmod(output.value, kHardenedFileMode) != 0 ||
        fsetxattr(output.value, kSelinuxXattr, context, strlen(context) + 1, 0) != 0) {
        return kErrSetFileSelinux;
    }
    if (fstat(output.value, &st) != 0 || st.st_size != static_cast<off_t>(size) ||
        fsync(output.value) != 0) {
        return kErrWriteFile;
    }
    const int saved = output.value;
    output.value = -1;
    if (close(saved) != 0) return kErrWriteFile;
    if (renameat(directory, staging.name.c_str(), directory, name) != 0) return kErrWriteFile;
    staging.name.clear();
    return fsync(directory) == 0 ? kOk : kErrWriteFile;
}

// Publishes one program at the parent directory of `path`.
long long publish(const char* path, const void* bytes, unsigned long size, const char* context) {
    if (path == nullptr || bytes == nullptr || size == 0 || context == nullptr) {
        return kErrModuleParam;
    }
    const std::string target(path);
    const std::size_t slash = target.rfind('/');
    if (slash == std::string::npos || slash + 1 == target.size()) return kErrModuleParam;
    const std::string parent = slash == 0 ? std::string("/") : target.substr(0, slash);
    const std::string name = target.substr(slash + 1);
    Fd directory{open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0)};
    if (directory.value < 0) return kErrOpenDir;
    return publish_at(directory.value, name.c_str(), bytes, size, context);
}

}  // namespace

// Installs one runtime program next to the module tree.  Imported by the other
// installers.  Returns 0 on success or a kit error code.
extern "C" long long maplesu_publish_executable(const char* target_path, const void* data,
                                                unsigned long size,
                                                const char* selinux_context) {
    return publish(target_path, data, size, selinux_context);
}
