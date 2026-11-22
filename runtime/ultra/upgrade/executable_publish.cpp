#include "executable_publish.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace {
struct Fd {
    int value;
    ~Fd() { if (value >= 0) close(value); }
};
struct Staging {
    int directory;
    std::string name;
    ~Staging() { if (!name.empty()) unlinkat(directory, name.c_str(), 0); }
};
}

static KModErr publish_at(int directory, const char* name, const void* bytes, size_t size,
                         const char* context, mode_t mode) {
    if (!name || !*name || strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..") ||
        !bytes || !size || !context) return KModErr::ERR_MODULE_PARAM;
    struct stat st{};
    if (fstat(directory, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        (mode == 0700 && (st.st_mode & 0022))) return KModErr::ERR_MODULE_OPEN_DIR;
    if (fstatat(directory, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1) return KModErr::ERR_MODULE_OPEN_FILE;
    } else if (errno != ENOENT) return KModErr::ERR_MODULE_OPEN_FILE;

    // O_EXCL handles concurrent writers and stale names without following links.
    Staging staging{directory, {}};
    Fd output{-1};
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto candidate = ".maplesu-exec-" + std::to_string(getpid()) + "-" + std::to_string(attempt);
        output.value = openat(directory, candidate.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (output.value >= 0) { staging.name = candidate; break; }
        if (errno != EEXIST) return KModErr::ERR_MODULE_OPEN_FILE;
    }
    if (output.value < 0) return KModErr::ERR_MODULE_OPEN_FILE;
    size_t written = 0;
    while (written < size) {
        const auto count = write(output.value, static_cast<const char*>(bytes) + written, size - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return KModErr::ERR_MODULE_WRITE_FILE;
        written += static_cast<size_t>(count);
    }
    // Prepare the SDK's expected label before exposing the new inode.
    if (fchmod(output.value, mode) != 0 ||
        fsetxattr(output.value, "security.selinux", context, strlen(context) + 1, 0) != 0)
        return KModErr::ERR_SET_FILE_SELINUX;
    if (fstat(output.value, &st) != 0 || st.st_size != static_cast<off_t>(size) || fsync(output.value) != 0)
        return KModErr::ERR_MODULE_WRITE_FILE;
    const int saved = output.value;
    output.value = -1;
    if (close(saved) != 0) return KModErr::ERR_MODULE_WRITE_FILE;
    if (renameat(directory, staging.name.c_str(), directory, name) != 0)
        return KModErr::ERR_MODULE_WRITE_FILE;
    staging.name.clear();
    return fsync(directory) == 0 ? KModErr::OK : KModErr::ERR_MODULE_WRITE_FILE;
}

static KModErr publish(const char* path, const void* bytes, size_t size,
                      const char* context, mode_t mode) {
    if (!path || !bytes || !size || !context) return KModErr::ERR_MODULE_PARAM;
    const std::string target(path);
    const auto slash = target.rfind('/');
    if (slash == std::string::npos || slash + 1 == target.size()) return KModErr::ERR_MODULE_PARAM;
    const auto parent = slash == 0 ? "/" : target.substr(0, slash);
    const auto name = target.substr(slash + 1);
    Fd directory{open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (directory.value < 0) return KModErr::ERR_MODULE_OPEN_DIR;
    return publish_at(directory.value, name.c_str(), bytes, size, context, mode);
}

#ifndef MAPLESU_BACKEND_PUBLISH_ONLY
extern "C" KModErr maplesu_publish_executable(const char* path, const void* bytes,
                                             size_t size, const char* context) {
    return publish(path, bytes, size, context, 0755);
}
#endif

extern "C" KModErr maplesu_publish_private_backend(const char* path, const void* bytes,
                                                  size_t size, const char* context) {
    return publish(path, bytes, size, context, 0700);
}

extern "C" KModErr maplesu_publish_private_backend_at(int directory, const char* name,
                                                     const void* bytes, size_t size, const char* context) {
    return publish_at(directory, name, bytes, size, context, 0700);
}
