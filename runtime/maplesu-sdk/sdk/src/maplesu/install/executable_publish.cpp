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
using maplesu::install::PublishCondition;
using maplesu::install::PublishErrorSource;
using maplesu::install::PublishPhase;
using maplesu::install::PublishResult;

struct Fd {
    int value;
    ~Fd() { if (value >= 0) close(value); }
};
struct Staging {
    int directory;
    std::string name;
    ~Staging() { if (!name.empty()) unlinkat(directory, name.c_str(), 0); }
};

PublishResult posix_failure(PublishPhase phase, int error, bool published = false) {
    return {PublishErrorSource::Posix, error, phase, published};
}

PublishResult condition_failure(PublishPhase phase, PublishCondition condition) {
    return {PublishErrorSource::Condition, static_cast<int64_t>(condition), phase, false};
}

// Only the frozen scalar entry points project producer details onto KModErr.
KModErr legacy_code(const PublishResult& result) {
    if (result.source == PublishErrorSource::None) return KModErr::OK;
    switch (result.phase) {
    case PublishPhase::Input:
        return KModErr::ERR_MODULE_PARAM;
    case PublishPhase::DirectoryOpen:
    case PublishPhase::DirectoryStat:
    case PublishPhase::DirectoryOwner:
        return KModErr::ERR_MODULE_OPEN_DIR;
    case PublishPhase::DestinationStat:
    case PublishPhase::DestinationValidate:
    case PublishPhase::StagingOpen:
        return KModErr::ERR_MODULE_OPEN_FILE;
    case PublishPhase::Mode:
    case PublishPhase::Context:
        return KModErr::ERR_SET_FILE_SELINUX;
    default:
        return KModErr::ERR_MODULE_WRITE_FILE;
    }
}

PublishResult publish_file(const char* path, const void* bytes, size_t size,
                          const char* context, mode_t mode) {
    if (!path || !bytes || !context)
        return condition_failure(PublishPhase::Input, PublishCondition::InvalidArgument);
    const std::string target(path);
    const auto slash = target.rfind('/');
    if (slash == std::string::npos || slash + 1 == target.size())
        return condition_failure(PublishPhase::Input, PublishCondition::InvalidPath);
    const auto parent = slash == 0 ? "/" : target.substr(0, slash);
    const auto name = target.substr(slash + 1);
    Fd directory{open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (directory.value < 0) return posix_failure(PublishPhase::DirectoryOpen, errno);
    struct stat st{};
    if (fstat(directory.value, &st) != 0)
        return posix_failure(PublishPhase::DirectoryStat, errno);
    if (st.st_uid != 0)
        return condition_failure(PublishPhase::DirectoryOwner, PublishCondition::DirectoryOwner);
    if (fstatat(directory.value, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode))
            return condition_failure(PublishPhase::DestinationValidate, PublishCondition::DestinationType);
        if (st.st_uid != 0)
            return condition_failure(PublishPhase::DestinationValidate, PublishCondition::DestinationOwner);
        if (st.st_nlink != 1)
            return condition_failure(PublishPhase::DestinationValidate, PublishCondition::DestinationLinks);
    } else {
        const int error = errno;
        if (error != ENOENT) return posix_failure(PublishPhase::DestinationStat, error);
    }

    // O_EXCL handles concurrent writers and stale names without following links.
    Staging staging{directory.value, {}};
    Fd output{-1};
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto candidate = ".maplesu-exec-" + std::to_string(getpid()) + "-" + std::to_string(attempt);
        output.value = openat(directory.value, candidate.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (output.value >= 0) { staging.name = candidate; break; }
        const int error = errno;
        if (error != EEXIST) return posix_failure(PublishPhase::StagingOpen, error);
    }
    if (output.value < 0)
        return condition_failure(PublishPhase::StagingOpen, PublishCondition::StagingNamesExhausted);
    size_t written = 0;
    while (written < size) {
        const auto count = write(output.value, static_cast<const char*>(bytes) + written, size - written);
        if (count < 0) {
            const int error = errno;
            if (error == EINTR) continue;
            return posix_failure(PublishPhase::Write, error);
        }
        if (count == 0)
            return condition_failure(PublishPhase::Write, PublishCondition::ZeroWrite);
        written += static_cast<size_t>(count);
    }
    // Prepare the SDK's expected label before exposing the new inode.
    if (fchmod(output.value, mode) != 0) return posix_failure(PublishPhase::Mode, errno);
    if (fsetxattr(output.value, "security.selinux", context, strlen(context) + 1, 0) != 0)
        return posix_failure(PublishPhase::Context, errno);
    if (fstat(output.value, &st) != 0) return posix_failure(PublishPhase::OutputStat, errno);
    if (st.st_size != static_cast<off_t>(size))
        return condition_failure(PublishPhase::OutputSize, PublishCondition::SizeMismatch);
    if (fsync(output.value) != 0) return posix_failure(PublishPhase::FileSync, errno);
    const int saved = output.value;
    output.value = -1;
    if (close(saved) != 0) return posix_failure(PublishPhase::FileClose, errno);
    if (renameat(directory.value, staging.name.c_str(), directory.value, name.c_str()) != 0)
        return posix_failure(PublishPhase::Rename, errno);
    staging.name.clear();
    if (fsync(directory.value) != 0) return posix_failure(PublishPhase::DirectorySync, errno, true);
    return {PublishErrorSource::None, 0, PublishPhase::Complete, true};
}

}  // namespace

extern "C" KModErr maplesu_publish_executable(const char* path, const void* bytes,
                                             size_t size, const char* context) {
    return maplesu::install::project_publish_result(
        maplesu::install::publish_executable_result(path, bytes, size, context));
}

namespace maplesu::install {
KModErr project_publish_result(const PublishResult& result) {
    return legacy_code(result);
}

PublishResult publish_executable_result(const char* path, const void* bytes,
                                        size_t size, const char* context) {
    if (!size) return condition_failure(PublishPhase::Input, PublishCondition::InvalidArgument);
    return publish_file(path, bytes, size, context, 0700);
}

PublishResult publish_version_result(const char* path, const void* bytes,
                                     size_t size, const char* context) {
    if (!size) return condition_failure(PublishPhase::Input, PublishCondition::InvalidArgument);
    return publish_file(path, bytes, size, context, 0777);
}

KModErr publish_empty_state(const char* path, const char* context) {
    static const char empty[] = "";
    return project_publish_result(publish_file(path, empty, 0, context, 0777));
}

KModErr publish_version(const char* path, const void* bytes, size_t size,
                        const char* context) {
    return project_publish_result(publish_version_result(path, bytes, size, context));
}
}  // namespace maplesu::install
