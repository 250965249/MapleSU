// One lock covers boot initialization and the complete authorization transaction.
#pragma once

#include "maplesu/compat/persisted_inputs.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAPLESU_SU_AUTH_LOCK_DIR
#define MAPLESU_SU_AUTH_LOCK_DIR "/data/adb/maplesu"
#endif

namespace maplesu::su_auth::detail {
struct SuAuthLock {
    int fd = -1;
    bool acquire() {
        // /data/adb may be absent in an SDK-only installation.
        if (mkdir("/data/adb", 0700) != 0 && errno != EEXIST) return false;
        if (mkdir(MAPLESU_SU_AUTH_LOCK_DIR, 0700) != 0 && errno != EEXIST) return false;
        const int directory = open(MAPLESU_SU_AUTH_LOCK_DIR, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory < 0) return false;
        struct stat st{};
        if (fstat(directory, &st) == 0 && st.st_uid == 0 && (st.st_mode & 0022) == 0)
            fd = openat(directory, maplesu::compat::kSuAuthorizationLockFile, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        close(directory);
        if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
            st.st_nlink != 1 || (st.st_mode & 0077) != 0) return false;
        int result;
        do { result = flock(fd, LOCK_EX); } while (result != 0 && errno == EINTR);
        return result == 0;
    }
    ~SuAuthLock() { if (fd >= 0) close(fd); }
};
}
