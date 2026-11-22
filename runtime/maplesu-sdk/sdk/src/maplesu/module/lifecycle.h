#pragma once

#include "module_err_def.h"
#include "maplesu_module_control.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace maplesu::module_lifecycle {

// The synchronous operation's process owns the record lock. Keep the inode:
// unlinking it would allow a later operation to lock a different file.
class ModuleMutation {
public:
    ModuleMutation(const std::string& kernel_directory, const char* id) {
        if (!id || !*id || !strcmp(id, ".") || !strcmp(id, "..") || strchr(id, '/')) {
            error_ = KModErr::ERR_MODULE_PARAM; return;
        }
        const std::string directory = kernel_directory + ".module-lifecycle";
        if (mkdir(directory.c_str(), 0700) && errno != EEXIST) return;
        const int parent = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent < 0) return;
        struct stat st{};
        if (fstat(parent, &st) || st.st_uid || (st.st_mode & 0022)) { close(parent); return; }
        fd_ = openat(parent, id, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
        close(parent);
        if (fd_ < 0 || fstat(fd_, &st) || !S_ISREG(st.st_mode) || st.st_uid ||
            st.st_nlink != 1 || (st.st_mode & 0022)) return;
        struct flock lock{};
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        int result;
        do { result = fcntl(fd_, F_SETLK, &lock); } while (result < 0 && errno == EINTR);
        if (result == 0) error_ = KModErr::OK;
        else if (errno == EACCES || errno == EAGAIN) error_ = static_cast<KModErr>(MODULE_CONTROL_BUSY);
    }
    ~ModuleMutation() { if (fd_ >= 0) close(fd_); }
    KModErr error() const { return error_; }
    ModuleMutation(const ModuleMutation&) = delete;
    ModuleMutation& operator=(const ModuleMutation&) = delete;
private:
    int fd_ = -1;
    KModErr error_ = static_cast<KModErr>(MODULE_CONTROL_IO);
};

}  // namespace maplesu::module_lifecycle
