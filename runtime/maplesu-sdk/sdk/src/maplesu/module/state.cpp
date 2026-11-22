#include "state.h"
#include "maplesu_storage_private.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <sstream>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/xattr.h>
#include <unistd.h>


namespace maplesu::module_state {
namespace {
// Every call opens its own description: flock serializes threads as well as
// processes. No callback or fork runs while a short state write holds this lock.
class WriteLock {
public:
    explicit WriteLock(const std::string& file) {
        const std::string lock = (std::filesystem::path(file).parent_path() / ".module-state.lock").string();
        fd_ = open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0) return;
        struct stat st{};
        if (fstat(fd_, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1 || (st.st_mode & 0022)) return;
        int result;
        do { result = flock(fd_, LOCK_EX); } while (result < 0 && errno == EINTR);
        locked_ = result == 0;
    }
    ~WriteLock() { if (fd_ >= 0) close(fd_); }
    bool ready() const { return locked_; }
private:
    int fd_ = -1;
    bool locked_ = false;
};

KModErr read_file(const std::string& file_path, std::vector<std::string>& out) {
    int fd = open(file_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? KModErr::OK : KModErr::ERR_MODULE_READ_FILE;
    struct stat st{};
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return KModErr::ERR_MODULE_READ_FILE; }
    std::string text;
    char buffer[4096];
    ssize_t size;
    while ((size = ::read(fd, buffer, sizeof(buffer))) != 0) {
        if (size < 0) {
            if (errno == EINTR) continue;
            close(fd); return KModErr::ERR_MODULE_READ_FILE;
        }
        text.append(buffer, static_cast<size_t>(size));
    }
    close(fd);
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return KModErr::OK;
}

KModErr save_file(const std::string& file_path, const std::vector<std::string>& ids, mode_t mode) {
    struct stat st{};
    if (lstat(file_path.c_str(), &st) == 0) {
        if (!S_ISREG(st.st_mode)) return KModErr::ERR_MODULE_WRITE_FILE;
    } else if (errno != ENOENT) return KModErr::ERR_MODULE_WRITE_FILE;
    std::ostringstream text;
    for (const auto& id : ids) if (!id.empty()) text << id << '\n';
    const std::string contents = text.str();
    struct ParentDirectory {
        int fd;
        ~ParentDirectory() { if (fd >= 0) close(fd); }
    } parent{open(std::filesystem::path(file_path).parent_path().c_str(),
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (parent.fd < 0) return KModErr::ERR_MODULE_WRITE_FILE;
    std::string temporary = file_path + ".tmp.XXXXXX";
    int fd = mkstemp(temporary.data());
    if (fd < 0) return KModErr::ERR_MODULE_WRITE_FILE;
    KModErr result = KModErr::OK;
    size_t done = 0;
    while (done < contents.size()) {
        const ssize_t size = ::write(fd, contents.data() + done, contents.size() - done);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) { result = KModErr::ERR_MODULE_WRITE_FILE; break; }
        done += static_cast<size_t>(size);
    }
    // Publish only after the existing metadata and file contents are durable.
    if (result == KModErr::OK && fchmod(fd, mode)) result = KModErr::ERR_SET_FILE_SELINUX;
    static constexpr char context[] = "u:object_r:kernel:s0";
    if (result == KModErr::OK && fsetxattr(fd, "security.selinux", context, sizeof(context), 0))
        result = KModErr::ERR_SET_FILE_SELINUX;
    const auto sync_file = [](int descriptor) {
        int synced;
        do { synced = fsync(descriptor); } while (synced < 0 && errno == EINTR);
        return synced == 0;
    };
    if (result == KModErr::OK && !sync_file(fd)) result = KModErr::ERR_MODULE_WRITE_FILE;
    if (close(fd) && result == KModErr::OK) result = KModErr::ERR_MODULE_WRITE_FILE;
    if (result == KModErr::OK && rename(temporary.c_str(), file_path.c_str())) result = KModErr::ERR_MODULE_WRITE_FILE;
    if (result == KModErr::OK && !sync_file(parent.fd)) result = KModErr::ERR_MODULE_WRITE_FILE;
    if (close(parent.fd) && result == KModErr::OK) result = KModErr::ERR_MODULE_WRITE_FILE;
    parent.fd = -1;
    if (result != KModErr::OK) unlink(temporary.c_str());
    return result;
}
}

namespace {
KModErr resolve_path(List state, std::string& out) {
    out.clear();
    static constexpr const char* names[] = {
        "running_mods.3cee2062f9eab0e034c55c298c7571b4",
        "abnormal_mods.3cee2062f9eab0e034c55c298c7571b4",
        "removed_pending_reboot_mods.3cee2062f9eab0e034c55c298c7571b4",
        "pending_developer_run_once_mods.3cee2062f9eab0e034c55c298c7571b4",
        "finished_developer_run_once_mods.3cee2062f9eab0e034c55c298c7571b4",
        "pending_uninstall_mods.3cee2062f9eab0e034c55c298c7571b4",
    };
    const auto index = static_cast<uint8_t>(state);
    if (index >= sizeof(names) / sizeof(names[0])) return KModErr::ERR_MODULE_PARAM;
    std::string directory;
    RETURN_IF_ERROR(storage::current_kernel_directory(directory));
    out = (std::filesystem::path(directory) / names[index]).string();
    return KModErr::OK;
}
}  // namespace

std::string path(List state) {
    std::string file_path;
    if (resolve_path(state, file_path) != KModErr::OK) return {};
    return file_path;
}

KModErr read(List state, std::vector<std::string>& out) {
    out.clear();
    std::string file_path;
    RETURN_IF_ERROR(resolve_path(state, file_path));
    return read_file(file_path, out);
}

KModErr save(List state, const std::vector<std::string>& ids) {
    std::string file_path;
    RETURN_IF_ERROR(resolve_path(state, file_path));
    WriteLock lock(file_path);
    if (!lock.ready()) return KModErr::ERR_MODULE_WRITE_FILE;
    return save_file(file_path, ids, state == List::PendingRemoval ? 0600 : 0777);
}

KModErr add(List state, const std::string& id) {
    if (id.empty()) return KModErr::ERR_MODULE_PARAM;
    std::string file_path;
    RETURN_IF_ERROR(resolve_path(state, file_path));
    WriteLock lock(file_path);
    if (!lock.ready()) return KModErr::ERR_MODULE_WRITE_FILE;
    std::vector<std::string> ids;
    RETURN_IF_ERROR(read_file(file_path, ids));
    if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
    return save_file(file_path, ids, state == List::PendingRemoval ? 0600 : 0777);
}

KModErr remove(List state, const std::string& id) {
    if (id.empty()) return KModErr::ERR_MODULE_PARAM;
    std::string file_path;
    RETURN_IF_ERROR(resolve_path(state, file_path));
    WriteLock lock(file_path);
    if (!lock.ready()) return KModErr::ERR_MODULE_WRITE_FILE;
    std::vector<std::string> ids;
    RETURN_IF_ERROR(read_file(file_path, ids));
    const size_t before = ids.size();
    ids.erase(std::remove(ids.begin(), ids.end(), id), ids.end());
    return ids.size() == before ? KModErr::OK : save_file(file_path, ids, state == List::PendingRemoval ? 0600 : 0777);
}

}  // namespace maplesu::module_state
