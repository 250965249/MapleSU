#include "executable_publish.h"
#include <cassert>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static std::string scenario;
static bool injecting, interrupted;
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" int __real_fsync(int);
extern "C" int __real_close(int);
extern "C" int __real_fchmod(int, mode_t);
extern "C" int __real_renameat(int, const char*, int, const char*);
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size) {
    if (injecting && scenario == "write_failure") { errno = ENOSPC; return -1; }
    if (injecting && scenario == "zero_write") return 0;
    if (injecting && scenario == "interrupted" && !interrupted) {
        interrupted = true; errno = EINTR; return -1;
    }
    if (injecting && scenario == "short_write" && size > 31) size = 31;
    return __real_write(fd, data, size);
}
extern "C" int __wrap_fsync(int fd) {
    struct stat st{};
    if (injecting && fstat(fd, &st) == 0 &&
        ((scenario == "sync_failure" && S_ISREG(st.st_mode)) ||
         (scenario == "directory_sync_failure" && S_ISDIR(st.st_mode)))) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
extern "C" int __wrap_close(int fd) {
    struct stat st{};
    bool fail = injecting && scenario == "close_failure" && fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    int result = __real_close(fd);
    if (fail) { errno = EIO; return -1; }
    return result;
}
extern "C" int __wrap_fchmod(int fd, mode_t mode) {
    if (injecting && scenario == "mode_failure") { errno = EPERM; return -1; }
    return __real_fchmod(fd, mode);
}
extern "C" int __wrap_renameat(int from, const char* name, int to, const char* target) {
    if (injecting && scenario == "rename_failure") { errno = EACCES; return -1; }
    return __real_renameat(from, name, to, target);
}
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* data, size_t size, int flags) {
    assert(strcmp(name, "security.selinux") == 0);
    if (injecting && scenario == "label_failure") { errno = EACCES; return -1; }
    return __real_fsetxattr(fd, "user.maplesu.selinux", data, size, flags);
}
static std::string contents(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
int main(int argc, char** argv) {
    assert(argc == 2);
    scenario = argv[1];
    char root[] = "/tmp/maplesu-policy-publish-XXXXXX";
    assert(mkdtemp(root));
    const std::string path = std::string(root) + "/backend";
    const std::string old_path = std::string(root) + "/old";
    const std::string payload(8193, 'N');
    constexpr char context[] = "u:object_r:system_file:s0";
    std::ofstream(old_path) << "previous";
    if (scenario == "symlink") assert(symlink(old_path.c_str(), path.c_str()) == 0);
    else if (scenario == "hardlink") assert(link(old_path.c_str(), path.c_str()) == 0);
    else if (scenario != "fresh") std::ofstream(path) << "previous";
    if (scenario == "foreign_owner") assert(chown(path.c_str(), 10315, 10315) == 0);
    if (scenario == "unsafe_directory") assert(chmod(root, 0777) == 0);
    if (scenario == "stale_stage") {
        std::string stale = std::string(root) + "/.maplesu-exec-" + std::to_string(getpid()) + "-0";
        assert(symlink(old_path.c_str(), stale.c_str()) == 0);
    }
    const int held = scenario == "held_inode" ? open(path.c_str(), O_RDONLY | O_CLOEXEC) : -1;
    injecting = true;
    KModErr result = KModErr::OK;
    if (scenario == "concurrent") {
        pid_t children[4];
        for (auto& child : children) {
            child = fork(); assert(child >= 0);
            if (child == 0) _exit(maplesu_publish_private_backend(path.c_str(), payload.data(), payload.size(), context) == KModErr::OK ? 0 : 1);
        }
        for (auto child : children) { int status; assert(waitpid(child, &status, 0) == child && status == 0); }
    } else if (scenario == "legacy_mode") {
        result = maplesu_publish_executable(path.c_str(), payload.data(), payload.size(), context);
    } else result = maplesu_publish_private_backend(path.c_str(), payload.data(), payload.size(), context);
    injecting = false;
    bool postcommit = scenario == "directory_sync_failure";
    bool bad_path = scenario == "symlink" || scenario == "hardlink" || scenario == "foreign_owner";
    bool bad_label = scenario == "mode_failure" || scenario == "label_failure";
    bool failure = scenario.find("failure") != std::string::npos || scenario == "zero_write" || bad_path || scenario == "unsafe_directory";
    if (failure && !postcommit) {
        KModErr expected = bad_path ? KModErr::ERR_MODULE_OPEN_FILE : bad_label ? KModErr::ERR_SET_FILE_SELINUX :
            scenario == "unsafe_directory" ? KModErr::ERR_MODULE_OPEN_DIR : KModErr::ERR_MODULE_WRITE_FILE;
        assert(result == expected && contents(path) == "previous");
    } else {
        assert(result == (postcommit ? KModErr::ERR_MODULE_WRITE_FILE : KModErr::OK));
        struct stat st{};
        assert(stat(path.c_str(), &st) == 0 && contents(path) == payload && st.st_uid == 0 && st.st_nlink == 1);
        assert((st.st_mode & 07777) == (scenario == "legacy_mode" ? 0755 : 0700));
        char label[64]{};
        assert(getxattr(path.c_str(), "user.maplesu.selinux", label, sizeof(label)) == sizeof(context));
        assert(strcmp(context, label) == 0);
    }
    if (held >= 0) {
        char data[8];
        struct stat before{}, after{};
        assert(read(held, data, sizeof(data)) == 8 && memcmp(data, "previous", 8) == 0);
        assert(fstat(held, &before) == 0 && stat(path.c_str(), &after) == 0 && before.st_ino != after.st_ino);
        close(held);
    }
    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        const auto name = entry.path().filename().string();
        if (name.find(".maplesu-exec-") == 0)
            assert(scenario == "stale_stage" && std::filesystem::is_symlink(entry));
    }
    assert(contents(old_path) == "previous");
    std::filesystem::remove_all(root);
    printf("PASS private-backend publication %s\n", scenario.c_str());
}
