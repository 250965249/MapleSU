#include "module_err_def.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
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

extern "C" KModErr test_write(const char*);
static std::string scenario;
static bool injecting = false;
static bool interrupted = false;
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" int __real_fsync(int);
extern "C" int __real_close(int);
extern "C" int __real_renameat(int, const char*, int, const char*);
extern "C" int __real_fchmod(int, mode_t);
// Only SELinux xattrs are modeled; file opens, ETXTBSY, writes, fsync and rename
// are real Linux operations in the container.
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    assert(strcmp(name, "security.selinux") == 0);
    if (injecting && scenario == "label_failure") { errno = EACCES; return -1; }
    return __real_fsetxattr(fd, "user.maplesu.selinux", value, size, flags);
}
extern "C" ssize_t __wrap_write(int fd, const void* bytes, size_t size) {
    if (injecting && scenario == "write_failure") { errno = ENOSPC; return -1; }
    if (injecting && scenario == "zero_write") return 0;
    if (injecting && scenario == "interrupted" && !interrupted) {
        interrupted = true; errno = EINTR; return -1;
    }
    if (injecting && scenario == "short_write" && size > 4093) size = 4093;
    return __real_write(fd, bytes, size);
}
extern "C" int __wrap_fsync(int fd) {
    struct stat st{};
    if (injecting && fstat(fd, &st) == 0 &&
        ((scenario == "sync_failure" && S_ISREG(st.st_mode)) ||
         (scenario == "directory_sync_failure" && S_ISDIR(st.st_mode)))) {
        errno = EIO; return -1;
    }
    return __real_fsync(fd);
}
extern "C" int __wrap_close(int fd) {
    struct stat st{};
    const bool fail = injecting && scenario == "close_failure" && fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    const auto result = __real_close(fd);
    if (fail) { errno = EIO; return -1; }
    return result;
}
extern "C" int __wrap_renameat(int from, const char* name, int to, const char* target) {
    if (injecting && scenario == "rename_failure") { errno = EACCES; return -1; }
    return __real_renameat(from, name, to, target);
}
extern "C" int __wrap_fchmod(int fd, mode_t mode) {
    if (injecting && scenario == "mode_failure") { errno = EPERM; return -1; }
    return __real_fchmod(fd, mode);
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345";
}

int main(int argc, char** argv) {
    if (argc == 4 && strcmp(argv[1], "--hold") == 0) {
        const int ready = atoi(argv[2]), release = atoi(argv[3]);
        assert(write(ready, "R", 1) == 1);
        close(ready);
        char byte;
        assert(read(release, &byte, 1) == 0);
        return 0;
    }
    assert(argc == 2);
    scenario = argv[1];
    const bool busy = scenario == "busy";
    const bool postcommit_failure = scenario == "directory_sync_failure";
    const bool failure = !postcommit_failure && (scenario.find("failure") != std::string::npos || scenario == "zero_write" ||
        scenario == "symlink" || scenario == "hardlink" || scenario == "foreign_owner");
    char directory[] = "/tmp/maplesu-upgrade-XXXXXX";
    assert(mkdtemp(directory));
    const std::string path = std::string(directory) + "/su";
    const auto contents = [](const std::string& filename) {
        std::ifstream input(filename, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    };
    const std::string reference = std::string(directory) + "/reference";
    assert(test_write(reference.c_str()) == KModErr::OK);
    const auto expected = contents(reference);
    assert(expected.size() == 741912);
    assert(unlink(reference.c_str()) == 0);
    pid_t child = -1;
    int ready[2]{}, release[2]{};
    const std::string preserved = std::string(directory) + "/preserved";
    if (scenario == "repeat") assert(test_write(path.c_str()) == KModErr::OK);
    if (scenario == "stale_stage") {
        const auto stale = std::string(directory) + "/.maplesu-exec-" + std::to_string(getpid()) + "-0";
        assert(symlink("/absent", stale.c_str()) == 0);
    }
    if (failure) {
        const int fd = open(preserved.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0700);
        assert(fd >= 0 && write(fd, "previous", 8) == 8); close(fd);
        if (scenario == "symlink") assert(symlink(preserved.c_str(), path.c_str()) == 0);
        else if (scenario == "hardlink") assert(link(preserved.c_str(), path.c_str()) == 0);
        else {
            std::filesystem::copy_file(preserved, path);
            if (scenario == "foreign_owner") assert(chown(path.c_str(), 10315, 10315) == 0);
        }
    }
    if (busy) {
        std::filesystem::copy_file(argv[0], path);
        assert(pipe(ready) == 0 && pipe(release) == 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
            close(ready[0]); close(release[1]);
            const auto ready_text = std::to_string(ready[1]);
            const auto release_text = std::to_string(release[0]);
            execl(path.c_str(), path.c_str(), "--hold", ready_text.c_str(), release_text.c_str(), nullptr);
            _exit(127);
        }
        close(ready[1]); close(release[0]);
        char byte;
        assert(read(ready[0], &byte, 1) == 1 && byte == 'R');
        close(ready[0]);
        const int fd = open(path.c_str(), O_WRONLY);
        assert(fd == -1 && errno == ETXTBSY);
    }
    injecting = true;
    auto result = KModErr::OK;
    if (scenario == "concurrent") {
        pid_t children[4];
        for (auto& pid : children) {
            pid = fork();
            assert(pid >= 0);
            if (pid == 0) _exit(test_write(path.c_str()) == KModErr::OK ? 0 : 1);
        }
        for (const auto pid : children) {
            int status;
            assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
    } else result = test_write(path.c_str());
    const int saved_errno = errno;
    injecting = false;
    struct stat installed{};
    bool ok = (postcommit_failure ? result == KModErr::ERR_MODULE_WRITE_FILE : result == KModErr::OK) &&
        stat(path.c_str(), &installed) == 0 && contents(path) == expected;
    if (failure) {
        char bytes[9]{};
        const int fd = open(path.c_str(), O_RDONLY);
        assert(fd >= 0 && read(fd, bytes, 9) == 8); close(fd);
        const auto expected_error = scenario == "symlink" || scenario == "hardlink" || scenario == "foreign_owner" ?
            KModErr::ERR_MODULE_OPEN_FILE : scenario == "label_failure" || scenario == "mode_failure" ?
            KModErr::ERR_SET_FILE_SELINUX : KModErr::ERR_MODULE_WRITE_FILE;
        ok = result == expected_error && strcmp(bytes, "previous") == 0;
    } else if (ok) {
        char magic[4]{};
        const int fd = open(path.c_str(), O_RDONLY);
        assert(fd >= 0 && read(fd, magic, 4) == 4); close(fd);
        ok = memcmp(magic, "\177ELF", 4) == 0;
#ifdef MAPLESU_ATOMIC_PUBLISH
        char context[64]{};
        const char expected_context[] = "u:object_r:system_file:s0";
        ok = ok && (installed.st_mode & 0777) == 0755 &&
            getxattr(path.c_str(), "user.maplesu.selinux", context, sizeof(context)) == sizeof(expected_context) &&
            strcmp(context, expected_context) == 0;
#endif
    }
    if (busy) {
        struct stat running{};
        const auto executable = "/proc/" + std::to_string(child) + "/exe";
        if (result == KModErr::OK)
            ok = ok && stat(executable.c_str(), &running) == 0 && running.st_ino != installed.st_ino && running.st_nlink == 0;
        close(release[1]);
        int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    if (scenario == "stale_stage") {
        const auto stale = std::string(directory) + "/.maplesu-exec-" + std::to_string(getpid()) + "-0";
        ok = ok && std::filesystem::is_symlink(stale);
        assert(unlink(stale.c_str()) == 0);
    }
    for (const auto& entry : std::filesystem::directory_iterator(directory))
        ok = ok && entry.path().filename().string().find(".maplesu-exec-") != 0;
    std::filesystem::remove_all(directory);
    printf("%s %s sdkError=%s errno=%d\n", ok ? "PASS" : "FAIL", argv[1], to_string(result).c_str(),
           result == KModErr::OK ? 0 : saved_errno);
    return ok ? 0 : 1;
}
