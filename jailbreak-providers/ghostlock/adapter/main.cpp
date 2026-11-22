#include "handoff.hpp"
#include "lease_contract.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

int maplesu_ghostlock_upstream_main(int argc, char** argv);

namespace maplesu::ghostlock_adapter {
Configuration configuration;

/* Reads a 0/1 selinuxfs boolean. When `optional`, the two ordinary-App failure
 * modes stay distinguishable: ENOENT proves the entry does not exist (-2), while
 * EACCES/EPERM proves it exists but is not observable from this domain (-1).
 * Neither aborts the attempt (S03), but the restore script asserts absence only
 * for -2 and applies the documented Android baseline for -1. */
static bool boolean_file(const char* path, int& value, bool optional) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (optional && errno == ENOENT) {
            value = -2;
            return true;
        }
        if (optional && (errno == EACCES || errno == EPERM)) {
            value = -1;
            return true;
        }
        return false;
    }
    char bytes[4]{};
    ssize_t count;
    do { count = read(fd, bytes, sizeof(bytes)); } while (count < 0 && errno == EINTR);
    close(fd);
    if (count < 1 || count > 2 || (bytes[0] != '0' && bytes[0] != '1') ||
        (count == 2 && bytes[1] != '\n')) return false;
    value = bytes[0] - '0';
    return true;
}

bool initialize(int argc, char** argv) {
    // No forced, CLI-profile or external-consumer entry in this derived binary.
    if ((argc != 9 && argc != 13) || std::strcmp(argv[1], "--maplesu-lease") ||
        std::strcmp(argv[6], "ghostlock") || std::strcmp(argv[7], "--ghostlock-app-call") ||
        std::strcmp(argv[8], "--enable-status-record")) return false;
    if (argc == 13) {
        if (std::strcmp(argv[9], "--target") || std::strcmp(argv[11], "--attempt") ||
            (std::strcmp(argv[10], "ultra") && std::strcmp(argv[10], "normal")) ||
            !maplesu_lease_boot_id(argv[12])) return false;
        configuration.target = argv[10];
        configuration.attempt = argv[12];
        configuration.helper = "/data/user/0/dev.maplesu.manager/bs";
        if (access(configuration.helper.c_str(), X_OK)) return false;
    }
    unsigned char nonce[32]{};
    int manager_uid = 0;
    if (!maplesu_lease_endpoint(argv[2]) || !maplesu_lease_nonce(argv[3], nonce) ||
        !maplesu_lease_decimal(argv[4], 10000, &manager_uid) ||
        !maplesu_lease_boot_id(argv[5]) || getuid() != static_cast<uid_t>(manager_uid) ||
        geteuid() != getuid()) return false;
    const int boot_fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (boot_fd < 0) return false;
    char boot[39]{};
    ssize_t count;
    do { count = read(boot_fd, boot, sizeof(boot) - 1); } while (count < 0 && errno == EINTR);
    close(boot_fd);
    if (count != 37 || boot[36] != '\n') return false;
    boot[36] = '\0';
    if (std::strcmp(boot, argv[5])) return false;
    const char* home = std::getenv("GHOSTLOCK_HOME");
    char canonical[PATH_MAX]{};
    struct stat status{};
    if (!home || std::strlen(home) > 255 || !realpath(home, canonical) || std::strcmp(home, canonical) ||
        lstat(home, &status) || !S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 0077)) return false;
    char executable[PATH_MAX]{};
    const ssize_t size = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (size < 1 || size >= static_cast<ssize_t>(sizeof(executable) - 1)) return false;
    char* slash = std::strrchr(executable, '/');
    if (!slash) return false;
    *slash = '\0';
    configuration.home = home;
    configuration.consumer = std::string(executable) + "/libmaplesu_root_consumer.so";
    if (stat(configuration.consumer.c_str(), &status) || !S_ISREG(status.st_mode) ||
        access(configuration.consumer.c_str(), X_OK)) return false;
    // Both booleans are observations, not prerequisites: -1 means this domain
    // cannot read the path (existence is unknown), -2 means it does not exist. The
    // restore script reports which case it used instead of silently treating
    // either one as an observed value.
    if (!boolean_file("/sys/fs/selinux/enforce", configuration.enforcing, true) ||
        !boolean_file("/sys/fs/selinux/checkreqprot", configuration.checkreqprot, true)) return false;
    for (size_t i = 0; i < configuration.arguments.size(); ++i) configuration.arguments[i] = argv[i + 2];
    return true;
}
}

int main(int argc, char** argv) {
    if (!maplesu::ghostlock_adapter::initialize(argc, argv)) {
        std::fprintf(stderr, "maplesu-ghostlock: input or baseline rejected\n");
        return 64;
    }
    char* upstream[] = {argv[0], argv[7], argv[8], nullptr};
    return maplesu_ghostlock_upstream_main(3, upstream);
}
