#include "uapi/supercall.h"
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <dirent.h>
#include <cstring>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
struct Descriptor {
    int value;
    ~Descriptor() { if (value >= 0) close(value); }
};
unsigned long number(const char* text) {
    char* end = nullptr;
    errno = 0;
    auto value = strtoul(text, &end, 10);
    if (errno || !*text || *end) throw std::runtime_error("KSU_MANAGER_FD_ARGUMENT");
    return value;
}
}

// Reuse KSU's existing manager setresuid hook in a single-threaded child.
// No root shell or reboot syscall is needed to obtain the first driver.
int ksu_manager_fd(int argc, char** argv) {
    if (argc != 5 || getuid() < 10000 || getuid() != geteuid())
        throw std::runtime_error("KSU_MANAGER_FD_SELF_REQUIRED");
    const auto uid = number(argv[3]), pid = number(argv[4]);
    const auto length = strlen(argv[2]);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (uid != getuid() || uid > 0x7fffffffUL || !pid || pid > 0x7fffffffUL ||
        !length || length >= sizeof(address.sun_path) - 1 ||
        strncmp(argv[2], "maplesu-ksu-fd-", 15))
        throw std::runtime_error("KSU_MANAGER_FD_ARGUMENT");
    memcpy(address.sun_path + 1, argv[2], length);
    Descriptor channel{socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (channel.value < 0 || connect(channel.value, reinterpret_cast<sockaddr*>(&address),
            offsetof(sockaddr_un, sun_path) + length + 1))
        throw std::runtime_error("KSU_MANAGER_FD_CONNECT");
    ucred peer{};
    socklen_t size = sizeof(peer);
    if (getsockopt(channel.value, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
        size != sizeof(peer) || peer.uid != uid || static_cast<unsigned long>(peer.pid) != pid)
        throw std::runtime_error("KSU_MANAGER_FD_PEER");
    timeval deadline{3, 0};
    if (setsockopt(channel.value, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)))
        throw std::runtime_error("KSU_MANAGER_FD_TIMEOUT");
    if (syscall(SYS_setresuid, getuid(), getuid(), getuid()))
        throw std::runtime_error("KSU_MANAGER_FD_REBIND");
    Descriptor driver{-1};
    auto* directory = opendir("/proc/self/fd");
    if (!directory) throw std::runtime_error("KSU_MANAGER_FD_SCAN");
    while (auto* entry = readdir(directory)) {
        char* end = nullptr;
        const long candidate = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end || candidate < 0 || candidate > 0x7fffffffL) continue;
        char path[64], target[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%ld", candidate);
        const auto count = readlink(path, target, sizeof(target) - 1);
        if (count < 0) continue;
        target[count] = 0;
        if (!strcmp(target, "anon_inode:[ksu_driver]")) {
            driver.value = static_cast<int>(candidate);
            break;
        }
    }
    closedir(directory);
    ksu_get_info_cmd info{};
    if (driver.value < 0 || ioctl(driver.value, KSU_IOCTL_GET_INFO, &info) || !info.version ||
        info.uapi_version != KERNEL_SU_UAPI_VERSION || !(info.flags & KSU_GET_INFO_FLAG_LATE_LOAD) || !(info.flags & KSU_GET_INFO_FLAG_MANAGER))
        throw std::runtime_error("KSU_MANAGER_FD_LATE_KERNEL_REQUIRED");
    char accepted = 'K';
    iovec payload{&accepted, 1};
    alignas(cmsghdr) unsigned char ancillary[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = ancillary;
    message.msg_controllen = sizeof(ancillary);
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &driver.value, sizeof(int));
    ssize_t sent;
    do { sent = sendmsg(channel.value, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    if (sent != 1) throw std::runtime_error("KSU_MANAGER_FD_SEND");
    return 0;
}
