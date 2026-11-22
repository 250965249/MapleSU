// Standalone diagnostic fixture. Intentionally excluded from production CMake/packaging.
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
int fail(const char* stage) {
    const int saved = errno;
    std::fprintf(stderr, "stage=%s errno=%d detail=%s\n", stage, saved, std::strerror(saved));
    return 1;
}
bool byte(int fd, char value) { return send(fd, &value, 1, MSG_NOSIGNAL) == 1; }
bool expect(int fd, char value) {
    char actual = 0;
    const ssize_t count = recv(fd, &actual, 1, MSG_WAITALL);
    if (count == 1 && actual == value) return true;
    if (count >= 0) errno = count == 0 ? ECONNRESET : EPROTO;
    return false;
}
bool address(const char* name, sockaddr_un& target, socklen_t& length) {
    const size_t size = std::strlen(name);
    constexpr const char* prefix = "maplesu.socketprobe.";
    if (std::strncmp(name, prefix, std::strlen(prefix)) != 0 || size >= sizeof(target.sun_path) - 1) {
        errno = EINVAL;
        return false;
    }
    target.sun_family = AF_UNIX;
    std::memcpy(target.sun_path + 1, name, size);
    length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + size);
    return true;
}
bool peer(int fd, uid_t expected) {
    ucred identity{};
    socklen_t size = sizeof(identity);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &identity, &size) != 0) return false;
    if (identity.uid != expected) { errno = EPERM; return false; }
    return true;
}
void timeout(int fd) {
    timeval duration{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &duration, sizeof(duration));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &duration, sizeof(duration));
}
bool send_fd(int control, int descriptor) {
    char marker = 'F';
    iovec payload{&marker, 1};
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int))> ancillary{};
    msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.data();
    message.msg_controllen = ancillary.size();
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    return sendmsg(control, &message, MSG_NOSIGNAL) == 1;
}
struct Descriptor {
    int value = -1;
    ~Descriptor() { if (value >= 0) close(value); }
};
} // namespace

int main(int argc, char** argv) {
    if (argc != 6 || (std::strcmp(argv[1], "A") != 0 && std::strcmp(argv[1], "B") != 0 && std::strcmp(argv[1], "C") != 0)) {
        errno = EINVAL; return fail("arguments");
    }
    if (getuid() != 0 || geteuid() != 0) { errno = EPERM; return fail("root_identity"); }
    char* end = nullptr;
    const auto manager = static_cast<uid_t>(std::strtoul(argv[4], &end, 10));
    if (!end || *end || manager < 10000) { errno = EINVAL; return fail("manager_uid"); }
    const auto client = static_cast<uid_t>(std::strtoul(argv[5], &end, 10));
    if (!end || *end || client < 10000 || client == manager) { errno = EINVAL; return fail("client_uid"); }
    char context[256]{};
    const int attribute = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (attribute >= 0) {
        const ssize_t size = read(attribute, context, sizeof(context) - 1);
        if (size > 0) context[size] = 0;
        close(attribute);
    }
    std::printf("uid=%u pid=%d context=%s\n", getuid(), getpid(), context);
    std::fflush(stdout);

    sockaddr_un control_address{};
    socklen_t control_length = 0;
    if (!address(argv[2], control_address, control_length)) return fail("control_address");
    Descriptor control{socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (control.value < 0) return fail("control_socket");
    if (connect(control.value, reinterpret_cast<sockaddr*>(&control_address), control_length) != 0)
        return fail("control_connect");
    timeout(control.value);
    if (!peer(control.value, manager)) return fail("control_peer_uid");
    if (!expect(control.value, 'A')) return fail("control_handshake");

    sockaddr_un listener_address{};
    socklen_t listener_length = 0;
    if (!address(argv[3], listener_address, listener_length)) return fail("listener_address");
    Descriptor listener{socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (listener.value < 0) return fail("listener_socket");
    if (bind(listener.value, reinterpret_cast<sockaddr*>(&listener_address), listener_length) != 0)
        return fail("listener_bind");
    if (std::strcmp(argv[1], "B") == 0) {
        // Manager performs the first listen through LocalServerSocket(FileDescriptor).
        if (!send_fd(control.value, listener.value)) return fail("listener_send_fd");
        if (!expect(control.value, 'L')) return fail("manager_listen_ack");
        close(listener.value); listener.value = -1;
        if (!byte(control.value, 'R')) return fail("manager_ready_ack");
        if (!expect(control.value, 'D')) return fail("manager_done_ack");
    } else {
        if (listen(listener.value, 1) != 0) return fail("listener_listen");
        if (!byte(control.value, 'R')) return fail("listener_ready");
        pollfd pending{listener.value, POLLIN, 0};
        if (poll(&pending, 1, 5000) != 1) { errno = ETIMEDOUT; return fail("listener_poll"); }
        Descriptor accepted{accept4(listener.value, nullptr, nullptr, SOCK_CLOEXEC)};
        if (accepted.value < 0) return fail("listener_accept");
        timeout(accepted.value);
        if (!peer(accepted.value, client)) return fail("client_peer_uid");
        if (std::strcmp(argv[1], "C") == 0) {
            if (!send_fd(control.value, accepted.value)) return fail("accepted_send_fd");
            const unsigned char identity[] = {
                static_cast<unsigned char>(client >> 24), static_cast<unsigned char>(client >> 16),
                static_cast<unsigned char>(client >> 8), static_cast<unsigned char>(client)};
            if (send(control.value, identity, sizeof(identity), MSG_NOSIGNAL) != static_cast<ssize_t>(sizeof(identity)))
                return fail("accepted_send_uid");
            close(accepted.value); accepted.value = -1;
            if (!expect(control.value, 'D')) return fail("manager_done_ack");
            std::printf("clientPeerUid=%u acceptedFdTransferred=true\n", client);
            std::puts("stage=complete");
            return 0;
        }
        char ping[4]{};
        if (recv(accepted.value, ping, sizeof(ping), MSG_WAITALL) != 4 || std::memcmp(ping, "PING", 4) != 0)
            return fail("client_read");
        if (send(accepted.value, "PONG", 4, MSG_NOSIGNAL) != 4) return fail("client_write");
        std::printf("clientPeerUid=%u echo=PONG\n", client);
    }
    std::puts("stage=complete");
    return 0;
}
