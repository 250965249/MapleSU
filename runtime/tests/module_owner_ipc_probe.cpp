#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

// Negative fixture: real UID is nonroot, effective UID remains Root.
int main() {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0 || setresuid(10000, 0, 0)) { std::perror("probe credentials"); return 2; }
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::strcpy(address.sun_path, "/tmp/maplesu-owner-test/run/modules.sock");
    if (connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address))) { std::perror("probe connect"); return 3; }
    // Identity is checked before reading any request.
    char response[256] {};
    ssize_t n = recv(fd, response, sizeof(response) - 1, 0);
    if (n <= 0) { std::perror("probe receive"); return 5; }
    (void)write(STDOUT_FILENO, response, static_cast<size_t>(n));
    (void)write(STDOUT_FILENO, "\n", 1);
    return std::strstr(response, "ERR Root peer required") ? 0 : 1;
}
