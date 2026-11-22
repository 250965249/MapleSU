/* SuAllowList::save_all uses a predictable temporary name. Secure that inode
 * before truncation, then publish its 0600 replacement with the existing rename. */
#include "private_dac.h"
#include <cerrno>
#include <cstdio>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

static bool write_all(int fd, const char *text, size_t size) {
    while (size) {
        const auto count = write(fd, text, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        text += count;
        size -= count;
    }
    return true;
}

extern "C" bool maplesu_private_allowlist_save(
        const std::string *path, const std::vector<std::string> *apps) {
    const std::string temporary = *path + ".tmp";
    const int fd = maplesu_private_file_open(temporary.c_str(), 0);
    if (fd < 0) return false;
    bool valid = ftruncate(fd, 0) == 0;
    for (const auto &app : *apps) {
        if (!valid) break;
        if (!app.empty()) valid = write_all(fd, app.data(), app.size()) && write_all(fd, "\n", 1);
    }
    if (valid) valid = fsync(fd) == 0;
    if (close(fd)) valid = false;
    if (valid) valid = rename(temporary.c_str(), path->c_str()) == 0;
    if (valid) sync();
    if (!valid) unlink(temporary.c_str());
    return valid;
}
