#include "backend_publish.h"
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_root.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

// The production shell prepares this tree before the production native writer
// uses it. Only kernel authorization and SELinux xattrs are host boundaries.
namespace maplesu::sdk {
KModErr get_root(const char*) { return KModErr::OK; }
}
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" ssize_t __real_fgetxattr(int, const char*, void*, size_t);
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* data, size_t size, int flags) {
    assert(strcmp(name, "security.selinux") == 0);
    return __real_fsetxattr(fd, "user.maplesu.selinux", data, size, flags);
}
extern "C" ssize_t __wrap_fgetxattr(int fd, const char* name, void* data, size_t size) {
    assert(strcmp(name, "security.selinux") == 0);
    return __real_fgetxattr(fd, "user.maplesu.selinux", data, size);
}

int main() {
    unsigned char bytes[1024]{};
    memcpy(bytes, "\177ELF\2\1", 6);
    bytes[16] = 3;
    bytes[18] = 183;
    const auto result = maplesu::module_policy::publish_backend(
        "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", bytes, sizeof(bytes));
    struct stat st{};
    assert(stat("/fixture/adb", &st) == 0);
    printf("MAPLESU_BACKEND_PREPARATION:result=%lld adb_mode=%o\n",
           static_cast<long long>(result), st.st_mode & 07777);
    return result == 0 ? 0 : 1;
}
