#include "module_err_def.h"
#include "maplesu_sdk/maplesu_su_auth.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace default_modules::module_su_redirect {
KModErr add_su_allowlist(const char*);
KModErr remove_su_allowlist(const char*);
}
static constexpr const char* key = "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345";
static constexpr const char* directory = "/data/ABCDEFGHIJKLMNOPA";
static constexpr const char* helper = "/data/ABCDEFGHIJKLMNOPA/su";
static constexpr const char* context = "u:object_r:system_file:s0";
static std::map<ino_t, std::string> labels;
static std::string scenario;
static bool changed = false;
static unsigned relabels = 0;

// Replay the report's SELinux labels at the xattr boundary. Files, descriptor
// checks and the complete production grant transaction run on the host.
extern "C" ssize_t __wrap_fgetxattr(int fd, const char* name, void* out, size_t size) {
    assert(strcmp(name, "security.selinux") == 0);
    struct stat st{}; assert(fstat(fd, &st) == 0);
    const auto& label = labels[st.st_ino];
    if (label.empty()) { errno = ENODATA; return -1; }
    if (size < label.size() + 1) { errno = ERANGE; return -1; }
    memcpy(out, label.c_str(), label.size() + 1);
    return label.size() + 1;
}
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* data, size_t size, int flags) {
    assert(strcmp(name, "security.selinux") == 0 && flags == 0);
    assert(size == strlen(context) + 1 && strcmp(static_cast<const char*>(data), context) == 0);
    ++relabels;
    if (scenario == "relabel_denied") { errno = EACCES; return -1; }
    struct stat st{}; assert(fstat(fd, &st) == 0);
    if (scenario != "bad_readback") labels[st.st_ino] = context;
    return 0;
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return key; }
namespace maplesu::sdk { KModErr get_root(const char*) { return KModErr::OK; } }
namespace kernel_module {
KModErr read_uint64_disk_storage(const char*, uint64_t& out) { out = 1; return KModErr::OK; }
KModErr read_kernel_mem(uint64_t, void* out, uint32_t) { *static_cast<uint64_t*>(out) = 2; return KModErr::OK; }
KModErr write_kernel_rw_mem_atomic64(uint64_t, uint64_t) { return KModErr::OK; }
}
extern "C" KModErr maplesu_write_su_allowlist(const std::vector<std::string>&, const char*, bool) {
    changed = true; return KModErr::OK;
}
extern "C" KModErr maplesu_sdk_add_su_allowlist(const char*) { changed = true; return KModErr::OK; }
extern "C" KModErr maplesu_sdk_remove_su_allowlist(const char*) { changed = true; return KModErr::OK; }
extern "C" KModErr maplesu_sdk_clear_su_allowlist() { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_get_su_allowlist(void (*)(const maplesu::sdk::su_auth_item*)) { return KModErr::OK; }

int main(int argc, char** argv) {
    assert(argc == 2); scenario = argv[1];
    assert(mkdir(directory, 0755) == 0);
    if (scenario != "missing") {
        if (scenario == "symlink") assert(symlink("/bin/sh", helper) == 0);
        else {
            const int fd = open(helper, O_CREAT | O_WRONLY | O_EXCL, 0777);
            assert(fd >= 0 && write(fd, "\177ELFfixture", 11) == 11); close(fd);
            assert(chmod(helper, 0777) == 0);
            if (scenario == "foreign_owner") assert(chown(helper, 10315, 10315) == 0);
        }
    }
    struct stat ds{}, fs{}; assert(stat(directory, &ds) == 0);
    labels[ds.st_ino] = scenario == "directory_label" ? "u:object_r:system_data_file:s0" : context;
    if (lstat(helper, &fs) == 0) labels[fs.st_ino] = scenario == "already" ? context : "u:object_r:system_data_file:s0";
    if (scenario == "already") assert(chmod(helper, 0755) == 0);
    const bool revoked = scenario == "revoke";
    const auto result = revoked ? default_modules::module_su_redirect::remove_su_allowlist("target")
        : default_modules::module_su_redirect::add_su_allowlist(scenario == "refresh" ? nullptr : "target");
    const bool reject = scenario == "missing" || scenario == "symlink" || scenario == "foreign_owner" ||
        scenario == "relabel_denied" || scenario == "bad_readback";
    bool ok = reject ? is_failed(result) && !changed : !is_failed(result) && changed;
    if (!reject && !revoked) {
        assert(stat(helper, &fs) == 0);
        assert(stat(directory, &ds) == 0);
        ok = ok && labels[fs.st_ino] == context && labels[ds.st_ino] == context &&
            (fs.st_mode & 0777) == 0711 && (ds.st_mode & 0777) == 0711;
        if (scenario == "already") ok = ok && relabels == 0;
    }
    unlink(helper); assert(rmdir(directory) == 0);
    printf("%s %s grant=%s helperContext=%s\n", ok ? "PASS" : "FAIL", argv[1], changed ? "changed" : "unchanged",
        labels[fs.st_ino] == context ? "executable" : "system_data_file");
    return ok ? 0 : 1;
}
