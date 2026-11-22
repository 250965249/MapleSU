// Exercise the admitted production CLI with selinuxfs writes redirected to files.
#ifndef MAPLE_POLICY_MAIN
#define MAPLE_POLICY_MAIN "../src/main.cpp"
#endif
#define main policy_cli_main
#include MAPLE_POLICY_MAIN
#undef main
#include <cassert>
#include <cstdarg>

int boot_sdk_control(int, char **) { return 99; }
int jailbreak_selinux_hide(int, char **) { return 99; }
int ksu_manager_fd(int, char **) { return 99; }
static std::string fixture;
static int load_fd = -1, loads;
static bool fail_state_write;
extern "C" int __real_open(const char *, int, ...);
extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" int __real_close(int);
extern "C" int __wrap_open(const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    std::string path(name);
    if (path == LIVE) path = fixture + "/live";
    else if (path == LOAD) path = fixture + "/load";
    else if (path == ENFORCE) path = fixture + "/enforce";
    int fd = __real_open(path.c_str(), flags, mode);
    if (!strcmp(name, LOAD)) load_fd = fd;
    return fd;
}
extern "C" int __wrap_close(int fd) {
    if (fd == load_fd) load_fd = -1;
    return __real_close(fd);
}
extern "C" ssize_t __wrap_write(int fd, const void *data, size_t size) {
    if (fd != load_fd) {
        if (fail_state_write) { errno = ENOSPC; return -1; }
        return __real_write(fd, data, size);
    }
    ++loads;
    int live = __real_open((fixture + "/live").c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
    assert(live >= 0 && __real_write(live, data, size) == static_cast<ssize_t>(size));
    close(live);
    return __real_write(fd, data, size);
}
static int command(std::initializer_list<const char *> args) {
    std::vector<char *> argv;
    for (const char *arg : args) argv.push_back(const_cast<char *>(arg));
    return policy_cli_main(argv.size(), argv.data());
}
static void put(const std::string &path, const std::string &text) {
    save(path, {text.begin(), text.end()});
}
static void pass(const char *name) { printf("{\"test\":%s,\"status\":\"passed\"}\n", quote(name).c_str()); }
int main(int argc, char **argv) {
    setbuf(stdout, nullptr);
    assert(argc == 3);
    fixture = argv[2];
    const char *policy = "/data/adb/modules/zygisk_lsposed/sepolicy.rule";
    const char *library = "/data/adb/modules/maplesu_zygisk/lib64/liblsp-shared.so";
    const std::string source = "type lsposed_file file_type\n"
        "typeattribute lsposed_file mlstrustedobject\nallow domain lsposed_file dir *\n"
        "allow domain lsposed_file file *\nallow system_server apk_data_file file execute\n";
    assert(maple_shared_file_contract(source.c_str()));
    assert(!maple_shared_file_contract((source + "type lsposed_file file_type\n").c_str()));
    assert(!maple_shared_file_contract(source.substr(source.find('\n') + 1).c_str()));
    assert(!maple_shared_file_contract((source + "allow zygote lsposed_file file execute\n").c_str()));
    assert(maple_shared_file_rule("allow zygote lsposed_file file execute") == -1);
    pass("four exact rules; missing, duplicate and unknown rules rejected");
    put(policy, source); put(library, "fixture");
    save(fixture + "/live", read_file(argv[1])); put(fixture + "/enforce", "1\n"); put(fixture + "/load", "");
    const std::string saved = fixture + "/saved";
    assert(command({"policy", "check", "--rules", policy}) == 0);
    assert(command({"policy", "save", "--rules", policy, "--output", saved.c_str()}) == 0);
    assert(access(MAPLE_SHARED_CONTEXT_STATE, F_OK) != 0 && loads == 0);
    pass("check and save preserve read-only shared-context behavior");
    assert(command({"policy", "apply", "--require-boot-policy", "--rules", policy}) == 77);
    assert(access(MAPLE_SHARED_CONTEXT_STATE, F_OK) != 0 && loads == 0);
    using namespace maplesu::module_policy;
    auto store = Store::open(true);
    const auto boot = current_boot_id();
    store.publish({Mode::Load, 3, boot});
    assert(unlink(library) == 0);
    assert(command({"policy", "apply", "--require-boot-policy", "--rules", policy}) == 0);
    assert(access(MAPLE_SHARED_CONTEXT_STATE, F_OK) != 0 && loads == 1);
    put(library, "fixture");
    assert(chmod("/data/adb/modules/zygisk_lsposed", 0770) == 0);
    assert(command({"policy", "apply", "--require-boot-policy", "--rules", policy}) == 0);
    assert(access(MAPLE_SHARED_CONTEXT_STATE, F_OK) != 0 && loads == 2);
    assert(chmod("/data/adb/modules/zygisk_lsposed", 0700) == 0);
    pass("blocked boot, missing shim and writable module never publish tuple");
    // Restore the real fixture baseline; the preceding normal policy path kept its rules.
    save(fixture + "/live", read_file(argv[1]));
    assert(command({"policy", "apply", "--require-boot-policy", "--rules", policy}) == 0);
    assert(loads == 3 && shared_context_file(policy));
    auto adapted = read_rules({policy});
    for (const auto &rule : adapted) assert(rule.text.find("lsposed_file") == std::string::npos);
    assert(adapted.size() == 2);
    pass("admitted boot apply publishes exact boot, directory identity and real shim tuple");
    for (const auto &invalid : {source + "type lsposed_file file_type\n",
            source.substr(source.find('\n') + 1), source + "allow zygote lsposed_file file execute\n"}) {
        put(policy, invalid);
        assert(command({"policy", "apply", "--require-boot-policy", "--rules", policy}) != 0 && loads == 3);
    }
    pass("existing marker rejects malformed contracts before any policy load");
    put(policy, source); assert(unlink(MAPLE_SHARED_CONTEXT_STATE) == 0);
    fail_state_write = true;
    assert(command({"policy", "apply", "--require-boot-policy", "--rules", policy}) != 0 && loads == 3);
    fail_state_write = false;
    assert(access(MAPLE_SHARED_CONTEXT_STATE, F_OK) != 0);
    pass("tuple write ENOSPC propagates and leaves no partial marker or policy load");
    assert(rmdir("/data/adb/maplesu_zygisk") == 0);
    put("/data/adb/maplesu_zygisk", "file");
    assert(command({"policy", "apply", "--require-boot-policy", "--rules", policy}) != 0 && loads == 3);
    pass("state directory failure propagates before policy load");
}
