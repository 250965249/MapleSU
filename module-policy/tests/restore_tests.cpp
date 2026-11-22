// Real parser/serializer/transaction tests; selinuxfs writes target fixture files only.
#define main policy_cli_main
#include "../src/main.cpp"
#undef main
#include <array>
#include <cassert>
#include <cstdarg>
#include "kernel_policy_gate.h"

extern "C" int maplesu_environment_policy_start(const char*);
static unsigned credential_assignments;
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char* key) {
    assert(key && strlen(key) == 32);
    ++credential_assignments;
}

static std::string fixture_root;
static int load_fd = -1, loads;
static bool fail_load, changed_readback;
// Model the native successful-reload observables at the actual selinuxfs write
// boundary. Rejected standard transactions must reach none of these effects.
static std::array<unsigned, 4> reload_observables{16, 5, 5, 0};
extern "C" int __real_open(const char *, int, ...);
extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" int __real_close(int);
extern "C" int __wrap_close(int fd) {
    if (fd == load_fd) load_fd = -1;
    return __real_close(fd);
}
extern "C" int __wrap_open(const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    std::string path(name);
    if (path == LIVE) path = fixture_root + "/live";
    else if (path == LOAD) path = fixture_root + "/load";
    else if (path == ENFORCE) path = fixture_root + "/enforce";
    else if (path == "/data/adb/maplesu-policy.lock") path = fixture_root + "/lock";
    else if (path == "/data") path = fixture_root + "/data";
    int fd = __real_open(path.c_str(), flags, mode);
    if (!strcmp(name, LOAD)) load_fd = fd;
    return fd;
}
extern "C" ssize_t __wrap_write(int fd, const void *data, size_t size) {
    if (fd != load_fd) return __real_write(fd, data, size);
    ++loads;
    if (fail_load) { errno = EIO; return -1; }
    reload_observables[0] += 2; // status.sequence
    ++reload_observables[1]; // status.policyload
    ++reload_observables[2]; // access av_decision.seqno
    ++reload_observables[3]; // policyload notification
    auto bytes = std::vector<char>(static_cast<const char *>(data), static_cast<const char *>(data) + size);
    if (changed_readback) {
        auto policy = decode(bytes);
        apply_rule(*policy, {"fixture", "allow system_server system_server process execmem", 1});
        bytes = encode(*policy);
    }
    int live = __real_open((fixture_root + "/live").c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
    assert(live >= 0 && __real_write(live, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()));
    close(live);
    return __real_write(fd, data, size);
}
static int command(std::initializer_list<const char *> args) {
    std::vector<char *> argv;
    for (const char *arg : args) argv.push_back(const_cast<char *>(arg));
    return policy_cli_main(argv.size(), argv.data());
}
int main(int argc, char **argv) {
    setbuf(stdout, nullptr);
    assert(argc == 3);
    fixture_root = argv[2];
    assert(mkdir(fixture_root.c_str(), 0700) == 0);
    assert(mkdir((fixture_root + "/data").c_str(), 0700) == 0);
    auto bytes = read_file(argv[1]);
    auto baseline = decode(bytes);
    apply_rule(*baseline, {"fixture", "deny system_server system_server process execmem", 1});
    auto clean = encode(*baseline);
    std::string backup = fixture_root + "/backup";
    save(backup, clean);
    apply_rule(*baseline, {"fixture", "allow system_server system_server process execmem", 1});
    apply_rule(*baseline, {"fixture", "permissive system_server", 2});
    auto modified = encode(*baseline);
    save(fixture_root + "/live", modified);
    save(fixture_root + "/enforce", {'1', '\n'});
    save(fixture_root + "/load", {});
    int result = command({"maplesu-policy", "restore", "--policy", backup.c_str()});
    auto restored_bytes = read_file(fixture_root + "/live");
    auto restored = decode(restored_bytes), expected = decode(clean);
    if (result != 0 || loads != 1 || !policy_equivalent(*expected, *restored)) {
        puts("FAIL: full restore did not load and verify the saved pre-host policy");
        return 1;
    }
    puts("PASS: restore removes real fixture changes and verifies the complete policy image");
    assert(command({"maplesu-policy", "restore"}) != 0 && loads == 1);
    assert(command({"maplesu-policy", "restore", "--policy", backup.c_str(), "--rules", backup.c_str()}) != 0 && loads == 1);
    puts("PASS: restore rejects a missing backup and extra rule mutation");
    save(backup, {'b', 'a', 'd'});
    assert(command({"maplesu-policy", "restore", "--policy", backup.c_str()}) != 0 && loads == 1);
    save(backup, clean);
    assert(command({"maplesu-policy", "restore", "--policy", "/missing-backup"}) != 0 && loads == 1);
    assert(command({"maplesu-policy", "restore", "--policy", backup.c_str(), "--output", backup.c_str()}) != 0 && loads == 1);
    puts("PASS: invalid or missing backup never reaches the load node");
    {
        Fd held(open("/data/adb/maplesu-policy.lock", O_RDWR | O_CLOEXEC));
        assert(held.value >= 0 && flock(held.value, LOCK_EX | LOCK_NB) == 0);
        assert(command({"maplesu-policy", "restore", "--policy", backup.c_str()}) == 75 && loads == 1);
    }
    puts("PASS: an overlapping policy transaction returns busy without a write");
    fail_load = true;
    assert(command({"maplesu-policy", "restore", "--policy", backup.c_str()}) != 0 && loads == 2);
    fail_load = false;
    changed_readback = true;
    assert(command({"maplesu-policy", "restore", "--policy", backup.c_str()}) == 3 && loads == 3);
    puts("PASS: write failure and mismatched readback never report successful restore");
    assert(read_file(fixture_root + "/enforce")[0] == '1');
    puts("PASS: enforcing state stays unchanged");
    const int unready_loads = loads;
    auto strict_blocked = [&] {
        const auto before = reload_observables;
        assert(command({"maplesu-policy", "apply", "--require-boot-policy"}) == 77);
        assert(command({"maplesu-policy", "apply", "--require-boot-policy", "--rules",
            "/source/zygisk/module/sepolicy.rule"}) == 77);
        assert(command({"maplesu-policy", "restore", "--require-boot-policy", "--policy", backup.c_str()}) == 77);
        assert(loads == unready_loads);
        assert(reload_observables == before);
    };
    strict_blocked();
    puts("PASS: Ultra transactions with no backend directory never load even real host rules");
    using namespace maplesu::module_policy;
    assert(mkdir((fixture_root + "/data/adb").c_str(), 0700) == 0);
    auto settings = Store::open(true);
    auto boot = current_boot_id();
    {
        const auto original = fixture_root;
        fixture_root += "/fresh-hook";
        assert(mkdir(fixture_root.c_str(), 0700) == 0);
        assert(mkdir((fixture_root + "/data").c_str(), 0700) == 0);
        assert(command({"maplesu-policy", "prepare-hook"}) == 0);
        struct stat directory{};
        assert(stat((fixture_root + "/data/adb").c_str(), &directory) == 0);
        assert(directory.st_uid == 0 && (directory.st_mode & 0777) == 0700);
        assert(Store::open(false).read(boot).effective->mode == Mode::Block);
        assert(command({"maplesu-policy", "config-hook", "1"}) == 0);
        assert(Store::open(false).read(boot).effective->mode == Mode::Load);
        fixture_root = original;
    }
    puts("PASS: a fresh temporary Root session prepares its own root-only /data/adb without boot installation");
    strict_blocked();
    settings.publish({Mode::Load, 3, "11111111-2222-3333-4444-555555555555"});
    strict_blocked();
    puts("PASS: missing records and another boot's Load record never satisfy Ultra readiness");
    // Exercise the real boot entry, Store and gate instead of inventing readiness.
    assert(maplesu_environment_policy_start("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0);
    assert(credential_assignments == 1 && settings.read(boot).effective);
    assert(settings.read(boot).effective->mode == Mode::Block);
    assert(maplesu_environment_policy_start("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0);
    assert(credential_assignments == 2 && settings.read(boot).effective->mode == Mode::Block);
    puts("PASS: default Block boot entry publishes readiness without suppressing native module startup");
    int previous_loads = loads;
    const auto before_block = reload_observables;
    assert(command({"maplesu-policy", "apply"}) == 77 && loads == previous_loads);
    assert(reload_observables == before_block);
    assert(command({"maplesu-policy", "apply", "--rules", "/missing-rules"}) == 77 && loads == previous_loads);
    assert(command({"maplesu-policy", "restore", "--policy", backup.c_str()}) == 77 && loads == previous_loads);
    settings.request(Mode::Load, boot);
    assert(command({"maplesu-policy", "apply"}) == 77 && loads == previous_loads);
    assert(reload_observables == before_block);
    puts("PASS: blocked boot prevents apply/restore and leaves status/access/netlink observables unchanged; requesting load waits for reboot");
    // A backend may fail after installing a subset of its hooks. The real CLI
    // must honor the durable attempt rather than falling back to legacy Load.
    assert(unlink((fixture_root + "/data/adb/maplesu/module-policy/effective").c_str()) == 0);
    assert(unlink((fixture_root + "/data/adb/maplesu/module-policy/attempt").c_str()) == 0);
    try {
        settings.prepare_boot(boot, [](Mode, bool) -> unsigned { throw std::runtime_error("FIXTURE_BACKEND"); });
        assert(false);
    } catch (const std::runtime_error& error) { assert(std::string(error.what()) == "FIXTURE_BACKEND"); }
    assert(command({"maplesu-policy", "apply"}) == 77 && loads == previous_loads);
    assert(command({"maplesu-policy", "apply", "--rules", "/missing-rules"}) == 77 && loads == previous_loads);
    assert(command({"maplesu-policy", "restore", "--policy", backup.c_str()}) == 77 && loads == previous_loads);
    assert(command({"maplesu-policy", "check"}) == 0 && loads == previous_loads);
    puts("PASS: interrupted boot backend blocks every live transaction while read-only policy checks still work");
    changed_readback = false;
    for (auto mode : {Mode::Load, Mode::Hide}) {
        const auto before = reload_observables;
        settings.publish({mode, 3, boot});
        settings.request(Mode::Block, boot);
        assert(command({"maplesu-policy", "restore", "--policy", backup.c_str()}) == 0 && loads == ++previous_loads);
        assert(command({"maplesu-policy", "apply"}) == 0 && loads == ++previous_loads);
        assert(command({"maplesu-policy", "apply", "--require-boot-policy", "--rules",
            "/source/zygisk/module/sepolicy.rule"}) == 0 && loads == ++previous_loads);
        assert(command({"maplesu-policy", "restore", "--require-boot-policy", "--policy", backup.c_str()}) == 0 && loads == ++previous_loads);
        assert(reload_observables[0] == before[0] + 8 && reload_observables[1] == before[1] + 4 &&
            reload_observables[2] == before[2] + 4 && reload_observables[3] == before[3] + 4);
    }
    puts("PASS: load and hide boots preserve real transactions until the next boot even after requesting block");
    // A new standalone Hook session uses only the transaction gate, not the
    // SDK's boot-latched kernel installation. Exercise the actual CLI entry.
    for (const char* name : {"requested", "effective", "attempt", "experimental", "experimental-support", "fallback", "hook"})
        unlink((fixture_root + "/data/adb/maplesu/module-policy/" + name).c_str());
    const auto before_prepare = reload_observables;
    const auto policy_before_prepare = read_file(LIVE);
    assert(command({"maplesu-policy", "prepare-hook"}) == 0);
    assert(settings.read(boot).effective->mode == Mode::Block);
    assert(command({"maplesu-policy", "config-hook", "1"}) == 0);
    assert(settings.read(boot).requested == Mode::Load && settings.read(boot).effective->mode == Mode::Load);
    assert(command({"maplesu-policy", "prepare-hook"}) == 0);
    assert(read_file(LIVE) == policy_before_prepare && reload_observables == before_prepare);
    assert(command({"maplesu-policy", "apply", "--require-boot-policy"}) == 0 && loads == ++previous_loads);
    const auto after_hook_load = reload_observables;
    const auto loaded_policy = read_file(LIVE);
    assert(command({"maplesu-policy", "config-hook", "0"}) == 0);
    assert(settings.read(boot).requested == Mode::Block && settings.read(boot).effective->mode == Mode::Block);
    assert(command({"maplesu-policy", "apply", "--require-boot-policy"}) == 77);
    assert(command({"maplesu-policy", "config-hook", "3"}) != 0);
    assert(read_file(LIVE) == loaded_policy && reload_observables == after_hook_load && loads == previous_loads);
    {
        Fd held(open("/data/adb/maplesu-policy.lock", O_RDWR | O_CLOEXEC));
        assert(held.value >= 0 && flock(held.value, LOCK_EX | LOCK_NB) == 0);
        assert(command({"maplesu-policy", "config-hook", "1"}) != 0);
        assert(settings.read(boot).effective->mode == Mode::Block);
    }
    assert(command({"maplesu-policy", "config-hook", "1"}) == 0);
    assert(settings.read(boot).effective->mode == Mode::Load);
    puts("PASS: Hook prepare/config applies without reboot, preserves loaded policy, blocks future writes, rejects false Hide and never waits on a busy transaction");
}
