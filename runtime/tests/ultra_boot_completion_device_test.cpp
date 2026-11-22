// Real Android files and production completion/state code, in a disposable directory.
#include "module_err_def.h"
#include <tuple>
#include "maplesu_sdk/maplesu_installer.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

static std::string helper, version;
extern "C" int maplesu_bootstrap_finish(const char*, int64_t);
extern "C" uint32_t maplesu_environment_state() noexcept;
extern "C" void maplesu_environment_paths(std::string* h, std::string* v) { *h = helper; *v = version; }
namespace default_modules::module_root {
KModErr set_current_root(bool) { return KModErr::OK; }
}
static void put(const std::string& path, const std::string& value) {
    std::ofstream out(path); out << value; out.close(); assert(out.good());
}
static std::string get(const std::string& path) {
    std::ifstream in(path); return {std::istreambuf_iterator<char>(in), {}};
}
static bool check(const char* label, unsigned expected) {
    unsigned actual = maplesu_environment_state();
    bool ok = actual == expected;
    printf("%s %s actual=%u expected=%u\n", ok ? "PASS" : "FAIL", label, actual, expected);
    return ok;
}
int main() {
    assert(getuid() == 0);
    char directory[] = "/data/local/tmp/maplesu-boot-state-XXXXXX";
    assert(mkdtemp(directory));
    helper = std::string(directory) + "/init";
    version = std::string(directory) + "/sdk.ver";
    const auto boot = get("/proc/sys/kernel/random/boot_id");
    const auto safe = helper + ".safe_flag", work = helper + ".boot_session.work";
    const auto completed = helper + ".boot_session.completed";
    put(helper, "fixture helper"); put(version, "5.1.0"); put(safe, "1");
    assert(maplesu_bootstrap_finish(safe.c_str(), 0) == 0);
    put(work, boot);
    bool ok = check("completed-current-boot", 1);
    // safe_install_module and unsafe_uninstall_module call the legacy reset,
    // which truncates this exact mutable flag after a successful boot.
    put(safe, "");
    ok &= check("native-module-reset-retains-running", 1);
    put(work, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    ok &= check("stale-work-is-unknown", 3);
    put(work, boot);
    put(completed, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    ok &= check("stale-completion-is-unknown", 3);
    put(completed, boot); put(safe, "1");
    ok &= check("incomplete-bootstrap-is-unknown", 3);
    put(safe, "3"); put(helper + ".boot_fail_protect", "");
    put(helper + ".boot_session.duplicate", boot);
    ok &= check("current-boot-protection-is-fault", 2);
    put(safe, "2"); std::filesystem::remove(completed);
    ok &= check("legacy-completed-boot-compatible", 1);
    put(safe, "");
    ok &= check("legacy-empty-marker-is-unknown", 3);
    std::filesystem::remove_all(directory);
    return ok ? 0 : 1;
}
