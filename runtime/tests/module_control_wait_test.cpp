#include "maplesu_module_control.h"
#include "module_err_def.h"
#include <tuple>
#include "maplesu_sdk/maplesu_installer.h"
#include "maplesu_sdk/maplesu_module.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

static const char* scenario;
static std::string fixture;
static unsigned waits = 0;
static bool is(const char* value) { return strcmp(scenario, value) == 0; }
extern "C" void maplesu_system_directory(std::string* out) { *out = fixture; }
extern "C" void maplesu_installed_helper_path(std::string* out) { *out = fixture + "/missing-helper"; }
namespace default_modules::module_root { KModErr set_current_root(bool) { return KModErr::OK; } }
namespace maplesu::sdk {
KModErr get_root(const char*) { return KModErr::OK; }
MapleSUEnvState get_maplesu::sdkironment_state(const char*) { return MapleSUEnvState::Running; }
KModErr unsafe_get_all_modules(std::vector<module_record>&) { return KModErr::OK; }
}
extern "C" int __real_poll(pollfd*, nfds_t, int);
extern "C" int __wrap_poll(pollfd* fds, nfds_t count, int timeout) {
    assert(count == 1 && timeout == 10000);
    return __real_poll(fds, count, timeout);
}
extern "C" pid_t __real_waitpid(pid_t, int*, int);
extern "C" pid_t __wrap_waitpid(pid_t child, int* status, int flags) {
    assert(child > 0 && flags == 0);
    ++waits;
    if (is("eintr") && waits == 1) { errno = EINTR; return -1; }
    const auto result = __real_waitpid(child, status, flags);
    assert(result == child);
    if (is("echild")) { errno = ECHILD; return -1; }
    return is("mismatch") ? result + 1 : result;
}
extern "C" [[noreturn]] void __real__exit(int);
extern "C" [[noreturn]] void __wrap__exit(int status) {
    if (is("signal")) raise(SIGTERM);
    __real__exit(is("exit") ? 17 : status);
}
int main(int argc, char** argv) {
    assert(argc == 2);
    scenario = argv[1];
    char directory[] = "/tmp/maplesu-control-wait-XXXXXX";
    const char* created = mkdtemp(directory);
    assert(created);
    fixture = created;
    bool supported = true;
    const auto error = maplesu::module_control_capability("0123456789abcdef0123456789abcdef", supported);
    const bool failure = is("echild") || is("mismatch") || is("signal") || is("exit");
    unlink((fixture + "/.module-control.lock").c_str());
    rmdir(fixture.c_str());
    if (error != (failure ? maplesu::MODULE_CONTROL_IO : 0) || supported || waits != (is("eintr") ? 2u : 1u)) {
        fprintf(stderr, "FAIL module control wait %s: error=%lld supported=%d waits=%u\n",
                scenario, static_cast<long long>(error), supported, waits);
        return 1;
    }
    printf("PASS module control wait %s\n", scenario);
}
