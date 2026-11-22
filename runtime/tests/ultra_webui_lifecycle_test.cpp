#include "webui_lifecycle.h"
#include <cstdio>
#include <cstring>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t manager_pid;
namespace maplesu::sdk::features::web_ui {
KModErr start_module_web_ui_server_async(const char* key, const char* id, int& port) {
    if (getpid() == manager_pid || std::strcmp(key, "fixture") != 0)
        return KModErr::ERR_MODULE_PARAM;
    if (std::strcmp(id, "error") == 0) return KModErr::ERR_MODULE_PARAM;
    if (std::strcmp(id, "crash") == 0) _exit(2);
    // Like the SDK, the server is a child and retains the creator PID. Verify
    // that creator has actually exited before the manager resumes using it.
    pid_t creator = getpid();
    pid_t server = fork();
    if (server < 0) return KModErr::ERR_MODULE_PARAM;
    if (server == 0) {
        for (int i = 0; i < 100 && getppid() == creator; ++i) usleep(1000);
        _exit(getppid() != creator ? 0 : 1);
    }
    port = server; // Fixture-only receipt identifies our adopted server.
    return KModErr::OK;
}
KModErr start_module_web_ui_server_for_manager(const char* key, const char* id, int& port,
                                              std::string& directory) {
    if (std::strcmp(id, "empty-directory") == 0) return KModErr::OK;
    if (std::strcmp(id, "oversized-directory") == 0) {
        directory.assign(128, 'x');
        return KModErr::OK;
    }
    const auto error = start_module_web_ui_server_async(key ? key : "fixture", id, port);
    if (is_ok(error)) directory = "/data/abcdefghijklmnopa/modules/fixture/";
    return error;
}
}
int main() {
    manager_pid = getpid();
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    int port = 0;
    bool passed = maplesu::start_detached_module_webui("fixture", "ok", port) == KModErr::OK;
    int status = -1;
    passed = waitpid(port, &status, 0) == port && WIFEXITED(status) && WEXITSTATUS(status) == 0 && passed;
    std::printf("creator exit and server adoption: %s\n", passed ? "PASS" : "FAIL");
    bool error = maplesu::start_detached_module_webui("fixture", "error", port) == KModErr::ERR_MODULE_PARAM;
    bool crash = maplesu::start_detached_module_webui("fixture", "crash", port) == KModErr::ERR_READ_CHILD_ERRCODE;
    std::printf("SDK error receipt: %s\nworker exit without receipt: %s\n", error ? "PASS" : "FAIL", crash ? "PASS" : "FAIL");
    std::string directory = "unchanged";
    bool manager = maplesu::start_detached_module_webui("fixture", "ok", port, directory) == KModErr::OK &&
        directory == "/data/abcdefghijklmnopa/modules/fixture/";
    status = -1;
    manager = waitpid(port, &status, 0) == port && WIFEXITED(status) && WEXITSTATUS(status) == 0 && manager;
    bool owner = maplesu::start_detached_module_webui(nullptr, "ok", port, directory) == KModErr::OK;
    status = -1;
    owner = waitpid(port, &status, 0) == port && WIFEXITED(status) && WEXITSTATUS(status) == 0 && owner;
    port = 1234;
    directory = "unchanged";
    bool invalid = maplesu::start_detached_module_webui("fixture", "empty-directory", port, directory) ==
        KModErr::ERR_READ_CHILD_DATA && port == 1234 && directory == "unchanged";
    invalid = maplesu::start_detached_module_webui("fixture", "oversized-directory", port, directory) ==
        KModErr::ERR_READ_CHILD_DATA && port == 1234 && directory == "unchanged" && invalid;
    bool manager_error = maplesu::start_detached_module_webui("fixture", "error", port, directory) ==
        KModErr::ERR_MODULE_PARAM && port == 1234 && directory == "unchanged";
    std::printf("Manager directory and creator: %s\nOwner nullable key: %s\n"
                "Invalid directory: %s\nManager SDK error: %s\n", manager ? "PASS" : "FAIL",
                owner ? "PASS" : "FAIL", invalid ? "PASS" : "FAIL", manager_error ? "PASS" : "FAIL");
    return passed && error && crash && manager && owner && invalid && manager_error ? 0 : 1;
}
