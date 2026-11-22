#include "module_err_def.h"
#include "maplesu_sdk/module_callback.h"
#include <chrono>
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>


// Mirrors the pinned SDK's unsafe_uninstall_module: only after the callback returns
// does it remove files, and only after that does safe_uninstall_module send a receipt.
static bool check(const char* id, bool expect_commit) {
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK) != 0) return false;
    const auto start = std::chrono::steady_clock::now();
    const pid_t worker = fork();
    if (worker == 0) {
        close(pipe_fds[0]);
        setpgid(0, 0);
        maplesu::sdk::features::callback::invoke_module_on_uninstall(id);
        const char committed = 'C';
        write(pipe_fds[1], &committed, 1);
        _exit(0);
    }
    close(pipe_fds[1]);
    if (worker < 0) { close(pipe_fds[0]); return false; }
    int status = 0;
    bool finished = false;
    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(2)) {
        if (waitpid(worker, &status, WNOHANG) == worker) { finished = true; break; }
        usleep(5000);
    }
    if (!finished) { kill(-worker, SIGKILL); kill(worker, SIGKILL); waitpid(worker, nullptr, 0); }
    char committed = 0;
    const bool got_commit = read(pipe_fds[0], &committed, 1) == 1 && committed == 'C';
    close(pipe_fds[0]);
    // Reap callback descendants adopted by this fixture; none may outlive a failure.
    bool live_descendant = false;
    for (int attempt = 0; attempt < 40; ++attempt) {
        while (waitpid(-1, nullptr, WNOHANG) > 0) {}
        if (waitpid(-1, nullptr, WNOHANG) < 0) { live_descendant = false; break; }
        live_descendant = true;
        usleep(5000);
    }
    const bool passed = finished && got_commit == expect_commit && !live_descendant &&
        (expect_commit ? WIFEXITED(status) && WEXITSTATUS(status) == 0
                       : WIFEXITED(status) && WEXITSTATUS(status) != 0);
    std::printf("%s: %s (finished=%d committed=%d descendants=%d)\n", id,
        passed ? "PASS" : "FAIL", finished, got_commit, live_descendant);
    return passed;
}

int main() {
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    bool passed = check("ok", true);
    passed = check("stall", false) && passed;
    passed = check("crash", false) && passed;
    passed = check("error", true) && passed; // Preserve the SDK's loader-error semantics.
    passed = check("descendant", false) && passed;
    passed = check("ok", true) && passed; // A failed call must release the SDK slot.
    return passed ? 0 : 1;
}
