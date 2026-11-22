#include "module_err_def.h"
#include <android/log.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MAPLESU_UNINSTALL_CALLBACK_TIMEOUT_MS
#define MAPLESU_UNINSTALL_CALLBACK_TIMEOUT_MS 30000
#endif

// Pinned SDK seam: unsafe_uninstall_module calls this AFTER set_current_root(true)
// and BEFORE deleting files. Abort that SDK worker on timeout/crash so
// safe_uninstall_module gets EOF and reports failure. Completed KModErr results
// keep the SDK's existing semantics (the module's own cleanup function is void).
// The imported archive remains unchanged. CMake wraps only this exact SDK symbol.
extern KModErr original_uninstall_callback(const std::string& id)
    asm("__real_maplesu_module_uninstall_callback");
extern KModErr bounded_uninstall_callback(const std::string& id)
    asm("__wrap_maplesu_module_uninstall_callback");

namespace {
using Clock = std::chrono::steady_clock;
enum class ChildState { Running, Exited, Lost };

ChildState observe_exit(pid_t child, Clock::time_point deadline, siginfo_t& status) {
    do {
        if (waitid(P_PID, child, &status, WEXITED | WNOHANG | WNOWAIT) == 0) {
            if (status.si_pid == child) return ChildState::Exited;
        } else if (errno != EINTR) return ChildState::Lost;
        usleep(5000);
    } while (Clock::now() < deadline);
    return ChildState::Running;
}

[[noreturn]] void interrupted(const char* reason) {
    __android_log_print(ANDROID_LOG_WARN, "MapleSUUltra", "uninstall callback interrupted: %s", reason);
    _exit(125);
}
}

KModErr bounded_uninstall_callback(const std::string& id) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(MAPLESU_UNINSTALL_CALLBACK_TIMEOUT_MS);
    int fds[2];
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) interrupted("pipe failed");
    const pid_t child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        interrupted("fork failed");
    }
    if (child == 0) {
        close(fds[0]);
        if (setpgid(0, 0) != 0) _exit(125);
        try {
            const KModErr result = original_uninstall_callback(id);
            ssize_t count;
            do { count = write(fds[1], &result, sizeof(result)); } while (count < 0 && errno == EINTR);
            _exit(count == sizeof(result) ? 0 : 125);
        } catch (...) {
            _exit(125);
        }
    }
    close(fds[1]);
    // Both sides set the group before executing module code. This parent already has
    // root, so it can stop the callback and inherited descendants after elevation.
    setpgid(child, child);
    siginfo_t status{};
    auto childState = observe_exit(child, deadline, status);
    KModErr result = KModErr::ERR_READ_CHILD_ERRCODE;
    ssize_t count;
    do { count = read(fds[0], &result, sizeof(result)); } while (count < 0 && errno == EINTR);
    close(fds[0]);
    const bool completed = childState == ChildState::Exited && status.si_code == CLD_EXITED &&
        status.si_status == 0 && count == sizeof(result);
    if (!completed && childState != ChildState::Lost) {
        // WNOWAIT reserves the leader PID until group termination; PID reuse must
        // never let a cleanup signal target an unrelated process.
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
        childState = observe_exit(child, Clock::now() + std::chrono::milliseconds(500), status);
    }
    if (childState == ChildState::Exited) {
        while (waitpid(child, nullptr, WNOHANG) < 0 && errno == EINTR) {}
    }
    if (!completed) interrupted("timeout or child termination; SDK deletion not started");
    return result;
}
