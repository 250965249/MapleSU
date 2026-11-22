#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Candidate-only error, outside the existing SDK error range.
#define MAPLESU_ERR_BOOTSTRAP_LAUNCH (-21002L)

static void record_failure(const char* helper, const char* stage, int detail) {
    if (helper == NULL || !*helper) return;
    const int saved = errno;
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s.launch.error", helper);
    if (n > 0 && (size_t)n < sizeof(path)) {
        const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd >= 0) {
            char line[160];
            n = snprintf(line, sizeof(line), "stage=%s detail=%d pid=%ld\n", stage, detail, (long)getpid());
            if (n > 0 && (size_t)n < sizeof(line)) {
                size_t written = 0;
                while (written < (size_t)n) {
                    const ssize_t count = write(fd, line + written, (size_t)n - written);
                    if (count < 0 && errno == EINTR) continue;
                    if (count <= 0) break;
                    written += (size_t)count;
                }
                (void)fsync(fd);
            }
            (void)close(fd);
        }
    }
    errno = saved;
}

__attribute__((visibility("hidden")))
long maplesu_installer_launch_error(int stage, const char* helper) {
    record_failure(helper, stage == 1 ? "detach-fork" : "exec-fork", errno);
    return MAPLESU_ERR_BOOTSTRAP_LAUNCH;
}

__attribute__((visibility("hidden")))
int maplesu_installer_exec(const char* path, char* const argv[], char* const envp[]) {
    const int result = execve(path, argv, envp);
    const int saved = errno;
    record_failure(path, "execve", saved);
    errno = saved;
    return result;
}

__attribute__((visibility("hidden")))
pid_t maplesu_installer_wait_child(pid_t child, int* status, const char* helper) {
    if (child <= 0) {
        errno = ECHILD;
        record_failure(helper, "invalid-child", child);
        return -1;
    }
    pid_t result;
    do { result = waitpid(child, status, 0); } while (result < 0 && errno == EINTR);
    if (result != child) {
        record_failure(helper, "waitpid", result < 0 ? errno : result);
        return -1;
    }
    if (!WIFEXITED(*status) || WEXITSTATUS(*status) != 0) {
        record_failure(helper, WIFSIGNALED(*status) ? "child-signal" : "child-exit", *status);
        errno = EIO;
        return -1;
    }
    return result;
}

// Called only by the detached Boot/uninstall worker. Command completion does not
// prove that the device rebooted; failures use the existing private diagnostic.
__attribute__((visibility("hidden")))
int maplesu_installer_reboot(const char* helper) {
    FILE* process = popen("reboot", "r");
    if (process == NULL) {
        record_failure(helper, "reboot-popen", errno);
        return 127;
    }
    const int status = pclose(process);
    if (status < 0) {
        record_failure(helper, "reboot-wait", errno);
        return 127;
    }
    if (!WIFEXITED(status)) {
        record_failure(helper, "reboot-signal", status);
        return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 127;
    }
    const int code = WEXITSTATUS(status);
    if (code != 0) record_failure(helper, "reboot-exit", status);
    return code;
}
