// Characterize ordinary POSIX behavior of the actual Android platform binding.
// This does not initialize the SDK, load a backend, or access an Android device.
#define main helper_platform_program_main
#include "../src/helper/helper_platform_android.cpp"
#undef main

#include <string>

int helper_run_boot(const helper_ops*, int, char* const[]) { return 127; }

namespace {
bool interrupt_wait;
pid_t interrupted_child;
int last_wait_status;
int failures;
int checks;
void check(bool passed, const char* name) {
    ++checks;
    printf("%s %s\n", passed ? "PASS" : "FAIL", name);
    if (!passed) ++failures;
}
}

extern "C" pid_t __real_waitpid(pid_t, int*, int);
extern "C" pid_t __wrap_waitpid(pid_t child, int* status, int flags) {
    if (interrupt_wait) {
        interrupt_wait = false;
        interrupted_child = child;
        errno = EINTR;
        return -1;
    }
    const pid_t result = __real_waitpid(child, status, flags);
    if (result == child && status) last_wait_status = *status;
    return result;
}

int main() {
    char file[] = "/tmp/maplesu-helper-platform-XXXXXX";
    const int created = mkstemp(file);
    if (created < 0) return 2;
    close(created);
    const int fd = kPlatformOps.open_path(file, HELPER_OPEN_READ | HELPER_OPEN_WRITE, 0);
    check(fd >= 0, "READ|WRITE opens an existing file");
    if (fd < 0) { unlink(file); return 2; }
    const int actual_mode = fcntl(fd, F_GETFL) & O_ACCMODE;
    check(actual_mode == O_RDWR, "READ|WRITE maps to O_RDWR");
    check(kPlatformOps.write(fd, "1", 1) == 1, "READ|WRITE descriptor accepts write");
    check(kPlatformOps.lseek(fd, 0, SEEK_SET) == 0, "READ|WRITE descriptor seeks");
    char value = 0;
    const auto read_result = kPlatformOps.read(fd, &value, 1);
    check(read_result == 1 && value == '1', "READ|WRITE descriptor accepts read after write");
    const int readonly = kPlatformOps.open_path(file, HELPER_OPEN_READ, 0);
    value = 0;
    check(readonly >= 0 && (fcntl(readonly, F_GETFL) & O_ACCMODE) == O_RDONLY &&
              kPlatformOps.read(readonly, &value, 1) == 1 && value == '1',
          "read-only mode remains readable");
    if (readonly >= 0) kPlatformOps.close(readonly);
    const int lock_peer = kPlatformOps.open_path(file, HELPER_OPEN_WRITE, 0);
    check(lock_peer >= 0 && (fcntl(lock_peer, F_GETFL) & O_ACCMODE) == O_WRONLY,
          "write-only mode remains write-only");
    check(kPlatformOps.flock_dir(fd, HELPER_LOCK_EX | HELPER_LOCK_NB) == 0,
          "ordinary file accepts exclusive nonblocking lock");
    check(lock_peer >= 0 && kPlatformOps.flock_dir(lock_peer, HELPER_LOCK_EX | HELPER_LOCK_NB) == HELPER_E_AGAIN,
          "separate descriptor observes conflicting lock");
    check(kPlatformOps.flock_dir(fd, HELPER_LOCK_UN) == 0 && lock_peer >= 0 &&
              kPlatformOps.flock_dir(lock_peer, HELPER_LOCK_EX | HELPER_LOCK_NB) == 0,
          "unlock permits peer acquisition");
    if (lock_peer >= 0) kPlatformOps.close(lock_peer);
    kPlatformOps.close(fd);
    unlink(file);
    printf("OBSERVED accessMode=%d expectedMode=%d readResult=%lld\n",
           actual_mode, O_RDWR, read_result);

    char output[128];
    helper_u32 length = 0;
    int status = -1;
    const int normal = kPlatformOps.run_shell("printf normal", output, sizeof(output), &length, &status);
    check(normal == 0 && status == 0 && length == 6 && !memcmp(output, "normal", 6),
          "ordinary shell output and exit status are captured");

    interrupt_wait = true;
    length = 0; status = -1; last_wait_status = 0;
    const int interrupted = kPlatformOps.run_shell("printf retry", output, sizeof(output), &length, &status);
    check(interrupted == 0 && status == 0, "run_shell retries waitpid after EINTR");
    if (interrupted_child > 0) {
        int child_status = 0;
        pid_t reaped;
        do { reaped = __real_waitpid(interrupted_child, &child_status, 0); }
        while (reaped < 0 && errno == EINTR);
        check(reaped < 0 && errno == ECHILD, "interrupted wait leaves no child for caller to reap");
        printf("OBSERVED interruptedResult=%d separatelyReaped=%d\n", interrupted, reaped > 0);
    }

    length = 0; status = -1;
    const int large = kPlatformOps.run_shell(
        "i=0; while [ \"$i\" -lt 1024 ]; do printf '%01024d' 0 || exit 23; i=$((i+1)); done",
        output, sizeof(output), &length, &status);
    check(large == 0 && status == 0 && length == sizeof(output),
          "capture limit drains remaining output without changing child success");
    printf("OBSERVED largeResult=%d largeStatus=%d stored=%u capacity=%zu childSignal=%d\n",
           large, status, length, sizeof(output),
           WIFSIGNALED(last_wait_status) ? WTERMSIG(last_wait_status) : 0);

    length = 0; status = -1;
    const int ignored = kPlatformOps.run_shell("printf ignored", nullptr, 0, &length, &status);
    check(ignored == 0 && status == 0 && length == 0,
          "zero capture capacity drains output and preserves success");
    length = 0; status = -1;
    const int nonzero = kPlatformOps.run_shell("printf failure; exit 23", output, sizeof(output), &length, &status);
    check(nonzero == 0 && status == 23 && length == 7 && !memcmp(output, "failure", 7),
          "ordinary nonzero shell status is preserved");
    length = 0; status = 0;
    const int signaled = kPlatformOps.run_shell("printf before; kill -TERM $$", output, sizeof(output), &length, &status);
    check(signaled == 0 && status == -1 && length == 6 && WIFSIGNALED(last_wait_status) &&
              WTERMSIG(last_wait_status) == SIGTERM,
          "deliberately signaled child retains the existing status convention");
    printf("helper platform checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
