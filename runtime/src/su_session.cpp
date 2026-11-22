#include "su_protocol.h"
#include <climits>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <termios.h>

namespace maplesu {
namespace {
// A gated session reports PREPARED, waits for exactly one commit byte, and only
// then releases the child that is already forked and blocked on a private pipe.
// Until that byte arrives the user command has not been executed at all, so a
// revoke, a switch-off or an identity change that lands during preparation can
// still reject the request without side effects.
constexpr char PREPARED = 'P';
constexpr char COMMIT = 'G';
constexpr char STARTED = 'R';
// Bounded wait for the authorization owner's commit. The owner commits under its
// policy lock with a single byte write, so this only has to outlast scheduling.
constexpr int COMMIT_TIMEOUT_MS = 30000;
// The child exits with this code if it was released without a commit. It never
// reaches the user command, and the value is distinct from exec failures.
constexpr int NOT_COMMITTED = 125;
constexpr size_t MAX_CHILDREN_SNAPSHOT = 1024 * 1024;

bool read_children(std::vector<pid_t>& children) {
    char path[96];
    const long tid = syscall(SYS_gettid);
    if (tid <= 0) return false;
    const int length = snprintf(path, sizeof(path), "/proc/self/task/%ld/children", tid);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(path)) return false;
    const int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return false;
    std::string contents;
    char block[4096];
    for (;;) {
        const ssize_t count = read(descriptor, block, sizeof(block));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || contents.size() + static_cast<size_t>(count) > MAX_CHILDREN_SNAPSHOT) {
            close(descriptor);
            return false;
        }
        if (count == 0) break;
        contents.append(block, static_cast<size_t>(count));
    }
    close(descriptor);
    const char* cursor = contents.c_str();
    const char* const end = cursor + contents.size();
    while (cursor < end) {
        while (cursor < end && *cursor == ' ') ++cursor;
        if (cursor == end) break;
        char* next = nullptr;
        errno = 0;
        const long value = strtol(cursor, &next, 10);
        if (errno || next == cursor || value <= 1 || value > INT_MAX ||
            (next < end && *next != ' ')) return false;
        children.push_back(static_cast<pid_t>(value));
        cursor = next;
    }
    return true;
}

void kill_and_reap_descendants() {
    for (;;) {
        std::vector<pid_t> children;
        if (!read_children(children)) {
            poll(nullptr, 0, 10);
            continue;
        }
        for (pid_t child : children) {
            if (kill(child, SIGKILL) != 0 && errno != ESRCH) continue;
        }
        bool pending = false;
        for (;;) {
            int status = 0;
            const pid_t child = waitpid(-1, &status, WNOHANG);
            if (child > 0) continue;
            if (child < 0 && errno == EINTR) continue;
            if (child < 0 && errno == ECHILD) return;
            pending = true;
            break;
        }
        if (pending || !children.empty()) poll(nullptr, 0, 10);
    }
}

void terminate_group(pid_t child, int master, int signal) {
    if (master >= 0) {
        const pid_t foreground = tcgetpgrp(master);
        if (foreground > 0 && foreground != child) kill(-foreground, signal);
    }
    kill(-child, signal);
}
bool set_window(int fd, const std::array<uint32_t, 4>& values) {
    winsize window{static_cast<unsigned short>(values[0]), static_cast<unsigned short>(values[1]),
        static_cast<unsigned short>(values[2]), static_cast<unsigned short>(values[3])};
    return ioctl(fd, TIOCSWINSZ, &window) == 0;
}
// Blocks the child until the parent writes the commit byte or closes the pipe.
// EOF (parent died, request withdrawn) is a rejection, never an implicit start.
bool await_commit(int descriptor) {
    char grant = 0;
    ssize_t count;
    do { count = read(descriptor, &grant, 1); } while (count < 0 && errno == EINTR);
    return count == 1 && grant == COMMIT;
}
}
int su_session(int control, bool gated) {
    SuRequest request;
    std::array<int, 3> descriptors{-1, -1, -1};
    if (!request.read_from(STDIN_FILENO) || !receive_fds(control, 'F', descriptors.data(), 3)) return 65;
    if (request.global_mount) {
        const int namespace_fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
        const int joined = namespace_fd < 0 ? -1 : setns(namespace_fd, CLONE_NEWNS);
        if (namespace_fd >= 0) close(namespace_fd);
        struct stat current{}, init{};
        if (joined != 0 || stat("/proc/self/ns/mnt", &current) != 0 || stat("/proc/1/ns/mnt", &init) != 0 ||
            current.st_dev != init.st_dev || current.st_ino != init.st_ino) {
            for (int fd : descriptors) close(fd);
            return 71;
        }
    }
    int master = -1, slave = -1;
    if (request.terminals) {
        master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
            if (master >= 0) close(master);
            for (int fd : descriptors) close(fd);
            return 71;
        }
        char path[128]{};
        if (ptsname_r(master, path, sizeof(path)) != 0 ||
            (slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC)) < 0 || !set_window(slave, request.window)) {
            if (slave >= 0) close(slave);
            close(master); for (int fd : descriptors) close(fd); return 71;
        }
        for (size_t i = 0; i < descriptors.size(); ++i) {
            termios attributes{};
            if ((request.terminals & (1U << i)) && tcgetattr(descriptors[i], &attributes) == 0) {
                if (tcsetattr(slave, TCSANOW, &attributes) != 0) {
                    close(slave); close(master); for (int fd : descriptors) close(fd); return 71;
                }
                break;
            }
        }
    }
    // The commit pipe exists only for a gated session. It is CLOEXEC so the user
    // command inherits nothing, and the child holds only the read end.
    int gate[2] = {-1, -1};
    if (gated && pipe2(gate, O_CLOEXEC) != 0) {
        if (slave >= 0) close(slave);
        if (master >= 0) close(master);
        for (int fd : descriptors) close(fd);
        return 71;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        if (gated) { close(gate[0]); close(gate[1]); }
        if (slave >= 0) close(slave);
        if (master >= 0) close(master);
        for (int fd : descriptors) close(fd);
        return 71;
    }
    const pid_t child = fork();
    if (child == 0) {
        close(control);
        if (gate[1] >= 0) close(gate[1]);
        if (master >= 0) close(master);
        if (gate[0] >= 0) {
            const bool granted = await_commit(gate[0]);
            close(gate[0]);
            if (!granted) _exit(NOT_COMMITTED);
        }
        if (slave >= 0) {
            if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0) _exit(71);
        } else if (setpgid(0, 0) != 0) _exit(71);
        for (size_t i = 0; i < descriptors.size(); ++i) {
            const int source = request.terminals & (1U << i) ? slave : descriptors[i];
            if (dup2(source, static_cast<int>(i)) < 0) _exit(71);
        }
        for (int fd : descriptors) if (fd > STDERR_FILENO) close(fd);
        if (slave > STDERR_FILENO) close(slave);
        if (chdir(request.directory.c_str()) != 0 || clearenv() != 0) _exit(71);
        for (const auto& variable : request.environment) {
            const size_t separator = variable.find('=');
            if (setenv(variable.substr(0, separator).c_str(), variable.c_str() + separator + 1, 1) != 0) _exit(71);
        }
        umask(0022);
        if (setgroups(0, nullptr) != 0 || setresgid(request.uid, request.uid, request.uid) != 0 ||
            setresuid(request.uid, request.uid, request.uid) != 0) _exit(71);
        for (int signal : {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP, SIGCONT, SIGWINCH, SIGPIPE})
            if (::signal(signal, SIG_DFL) == SIG_ERR) _exit(71);
        std::vector<char*> arguments;
        for (auto& argument : request.arguments) arguments.push_back(argument.data());
        arguments.push_back(nullptr);
        execv(request.executable.c_str(), arguments.data());
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (gated) close(gate[0]);
    if (slave >= 0) close(slave);
    for (int fd : descriptors) close(fd);
    if (child < 0) {
        if (gated) close(gate[1]);
        if (master >= 0) close(master);
        return 71;
    }
    // A PTY child must call setsid itself; parent setpgid would make setsid fail.
    if (master < 0 && setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) kill(child, SIGKILL);
    bool cancelled = false;
    if (gated) {
        // Report readiness without having executed anything, then wait for the
        // authorization owner's single commit byte. Every other outcome - denial,
        // EOF, a cancel byte, a timeout - withdraws the request.
        if (!write_all(control, &PREPARED, 1)) cancelled = true;
        if (!cancelled) {
            pollfd event{control, POLLIN | POLLHUP | POLLERR, 0};
            int polled;
            do { polled = poll(&event, 1, COMMIT_TIMEOUT_MS); } while (polled < 0 && errno == EINTR);
            char commit = 0;
            if (polled <= 0 || !read_all(control, &commit, 1) || commit != COMMIT) cancelled = true;
        }
        if (!cancelled && !write_all(gate[1], &COMMIT, 1)) cancelled = true;
        close(gate[1]);
        gate[1] = -1;
        if (cancelled) {
            if (master >= 0) close(master);
            terminate_group(child, -1, SIGKILL);
            kill(child, SIGKILL);
            while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
            kill_and_reap_descendants();
            close(control);
            return 137;
        }
    }
    if (!write_all(control, &STARTED, 1) || (master >= 0 && !send_fds(control, 'P', &master, 1))) cancelled = true;
    close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
    int status = 0;
    while (true) {
        if (cancelled) { terminate_group(child, master, SIGKILL); kill(child, SIGKILL); }
        siginfo_t information{};
        if (waitid(P_PID, static_cast<id_t>(child), &information, WEXITED | WNOHANG | WNOWAIT) != 0) {
            if (errno == EINTR) continue;
            terminate_group(child, master, SIGKILL); kill(child, SIGKILL); cancelled = true; break;
        }
        if (information.si_pid == child) break;
        pollfd event{control, POLLIN | POLLHUP | POLLERR, 0};
        const int polled = poll(&event, 1, 100);
        if (polled < 0) { if (errno == EINTR) continue; cancelled = true; continue; }
        if (polled == 0) continue;
        char command;
        if (!read_all(control, &command, 1)) { cancelled = true; continue; }
        if (command == 'S') {
            uint32_t signal;
            if (!read_u32(control, signal) || (signal != SIGINT && signal != SIGTERM && signal != SIGHUP &&
                signal != SIGQUIT && signal != SIGTSTP && signal != SIGCONT)) cancelled = true;
            else terminate_group(child, master, static_cast<int>(signal));
        } else if (command == 'W' && master >= 0) {
            std::array<uint32_t, 4> window{};
            for (auto& value : window) if (!read_u32(control, value) || value > 65535) cancelled = true;
            if (!cancelled && !set_window(master, window)) cancelled = true;
        } else cancelled = true;
    }
    terminate_group(child, master, SIGKILL);
    while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) { status = -1; break; } }
    kill_and_reap_descendants();
    if (master >= 0) close(master);
    close(control);
    if (cancelled) return 137;
    if (status == -1) return 71;
    return WIFEXITED(status) ? WEXITSTATUS(status) : WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 71;
}
}
