#include "rootkit_command.h"
#include "rootkit_parasite_app.h"
#include "rootkit_process64_inject.h"
#include "rootkit_process_cmdline_utils.h"
#include "su_protocol.h"
#include "compat/command_inputs.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <poll.h>
#include <sched.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>


namespace {
int fail(int code, const char* reason) {
    std::fprintf(stderr, "maplesu-runtime: %s\n", reason);
    return code;
}

bool read_exact(void* data, size_t size) {
    auto* out = static_cast<unsigned char*>(data);
    while (size) {
        const ssize_t count = read(STDIN_FILENO, out, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        out += count;
        size -= static_cast<size_t>(count);
    }
    return true;
}

bool read_key(std::array<char, 49>& key) {
    // Bounded frame: four-byte big-endian length, then 48 alphanumeric bytes.
    // Remaining stdin belongs to the command. No key is accepted via argv/env.
    std::array<unsigned char, 4> size{};
    if (!read_exact(size.data(), size.size()) ||
        size != std::array<unsigned char, 4>{0, 0, 0, 48}) return false;
    if (!read_exact(key.data(), 48)) return false;
    for (size_t i = 0; i < 48; ++i) {
        const char c = key[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9'))) return false;
    }
    return true;
}

void clear_key(std::array<char, 49>& key) {
    // Clear this wrapper's buffer; upstream also creates a temporary std::string.
    volatile char* out = key.data();
    for (size_t i = 0; i < key.size(); ++i) out[i] = 0;
}

/*
 * Persistent `su` PATH wiring for one authorised application.
 *
 * <p>This is the upstream Lite primitive, not a reimplementation: the imported static
 * library patches one of the target's own JNI libraries to gain a DT_NEEDED entry for a
 * side library it writes next to it, and that side library prepends the published `su`
 * directory to PATH in a constructor. Only processes of that one application therefore
 * resolve a bare `su`; every other application is untouched.
 *
 * <p>The credential arrives on stdin in the same 4+48 frame the rest of this binary
 * uses, is never placed in argv or the environment, and is cleared before returning.
 * Authorisation is decided by the caller (Manager) before this runs; this process only
 * performs the implant it was told to perform.
 */
int wire_precheck(const char* target_cmdline) {
    std::array<char, 49> key{};
    if (!read_key(key)) return fail(65, "credential frame required");
    std::map<std::string, kernel_root::AppDynlibStatus> libraries;
    const KRootErr status =
        kernel_root::parasite_precheck_app(key.data(), target_cmdline, libraries);
    clear_key(key);
    if (!is_ok(status)) {
        std::fprintf(stderr, "maplesu-runtime: precheck rejected code=%d\n",
            static_cast<int>(status));
        return 66;
    }
    for (const auto& [path, state] : libraries)
        std::printf("%d %s\n", static_cast<int>(state), path.c_str());
    return 0;
}

int wire_implant(const char* target_cmdline, const char* library, const char* su_directory) {
    std::array<char, 49> key{};
    if (!read_key(key)) return fail(65, "credential frame required");
    const KRootErr status = kernel_root::parasite_implant_su_env(
        key.data(), target_cmdline, library, su_directory);
    clear_key(key);
    if (!is_ok(status)) {
        std::fprintf(stderr, "maplesu-runtime: implant rejected code=%d\n",
            static_cast<int>(status));
        return 67;
    }
    std::printf("WIRED:%s\n", library);
    return 0;
}

/*
 * H4：对已运行的目标进程植入"普通 App 寄生 so"（`parasite_implant_app`）。
 *
 * 与 wire_implant 相同：凭证从 stdin 的 4+48 帧读取，绝不进 argv/env，返回前清零；
 * 成功 stdout `IMPLANTED:<so 绝对路径>`，被 SDK 拒绝时 stderr 诊断 + exit 68。
 * 该子命令与 `--wire-su-precheck` / `--wire-su-env` 一起只服务 Lite(A) 运行端。
 */
int wire_implant_app(const char* target_cmdline, const char* library) {
    std::array<char, 49> key{};
    if (!read_key(key)) return fail(65, "credential frame required");
    const KRootErr status = kernel_root::parasite_implant_app(
        key.data(), target_cmdline, library);
    clear_key(key);
    if (!is_ok(status)) {
        std::fprintf(stderr, "maplesu-runtime: implant app rejected code=%d\n",
            static_cast<int>(status));
        return 68;
    }
    std::printf("IMPLANTED:%s\n", library);
    return 0;
}

/** Monotonic milliseconds, used to bound waiting. */
long long monotonic_ms() {
    // Bounded waiting only; wall clock jumps must not shorten a wait.
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

/*
 * Every process of one package.
 *
 * <p>The upstream lookup compares the whole first command-line argument, so it only ever
 * finds the main process: a private process is `package:name`, a different string. Reading
 * the map once and matching the prefix here is what lets a single call cover every process
 * the package runs - a WebUI, a `:remote` service, a sandboxed child - while the exact
 * match stays a subset of it.
 */
std::set<pid_t> package_processes(const char* key, const char* package) {
    std::map<pid_t, std::string> all;
    std::set<pid_t> found;
    if (is_failed(kernel_root::get_all_cmdline_process(key, all, false))) return found;
    const std::string name(package);
    for (const auto& [pid, cmdline] : all) {
        if (cmdline == name) {
            found.insert(pid);
        } else if (cmdline.size() > name.size() && cmdline.compare(0, name.size(), name) == 0 &&
                   cmdline[name.size()] == ':') {
            found.insert(pid);
        }
    }
    return found;
}

int inject_path(const char* target_cmdline, const char* directory, int wait_ms) {
    std::array<char, 49> key{};
    if (!read_key(key)) return fail(65, "credential frame required");
    std::set<pid_t> targets;
    const long long deadline = monotonic_ms() + wait_ms;
    // A process that was only just asked for does not exist yet. Waiting here instead of
    // failing turns "the grant arrived one second too early" into a success.
    while (true) {
        targets = package_processes(key.data(), target_cmdline);
        if (!targets.empty() || monotonic_ms() >= deadline) break;
        usleep(100 * 1000);
    }
    if (targets.empty()) {
        clear_key(key);
        std::fprintf(stderr, "maplesu-runtime: no process for %s\n", target_cmdline);
        return 68;
    }
    // The three upstream offset strategies, in order: the first normally works, the others
    // cover a build where the libc file under the APEX cannot be read (OnlyReadSelfMem) or
    // where the target maps a libc instance this process does not share (OnlyReadFile).
    static constexpr kernel_root::ApiOffsetReadMode modes[] = {
        kernel_root::ApiOffsetReadMode::ReadAll,
        kernel_root::ApiOffsetReadMode::OnlyReadSelfMem,
        kernel_root::ApiOffsetReadMode::OnlyReadFile,
    };
    static const char* const mode_names[] = {"read-all", "self-mem", "libc-file"};
    int injected = 0;
    int last = 0;
    int mode_used[3] = {0, 0, 0};
    for (const pid_t pid : targets) {
        KRootErr status = KRootErr::ERR_INJECT_PROC64_ENV;
        int used = -1;
        // One retry: a process that has just forked out of zygote can refuse while its
        // linker is still setting up, and the same call succeeds a moment later.
        for (int attempt = 0; attempt < 2 && used < 0; ++attempt) {
            for (int index = 0; index < 3; ++index) {
                status = kernel_root::inject_process_env64_PATH_wrapper(
                    key.data(), static_cast<int>(pid), directory, modes[index]);
                if (is_ok(status)) {
                    used = index;
                    break;
                }
            }
            if (used < 0 && attempt == 0) usleep(60 * 1000);
        }
        if (used >= 0) {
            ++injected;
            ++mode_used[used];
            std::printf("TARGET:%d:%s\n", static_cast<int>(pid), mode_names[used]);
        } else {
            last = static_cast<int>(status);
            std::fprintf(stderr, "maplesu-runtime: pid %d rejected code=%d\n",
                static_cast<int>(pid), last);
        }
    }
    clear_key(key);
    if (injected == 0) {
        std::fprintf(stderr, "maplesu-runtime: injection rejected code=%d\n", last);
        return 69;
    }
    std::printf("INJECTED:%d\n", injected);
    std::printf("MODES:%d:%d:%d\n", mode_used[0], mode_used[1], mode_used[2]);
    return 0;
}

int inherited_control() {
    // The JNI launcher explicitly dup2s one connected socketpair endpoint to 3.
    // No name, bind, listen or rendezvous file is registered for a session.
    constexpr int control = 3;
    ucred peer{};
    socklen_t size = sizeof(peer);
    int type = 0;
    socklen_t type_size = sizeof(type);
    sockaddr address{};
    socklen_t address_size = sizeof(address);
    if (getsockopt(control, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
        peer.uid != getuid() || getsockopt(control, SOL_SOCKET, SO_TYPE, &type, &type_size) != 0 ||
        type != SOCK_STREAM || getpeername(control, &address, &address_size) != 0 ||
        address.sa_family != AF_UNIX || fcntl(control, F_SETFD, FD_CLOEXEC) != 0) {
        close(control);
        return -1;
    }
    // Consume the parent handshake before authenticating or parsing a request.
    char accepted = 0;
    ssize_t count;
    do { count = read(control, &accepted, 1); } while (count < 0 && errno == EINTR);
    if (count != 1 || accepted != 'A') { close(control); return -1; }
    return control;
}

int supervised_exec(int control, char** command) {
    const pid_t child = fork();
    if (child < 0) return fail(71, "session fork failed");
    if (child == 0) {
        close(control);
        if (setpgid(0, 0) != 0) _exit(71);
        execv(command[0], command);
        _exit(errno == ENOENT ? 127 : 126);
    }
    // Both sides set the group to avoid a cancellation race before the child's first instruction.
    if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
        kill(child, SIGKILL);
    }
    if (send(control, "R", 1, MSG_NOSIGNAL) != 1) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    int status = 0;
    bool cancelled = false;
    while (true) {
        siginfo_t exited{};
        const int waited = waitid(P_PID, static_cast<id_t>(child), &exited, WEXITED | WNOHANG | WNOWAIT);
        if (waited == 0 && exited.si_pid == child) {
            // The unreaped leader keeps its ID reserved while we terminate remaining group members.
            kill(-child, SIGKILL);
            while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) break; }
            break;
        }
        if (waited < 0) {
            if (errno == EINTR) continue;
            kill(-child, SIGKILL);
            close(control);
            return 71;
        }
        pollfd event{control, POLLIN | POLLHUP | POLLERR, 0};
        const int result = poll(&event, 1, 100);
        if (result < 0 && errno == EINTR) continue;
        if (result != 0) {
            // Any control byte, EOF, or broken owner connection cancels this command group.
            kill(-child, SIGKILL);
            cancelled = true;
        }
        if (cancelled) {
            while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) break; }
            break;
        }
    }
    close(control);
    if (cancelled) return 137;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 71;
}
} // namespace

int main(int argc, char** argv) {
    // Authorised-application wiring. Not an execution mode: it creates no root
    // session and serves no caller. The credential arrives on stdin, and the Manager
    // only reaches these paths after its own grant check.
    if (argc == 3 && std::strcmp(argv[1], "--wire-su-precheck") == 0)
        return wire_precheck(argv[2]);
    if (argc == 4 && std::strcmp(argv[1], "--implant-app") == 0)
        return wire_implant_app(argv[2], argv[3]);
    if (argc >= 4 && std::strcmp(argv[1], "--inject-path") == 0) {
        // Optional fourth argument: how long to wait for the process to exist.
        int wait_ms = argc >= 5 ? std::atoi(argv[4]) : 3000;
        if (wait_ms < 0) wait_ms = 0;
        return inject_path(argv[2], argv[3], wait_ms);
    }
    if (argc == 5 && std::strcmp(argv[1], "--wire-su-env") == 0)
        return wire_implant(argv[2], argv[3], argv[4]);
    // Direct admission: the caller already holds the delivered credential, so no
    // resident verifier, Binder endpoint or root service participates. This is the
    // shape a self-sufficient client uses after the non-resident migration.
    if (argc >= 4 && std::strcmp(argv[1], "--direct-stdin") == 0 &&
        std::strcmp(argv[2], "--") == 0 && argv[3][0] == '/') {
        std::array<char, 49> key{};
        if (!read_key(key)) return fail(65, "credential frame required");
        const KRootErr status = kernel_root::get_root(key.data());
        clear_key(key);
        if (!is_ok(status)) return fail(70, "credential rejected");
        if (getuid() != 0 || geteuid() != 0) return fail(70, "credential did not grant root");
        execv(argv[3], argv + 3);
        return fail(66, "exec failed");
    }
    if (argc < 4 || std::strcmp(argv[2], "--") != 0 || argv[3][0] != '/')
        return fail(64, "usage: --maplesu-stdin|--maplesu-global-stdin|--maplesu-session-stdin|--maplesu-su-stdin|--unprivileged -- /absolute/program [args...]");
    const bool su = (std::strcmp(argv[1], "--maplesu-su-stdin") == 0 || std::strcmp(argv[1], maplesu::compat::command_inputs::kSuStdin) == 0);
    const bool root_su = std::strcmp(argv[1], "--root-su") == 0;
    const bool root_session = std::strcmp(argv[1], "--root-session") == 0;
    const bool root_global_session = std::strcmp(argv[1], "--root-global-session") == 0;
    const bool session = su || (std::strcmp(argv[1], "--maplesu-session-stdin") == 0 || std::strcmp(argv[1], maplesu::compat::command_inputs::kSessionStdin) == 0);
    const bool global = (std::strcmp(argv[1], "--maplesu-global-stdin") == 0 || std::strcmp(argv[1], maplesu::compat::command_inputs::kGlobalStdin) == 0);
    const bool maplesu = session || global || (std::strcmp(argv[1], "--maplesu-stdin") == 0 || std::strcmp(argv[1], maplesu::compat::command_inputs::kStdin) == 0);
    if (!maplesu && !root_su && !root_session && !root_global_session && std::strcmp(argv[1], "--unprivileged") != 0)
        return fail(64, "unknown execution mode");
    if (root_su || root_session || root_global_session) {
        if (getuid() != 0 || geteuid() != 0) return fail(70, "root session owner required");
        const int root_control = inherited_control();
        if (root_control < 0) return fail(65, "invalid root session control connection");
        if (root_global_session) {
            // Only this separately spawned executor joins init's namespace.
            const int mount_namespace = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
            if (mount_namespace < 0) return fail(71, "global mount namespace open failed");
            const int joined = setns(mount_namespace, CLONE_NEWNS);
            close(mount_namespace);
            if (joined != 0) return fail(71, "global mount namespace join failed");
        }
        // A restricted su request runs behind the authorization owner's commit gate:
        // prepare, report PREPARED, wait for G, and only then execute. The owner's
        // single commit byte is the linearization point of the admission decision.
        return root_su ? maplesu::su_session(root_control, /*gated=*/true)
                       : supervised_exec(root_control, argv + 3);
    }
    // A pre-existing root identity would make get_root's UID check inconclusive.
    if (getuid() == 0 || geteuid() == 0 || getuid() != geteuid() || getgid() != getegid())
        return fail(70, "requires an ordinary, unchanged caller identity");
    int control = -1;
    if (maplesu) {
        std::array<char, 49> key{};
        if (!read_key(key)) {
            clear_key(key);
            return fail(65, "invalid credential frame");
        }
        if (session) {
            control = inherited_control();
            if (control < 0) {
                clear_key(key);
                return fail(65, "invalid session control connection");
            }
        }
        const auto result = kernel_root::get_root(key.data());
        clear_key(key);
        if (result != KRootErr::OK || getuid() != 0 || geteuid() != 0)
            return fail(69, "MapleSU credential was not accepted");
        if (global) {
            const int mount_namespace = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
            if (mount_namespace < 0) return fail(71, "global mount namespace open failed");
            const int joined = setns(mount_namespace, CLONE_NEWNS);
            close(mount_namespace);
            if (joined != 0) return fail(71, "global mount namespace join failed");
        }
        // get_root ignores SIGPIPE internally; commands receive normal exec semantics.
        if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
            return fail(71, "signal setup failed");
    }
    // Legacy internal mode: the caller already proved possession of the credential
    // frame on stdin, so this session is not the third-party admission path.
    if (su) return maplesu::su_session(control, /*gated=*/false);
    if (session) return supervised_exec(control, argv + 3);
    // execv preserves argv, cwd, environment, stdio and actual command exit status.
    // No popen, su fallback, shell interpolation, or success response before exec.
    execv(argv[3], argv + 3);
    const int error = errno;
    return fail(error == ENOENT ? 127 : 126, "command exec failed");
}
