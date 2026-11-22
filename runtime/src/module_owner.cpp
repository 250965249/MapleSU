#include "module_task_environment.h"
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Test paths are selected at compile time, never by a caller or environment.
#ifdef MAPLESU_OWNER_TEST
static constexpr char kBase[] = "/tmp/maplesu-owner-test";
static constexpr char kModules[] = "/tmp/maplesu-owner-test/modules";
static constexpr char kTool[] = "/bin/busybox";
#else
static constexpr char kBase[] = "/data/adb/maplesu";
static constexpr char kModules[] = "/data/adb/modules";
static constexpr char kTool[] = "/data/adb/maplesu/bin/busybox";
#endif
static const std::string kRun = std::string(kBase) + "/run";
static const std::string kSocket = kRun + "/modules.sock";
static volatile sig_atomic_t stopping = 0;

static void on_stop(int) { stopping = 1; }
static void fail(const std::string& what) { throw std::runtime_error(what + ": " + strerror(errno)); }
static void require(bool ok, const char* what) {
    if (!ok) throw std::runtime_error(what);
}
static bool trusted(const struct stat& s, bool directory) {
    return s.st_uid == 0 && !(s.st_mode & 0022) &&
        (directory ? S_ISDIR(s.st_mode) : (S_ISREG(s.st_mode) && s.st_nlink == 1));
}
static int checked_dir(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("open directory " + path);
    struct stat s {};
    if (fstat(fd, &s) || !trusted(s, true)) {
        close(fd);
        throw std::runtime_error("untrusted directory " + path);
    }
    return fd;
}
static int child_dir(int parent, const char* name) {
    if (mkdirat(parent, name, 0700) && errno != EEXIST) fail("mkdir");
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("open child directory");
    struct stat s {};
    if (fstat(fd, &s) || !trusted(s, true) || (s.st_mode & 0077)) {
        close(fd);
        throw std::runtime_error("state directory must be Root private");
    }
    return fd;
}
static int prepare() {
#ifndef MAPLESU_OWNER_TEST
    // Android /data is system-owned. Its fixed adb child is the Root trust anchor.
    int adb = checked_dir("/data/adb");
    int base = child_dir(adb, "maplesu");
    close(adb);
#else
    int base = checked_dir(kBase);
#endif
    int run = child_dir(base, "run");
    close(base);
    return run;
}
static int checked_file(int directory, const char* name, int flags, mode_t mode = 0600) {
    int fd = openat(directory, name, flags | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) fail(std::string("open ") + name);
    struct stat s {};
    if (fstat(fd, &s) || !trusted(s, false)) {
        close(fd);
        throw std::runtime_error(std::string("untrusted file ") + name);
    }
    return fd;
}
static void write_all(int fd, const std::string& data) {
    size_t done = 0;
    while (done < data.size()) {
        ssize_t n = write(fd, data.data() + done, data.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("write");
        done += static_cast<size_t>(n);
    }
}
static std::string read_small(int fd) {
    char buffer[4097];
    ssize_t n;
    do { n = read(fd, buffer, sizeof(buffer)); } while (n < 0 && errno == EINTR);
    if (n < 0) fail("read");
    require(n < static_cast<ssize_t>(sizeof(buffer)), "oversized state");
    return std::string(buffer, static_cast<size_t>(n));
}
static std::string boot_id() {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("boot_id");
    auto result = read_small(fd);
    close(fd);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) result.pop_back();
    require(result.size() == 36, "invalid boot ID");
    return result;
}
static unsigned long long start_time(pid_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    std::getline(input, line);
    auto end = line.rfind(')');
    if (end == std::string::npos) return 0;
    std::istringstream fields(line.substr(end + 2));
    std::string value;
    for (int field = 3; field <= 22; ++field) {
        if (!(fields >> value)) return 0;
    }
    return strtoull(value.c_str(), nullptr, 10);
}
static bool valid_id(const std::string& id) {
    if (id.empty() || id.size() > 64 || id.front() == '.') return false;
    for (char c : id) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return false;
    }
    return true;
}
static bool valid_stage(const std::string& stage) {
    return stage == "post-fs-data" || stage == "post-mount" ||
        stage == "service" || stage == "boot-completed";
}
static std::string key(const std::string& id, const std::string& stage) { return id + "." + stage; }
static void send_packet(int fd, const std::string& text) {
    if (send(fd, text.data(), text.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(text.size())) fail("send");
}
static std::string receive_packet(int fd) {
    char data[4096];
    ssize_t n;
    do { n = recv(fd, data, sizeof(data), MSG_TRUNC); } while (n < 0 && errno == EINTR && !stopping);
    if (n < 0) fail("receive");
    require(n < static_cast<ssize_t>(sizeof(data)), "oversized request/response");
    return std::string(data, static_cast<size_t>(n));
}
static bool root_peer(int fd) {
    struct ucred peer {};
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
        size != sizeof(peer) || peer.uid != 0 || peer.pid <= 0) return false;
    // SO_PEERCRED carries the effective UID; also require the peer's real UID.
    std::ifstream status("/proc/" + std::to_string(peer.pid) + "/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("Uid:", 0) != 0) continue;
        unsigned real = 1, effective = 1;
        std::istringstream ids(line.substr(4));
        return bool(ids >> real >> effective) && real == 0 && effective == 0;
    }
    return false;
}
static void timeout(int fd) {
    timeval limit { 3, 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit))) fail("socket timeout");
}
static sockaddr_un address() {
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    require(kSocket.size() < sizeof(addr.sun_path), "socket path too long");
    memcpy(addr.sun_path, kSocket.c_str(), kSocket.size() + 1);
    return addr;
}
static int connect_owner() {
    struct stat s {};
    if (lstat(kSocket.c_str(), &s)) return -1;
    require(S_ISSOCK(s.st_mode) && s.st_uid == 0 && (s.st_mode & 0777) == 0600,
            "untrusted owner socket");
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) fail("socket");
    auto addr = address();
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
        close(fd);
        return -1;
    }
    if (!root_peer(fd)) { close(fd); throw std::runtime_error("owner peer is not Root"); }
    timeout(fd);
    return fd;
}

struct Task {
    std::string id, stage, state;
    std::vector<std::string> environment;
    pid_t supervisor = 0;
    unsigned long long birth = 0;
    int leader_exit = -1;
    int control = -1;
};
static std::string describe(const Task& t) {
    return t.id + " " + t.stage + " " + t.state + " supervisor=" + std::to_string(t.supervisor) +
        " starttime=" + std::to_string(t.birth) + " leader_exit=" + std::to_string(t.leader_exit);
}
static void persist(int states, const std::string& boot, const Task& task) {
    std::string name = key(task.id, task.stage);
    std::string temporary = name + ".tmp";
    int fd = checked_file(states, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL);
    try {
        write_all(fd, boot + "\n" + task.id + " " + task.stage + " " + task.state + " " +
            std::to_string(task.supervisor) + " " + std::to_string(task.birth) + " " +
            std::to_string(task.leader_exit) + "\n");
        if (fsync(fd)) fail("fsync state");
        close(fd);
        fd = -1;
        if (renameat(states, temporary.c_str(), states, name.c_str()) || fsync(states)) fail("publish state");
    } catch (...) {
        if (fd >= 0) close(fd);
        unlinkat(states, temporary.c_str(), 0);
        throw;
    }
}
static void load_states(int states, const std::string& boot, std::map<std::string, Task>& tasks) {
    DIR* entries = fdopendir(dup(states));
    if (!entries) fail("state directory listing");
    try {
        while (auto* entry = readdir(entries)) {
            std::string name = entry->d_name;
            if (name == "." || name == "..") continue;
            int fd = checked_file(states, name.c_str(), O_RDONLY);
            auto content = read_small(fd);
            close(fd);
            if (name.size() >= 4 && name.substr(name.size() - 4) == ".tmp") {
                // An interrupted atomic write never proves that a script started.
                throw std::runtime_error("interrupted task journal requires recovery: " + name);
            }
            std::istringstream fields(content);
            std::string recorded_boot;
            Task task;
            require(bool(fields >> recorded_boot >> task.id >> task.stage >> task.state >>
                task.supervisor >> task.birth >> task.leader_exit), "invalid task journal");
            require(valid_id(task.id) && valid_stage(task.stage) && key(task.id, task.stage) == name,
                    "invalid task journal identity");
            if (recorded_boot != boot) { unlinkat(states, name.c_str(), 0); continue; }
            if (task.state == "starting" || task.state == "running" || task.state == "stopping") {
                task.state = "interrupted";
            }
            tasks.emplace(name, task);
        }
        closedir(entries);
    } catch (...) { closedir(entries); throw; }
}

// Each task has a separate subreaper. Thus even double-fork/setsid children stay
// owned by that task. Only this single-threaded supervisor reaps its children:
// their PIDs cannot be recycled between enumeration, signal and waitpid.
static std::vector<pid_t> direct_children() {
    std::ifstream input("/proc/self/task/" + std::to_string(getpid()) + "/children");
    require(input.good(), "cannot enumerate owned children");
    std::vector<pid_t> result;
    pid_t pid;
    while (input >> pid) if (pid > 0) result.push_back(pid);
    return result;
}
static void kill_owned() {
    for (pid_t pid : direct_children()) {
        // These are unreaped direct children, never persisted or recycled PIDs.
        if (kill(pid, SIGKILL) && errno != ESRCH) fail("stop owned child");
    }
}
static void close_other_fds(const std::vector<int>& keep) {
    DIR* entries = opendir("/proc/self/fd");
    if (!entries) fail("fd enumeration");
    int listing = dirfd(entries);
    while (auto* entry = readdir(entries)) {
        int fd = atoi(entry->d_name);
        bool retained = fd <= 2 || fd == listing;
        for (int allowed : keep) if (fd == allowed) retained = true;
        if (!retained) close(fd);
    }
    closedir(entries);
}
static int exit_code(int status) {
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
static void supervise(int control, int module, int script, int tool, int log, pid_t owner,
                      const std::vector<std::string>& facts) {
    stopping = 0;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) || prctl(PR_SET_PDEATHSIG, SIGTERM)) _exit(125);
    if (getppid() != owner) _exit(125);
    close_other_fds({ control, module, script, tool, log });
    int error_pipe[2];
    if (pipe2(error_pipe, O_CLOEXEC)) _exit(125);
    pid_t leader = fork();
    if (leader < 0) _exit(125);
    if (leader == 0) {
        close(error_pipe[0]);
        auto exec_fail = [&]() { int error = errno; (void)write(error_pipe[1], &error, sizeof(error)); _exit(126); };
        if (fchdir(module)) exec_fail();
        int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0 || dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0 || fcntl(script, F_SETFD, 0)) exec_fail();
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        std::string path = "/proc/self/fd/" + std::to_string(script);
        char* argv[] = {
            const_cast<char*>("busybox"), const_cast<char*>("sh"),
            path.data(), nullptr };
        char* base_environment[] = { const_cast<char*>("MAPLESU=1"), const_cast<char*>("ASH_STANDALONE=1"),
            const_cast<char*>("PATH=/data/adb/maplesu/bin:/system/bin:/system/xbin:/bin:/usr/bin"),
            const_cast<char*>("HOME=/"), nullptr };
        maplesu::module_task::Environment environment;
        const int captured = environment.build(base_environment, facts);
        if (captured) { errno = -captured; exec_fail(); }
        fexecve(tool, argv, environment.data());
        exec_fail();
    }
    close(error_pipe[1]);
    close(module);
    close(script);
    close(tool);
    close(log);
    int error = 0;
    ssize_t n;
    do { n = read(error_pipe[0], &error, sizeof(error)); } while (n < 0 && errno == EINTR && !stopping);
    close(error_pipe[0]);
    bool ready = n == 0 && !stopping;
    if (ready) send_packet(control, "ready");
    else { stopping = 1; send_packet(control, "exec-error " + std::to_string(error)); }
    for (;;) {
        if (stopping) kill_owned();
        int status;
        pid_t pid;
        bool empty = false;
        for (;;) {
            pid = waitpid(-1, &status, WNOHANG);
            if (pid > 0) {
                if (pid == leader) {
                    try { send_packet(control, "leader " + std::to_string(exit_code(status))); } catch (...) {}
                }
                continue;
            }
            empty = pid < 0 && errno == ECHILD;
            break;
        }
        if (empty) {
            try { send_packet(control, stopping ? "stopped" : "done"); } catch (...) {}
            _exit(0);
        }
        pollfd item { control, POLLIN, 0 };
        if (poll(&item, 1, 50) > 0) {
            if (item.revents & (POLLHUP | POLLERR | POLLNVAL)) stopping = 1;
            if (item.revents & POLLIN) {
                try { (void)receive_packet(control); stopping = 1; }
                catch (...) { stopping = 1; }
            }
        }
    }
}

static void launch(Task& task, int run, int states, const std::string& boot) {
    int modules = checked_dir(kModules);
    int module = openat(modules, task.id.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(modules);
    if (module < 0) fail("module directory");
    int script = -1, tool = -1, log = -1;
    int channel[2] { -1, -1 };
    try {
        struct stat info {};
        require(!fstat(module, &info) && trusted(info, true), "untrusted module directory");
        for (const char* marker : { "disable", "remove", "update" }) {
            if (!fstatat(module, marker, &info, AT_SYMLINK_NOFOLLOW))
                throw std::runtime_error(std::string("module marker blocks start: ") + marker);
            if (errno != ENOENT) fail("module marker");
        }
        script = checked_file(module, (task.stage + ".sh").c_str(), O_RDONLY);
        int tool_parent = checked_dir(std::string(kTool).substr(0, std::string(kTool).rfind('/')));
        tool = checked_file(tool_parent, std::string(kTool).substr(std::string(kTool).rfind('/') + 1).c_str(), O_RDONLY);
        close(tool_parent);
        require(!fstat(tool, &info) && (info.st_mode & 0111), "shell is not executable");
        std::string log_name = key(task.id, task.stage) + ".log";
        log = checked_file(run, log_name.c_str(), O_WRONLY | O_CREAT | O_APPEND);
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel)) fail("task channel");
        task.state = "starting";
        persist(states, boot, task);
        pid_t owner = getpid();
        pid_t pid = fork();
        if (pid < 0) fail("task fork");
        if (pid == 0) {
            close(channel[0]);
            try { supervise(channel[1], module, script, tool, log, owner, task.environment); }
            catch (...) {
                stopping = 1;
                (void)send(channel[1], "exec-error 125", 14, MSG_NOSIGNAL);
                for (;;) {
                    try { kill_owned(); } catch (...) {}
                    int status;
                    pid_t p = waitpid(-1, &status, WNOHANG);
                    if (p < 0 && errno == ECHILD) _exit(125);
                    usleep(50000);
                }
            }
            _exit(125);
        }
        task.supervisor = pid;
        task.birth = start_time(pid);
        task.control = channel[0];
        channel[0] = -1;
        persist(states, boot, task);
        close(channel[1]);
        channel[1] = -1;
        close(module); close(script); close(tool); close(log);
    } catch (...) {
        close(module);
        for (int fd : { script, tool, log, channel[0], channel[1] }) if (fd >= 0) close(fd);
        throw;
    }
}

static void daemon_loop(int ready_fd) {
    int run = prepare();
    int lock = checked_file(run, "owner.lock", O_RDWR | O_CREAT);
    if (flock(lock, LOCK_EX | LOCK_NB)) fail("owner lock");
    int states = child_dir(run, "tasks");
    auto boot = boot_id();
    std::map<std::string, Task> tasks;
    load_states(states, boot, tasks);
    struct stat old {};
    if (!fstatat(run, "modules.sock", &old, AT_SYMLINK_NOFOLLOW)) {
        require(S_ISSOCK(old.st_mode) && old.st_uid == 0 && (old.st_mode & 0777) == 0600,
                "untrusted stale socket");
        if (unlinkat(run, "modules.sock", 0)) fail("remove stale socket");
    } else if (errno != ENOENT) fail("socket stat");
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (listener < 0) fail("listener");
    auto addr = address();
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
        chmod(kSocket.c_str(), 0600) || listen(listener, 16)) fail("bind/listen");
    if (ready_fd >= 0) { write_all(ready_fd, "ready\n"); close(ready_fd); }
    bool shutdown = false;
    for (;;) {
        if (stopping) shutdown = true;
        if (shutdown) {
            for (auto& [name, task] : tasks) {
                (void)name;
                if (task.control >= 0 && task.state != "stopping") {
                    (void)send(task.control, "stop", 4, MSG_NOSIGNAL);
                    task.state = "stopping";
                    persist(states, boot, task);
                }
            }
        }
        std::vector<pollfd> items { { listener, POLLIN, 0 } };
        std::vector<Task*> live;
        for (auto& [name, task] : tasks) {
            (void)name;
            if (task.control >= 0) { items.push_back({task.control, POLLIN, 0}); live.push_back(&task); }
        }
        if (shutdown && live.empty()) break;
        if (poll(items.data(), items.size(), 200) < 0 && errno != EINTR) fail("poll owner");
        for (size_t i = 0; i < live.size(); ++i) {
            Task& task = *live[i];
            short events = items[i + 1].revents;
            if (!events) continue;
            std::string update;
            if (events & POLLIN) update = receive_packet(task.control);
            if (update == "ready") { if (task.state != "stopping") task.state = "running"; }
            else if (update.rfind("leader ", 0) == 0) task.leader_exit = atoi(update.c_str() + 7);
            else if (update == "done" || update == "stopped" || update.empty()) {
                task.state = update == "stopped" ? "stopped" :
                    (update == "done" ? (task.leader_exit == 0 ? "exited" : "failed") : "interrupted");
                close(task.control); task.control = -1;
                // Never signal a persisted PID. Only reap our actual supervisor child.
                int status;
                while (waitpid(task.supervisor, &status, 0) < 0 && errno == EINTR) {}
            } else if (update.rfind("exec-error ", 0) == 0) task.state = "stopping";
            persist(states, boot, task);
        }
        if (!(items[0].revents & POLLIN)) continue;
        int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) continue;
        try {
            require(root_peer(client), "Root peer required");
            timeout(client);
            std::istringstream packet(receive_packet(client));
            std::string first_line;
            std::getline(packet, first_line);
            std::istringstream request(first_line);
            std::string command, id, stage, extra;
            request >> command >> id >> stage >> extra;
            std::vector<std::string> facts;
            for (std::string line; std::getline(packet, line);) facts.push_back(line);
            require(command == "start" || facts.empty(), "unexpected module environment");
            if (command == "start") {
                maplesu::module_task::Environment checked;
                require(!checked.build(nullptr, facts), "module environment snapshot required");
            }
            std::string reply;
            if (command == "ping" && id.empty()) reply = "OK " + boot;
            else if (command == "shutdown" && id.empty()) { shutdown = true; reply = "OK stopping"; }
            else if (command == "status" && id.empty()) {
                reply = "OK boot=" + boot + " owner=" + std::to_string(getpid()) +
                    " starttime=" + std::to_string(start_time(getpid())) + " origin=runtime-bootstrap\n";
                for (const auto& [name, task] : tasks) { (void)name; reply += describe(task) + "\n"; }
            } else {
                require(valid_id(id) && valid_stage(stage) && extra.empty(), "expected command MODULE STAGE");
                auto name = key(id, stage);
                auto found = tasks.find(name);
                if (command == "start") {
                    require(!shutdown, "owner shutting down");
                    if (found != tasks.end()) reply = "OK already-recorded " + describe(found->second);
                    else {
                        Task task;
                        task.id = id; task.stage = stage; task.environment = facts;
                        auto [entry, inserted] = tasks.emplace(name, task);
                        (void)inserted;
                        try { launch(entry->second, run, states, boot); }
                        catch (...) {
                            if (entry->second.supervisor == 0) {
                                unlinkat(states, name.c_str(), 0);
                                tasks.erase(entry);
                            } else {
                                (void)send(entry->second.control, "stop", 4, MSG_NOSIGNAL);
                                entry->second.state = "stopping";
                                persist(states, boot, entry->second);
                            }
                            throw;
                        }
                        reply = "OK accepted " + describe(entry->second);
                    }
                } else if (command == "status") {
                    require(found != tasks.end(), "task not recorded");
                    reply = "OK " + describe(found->second);
                } else if (command == "stop") {
                    require(found != tasks.end(), "task not recorded");
                    auto& task = found->second;
                    if (task.control >= 0) {
                        send_packet(task.control, "stop"); task.state = "stopping";
                        persist(states, boot, task);
                    }
                    reply = "OK " + describe(task);
                } else throw std::runtime_error("unknown command");
            }
            require(reply.size() < 4096, "response too large; query one task");
            send_packet(client, reply);
        } catch (const std::exception& e) {
            std::string error = std::string("ERR ") + e.what();
            (void)send(client, error.data(), error.size(), MSG_NOSIGNAL);
        }
        close(client);
    }
    close(listener);
    unlinkat(run, "modules.sock", 0);
    close(states); close(lock); close(run);
}
static void detach_fds(int ready) {
    close_other_fds({ready});
    int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullfd < 0) fail("/dev/null");
    for (int fd = 0; fd < 3; ++fd) if (dup2(nullfd, fd) < 0) fail("redirect stdio");
    if (nullfd > 2) close(nullfd);
}
static void ensure_owner() {
    int client = connect_owner();
    if (client >= 0) { send_packet(client, "ping"); std::puts(receive_packet(client).c_str()); close(client); return; }
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) fail("ready pipe");
    pid_t pid = fork();
    if (pid < 0) fail("owner fork");
    if (pid == 0) {
        close(ready[0]);
        try {
            if (setsid() < 0 || chdir("/")) fail("detach owner");
            detach_fds(ready[1]);
            daemon_loop(ready[1]);
            _exit(0);
        } catch (const std::exception& e) {
            std::string error = std::string("ERR ") + e.what();
            (void)write(ready[1], error.data(), error.size());
            _exit(1);
        }
    }
    close(ready[1]);
    pollfd item { ready[0], POLLIN, 0 };
    int result;
    do { result = poll(&item, 1, 5000); } while (result < 0 && errno == EINTR);
    require(result > 0, "owner startup timeout");
    auto response = read_small(ready[0]);
    close(ready[0]);
    require(response == "ready\n", response.empty() ? "owner failed before ready" : response.c_str());
    std::puts("OK owner-ready origin=runtime-bootstrap");
}
int main(int argc, char** argv) {
    try {
        require(getuid() == 0 && geteuid() == 0, "real and effective Root required");
        umask(0077);
        signal(SIGPIPE, SIG_IGN);
        struct sigaction action {};
        action.sa_handler = on_stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, nullptr) || sigaction(SIGINT, &action, nullptr)) fail("signals");
        require(argc >= 2, "usage: maplesu-modules ensure|serve|status|start ID STAGE|stop ID STAGE|shutdown");
        int directory = prepare(); close(directory);
        std::string command = argv[1];
        if (command == "ensure" && argc == 2) ensure_owner();
        else if (command == "serve" && argc == 2) { detach_fds(-1); daemon_loop(-1); }
        else {
            require((argc == 2 && (command == "status" || command == "shutdown")) ||
                (argc == 4 && (command == "start" || command == "stop" || command == "status")), "invalid command");
            if (argc == 4) require(valid_id(argv[2]) && valid_stage(argv[3]), "invalid module/stage");
            int client = connect_owner();
            require(client >= 0, "owner is not running; run ensure first");
            if (argc == 4) command += std::string(" ") + argv[2] + " " + argv[3];
            if (std::string(argv[1]) == "start") {
                // Snapshot from the actual module worker; ensure/status/shutdown never require facts.
                std::vector<std::string> facts;
                for (const char* name : maplesu::module_task::fact_names) {
                    const char* value = getenv(name);
                    if (value) facts.emplace_back(std::string(name) + "=" + value);
                }
                maplesu::module_task::Environment checked;
                require(!checked.build(nullptr, facts), "module environment snapshot required");
                command += "\n";
                for (const auto& fact : facts) command += fact + "\n";
            }
            send_packet(client, command);
            auto reply = receive_packet(client);
            close(client);
            std::puts(reply.c_str());
            return reply.rfind("OK ", 0) == 0 ? 0 : 1;
        }
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "maplesu-modules: %s\n", e.what()); return 1; }
}
