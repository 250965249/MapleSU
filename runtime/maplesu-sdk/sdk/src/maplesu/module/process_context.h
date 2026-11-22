
//
#pragma once

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace cg_v1 {
struct UniqueFd {
    int fd{-1};
    UniqueFd() = default;
    explicit UniqueFd(int f) : fd(f) {}
    ~UniqueFd() { if (fd >= 0) ::close(fd); }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& o) noexcept : fd(o.fd) { o.fd = -1; }
    UniqueFd& operator=(UniqueFd&& o) noexcept {
        if (this != &o) { if (fd>=0) ::close(fd); fd=o.fd; o.fd=-1; }
        return *this;
    }
    explicit operator bool() const { return fd >= 0; }
    int get() const { return fd; }
};

inline bool write_all(int fd, const char* data, size_t n) {
    const char* p = data;
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w; n -= (size_t)w;
    }
    return true;
}
inline bool write_num_newline(const char* path, long num) {
    UniqueFd f(::open(path, O_WRONLY | O_CLOEXEC));
    if (!f) return false;
    char buf[64];
    int m = std::snprintf(buf, sizeof(buf), "%ld\n", num);
    if (m <= 0 || m >= (int)sizeof(buf)) { errno = EOVERFLOW; return false; }
    return write_all(f.get(), buf, (size_t)m);
}
inline bool path_exists(const char* p) { return ::access(p, F_OK) == 0; }

// 迁移结果
struct Result {
    int threads_total{0};
    int cpuset_moved{0};
    int stune_moved{0};
    int err_any{0};
    bool ok() const { return true; }
};

inline int count_self_threads() {
    int total = 0;
    if (DIR* d = ::opendir("/proc/self/task")) {
        while (dirent* e = ::readdir(d)) {
            if (e->d_name[0]=='.') continue;
            char* end=nullptr; long tid = std::strtol(e->d_name, &end, 10);
            if (!end || *end!='\0' || tid<=0) continue;
            ++total;
        }
        ::closedir(d);
    }
    return total;
}

inline int migrate_all_threads_to_tasks(const char* tasks_path) {
    if (!tasks_path || !path_exists(tasks_path)) return 0;
    int moved=0, total=0;
    if (DIR* d = ::opendir("/proc/self/task")) {
        while (dirent* e = ::readdir(d)) {
            if (e->d_name[0]=='.') continue;
            char* end=nullptr; long tid = std::strtol(e->d_name, &end, 10);
            if (!end || *end!='\0' || tid<=0) continue;
            ++total;
            if (write_num_newline(tasks_path, tid)) ++moved;
        }
        ::closedir(d);
    }
    return moved;
}

inline const char* pick_first_existing_cpuset() {
    static const char* C[] = {
        "/dev/cpuset/top-app/tasks",
        "/dev/cpuset/foreground/tasks",
        "/dev/cpuset/system-background/tasks",
        "/dev/cpuset/background/tasks",
        "/dev/cpuset/tasks"
    };
    for (const char* p : C) if (path_exists(p)) return p;
    return nullptr;
}
inline const char* pick_first_existing_stune() {
    static const char* S[] = {
        "/dev/stune/top-app/tasks",
        "/dev/stune/foreground/tasks",
        "/dev/stune/background/tasks",
        "/dev/stune/tasks"
    };
    for (const char* p : S) if (path_exists(p)) return p;
    return nullptr;
}

inline const char* pick_first_existing_acct() {
    static const char* A[] = {
        "/acct/tasks",
        "/sys/fs/cgroup/cpuacct/tasks",
        "/sys/fs/cgroup/cpu/tasks"
    };
    for (const char* p : A) if (path_exists(p)) return p;
    return nullptr;
}

inline const char* pick_first_existing_memory() {
    static const char* M[] = {
        "/sys/fs/cgroup/memory/tasks",
        "/dev/memcg/tasks"
    };
    for (const char* p : M) if (path_exists(p)) return p;
    return nullptr;
}

inline Result migrate_self_threads_v1(const char* cpuset_tasks_path = nullptr,
                                      const char* stune_tasks_path  = nullptr) {
    Result r{};
    r.threads_total = count_self_threads();

    const char* cp = cpuset_tasks_path ? cpuset_tasks_path : pick_first_existing_cpuset();
    const char* sp = stune_tasks_path  ? stune_tasks_path  : pick_first_existing_stune();

    if (cp) {
        int moved = migrate_all_threads_to_tasks(cp);
        r.cpuset_moved = moved;
        if (moved == 0 && r.err_any == 0) r.err_any = errno ? errno : EPERM;
    }
    if (sp) {
        int moved = migrate_all_threads_to_tasks(sp);
        r.stune_moved = moved;
        if (moved == 0 && r.err_any == 0) r.err_any = errno ? errno : EPERM;
    }
    
    const char* ap = pick_first_existing_acct();
    if (ap) {
        migrate_all_threads_to_tasks(ap);
    }
    
    const char* mp = pick_first_existing_memory();
    if (mp) {
        migrate_all_threads_to_tasks(mp);
    }
    return r;
}

} // namespace cg_v1

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace cg_v2 {
struct UniqueFd {
    int fd{-1};
    UniqueFd() = default;
    explicit UniqueFd(int f) : fd(f) {}
    ~UniqueFd() { if (fd >= 0) ::close(fd); }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& o) noexcept : fd(o.fd) { o.fd = -1; }
    UniqueFd& operator=(UniqueFd&& o) noexcept {
        if (this != &o) { if (fd>=0) ::close(fd); fd=o.fd; o.fd=-1; }
        return *this;
    }
    explicit operator bool() const { return fd >= 0; }
    int get() const { return fd; }
    int release() { int t = fd; fd = -1; return t; }
    void reset(int f=-1){ if (fd>=0) ::close(fd); fd=f; }
};

inline bool write_all(int fd, const char* data, size_t n) {
    const char* p = data;
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w; n -= (size_t)w;
    }
    return true;
}
inline bool path_exists(const char* p) { return ::access(p, F_OK) == 0; }

inline bool write_num_newline(const char* path, long num) {
    UniqueFd f(::open(path, O_WRONLY | O_CLOEXEC));
    if (!f) return false;
    char buf[64];
    int m = std::snprintf(buf, sizeof(buf), "%ld\n", num);
    if (m <= 0 || m >= (int)sizeof(buf)) { errno = EOVERFLOW; return false; }
    return write_all(f.get(), buf, (size_t)m);
}

struct Result {
    bool ok{false};
    int  err{0};
};

inline Result migrate_self_to_root() {
    const char* v2_procs = "/sys/fs/cgroup/cgroup.procs";
    Result r{};
    if (!path_exists(v2_procs)) {
        r.err = ENOENT;
        return r;
    }
    pid_t self = ::getpid();
    if (!write_num_newline(v2_procs, (long)self)) {
        r.err = errno;
        return r;
    }
    r.ok = true;
    return r;
}

} // namespace cg_v2

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

namespace selinux_procattr {

namespace detail {

inline pid_t gettid_compat() {
#ifdef SYS_gettid
    return static_cast<pid_t>(syscall(SYS_gettid));
#else
    return static_cast<pid_t>(syscall(__NR_gettid));
#endif
}

// 打开本线程的 /proc/.../attr/<attr>
// 优先 thread-self（新内核更推荐），不行再 fallback 到 self/task/<tid>
inline int open_self_attr(const char* attr, int flags) {
    char path[128];

    // 1) /proc/thread-self/attr/<attr>
    snprintf(path, sizeof(path), "/proc/thread-self/attr/%s", attr);
    int fd = open(path, flags | O_CLOEXEC);
    if (fd >= 0) return fd;

    if (errno != ENOENT) return -1;

    // 2) /proc/self/task/<tid>/attr/<attr>
    const pid_t tid = gettid_compat();
    snprintf(path, sizeof(path), "/proc/self/task/%d/attr/%s", static_cast<int>(tid), attr);
    return open(path, flags | O_CLOEXEC);
}

inline int write_attr(const char* attr, const char* con) {
    int fd = open_self_attr(attr, O_WRONLY);
    if (fd < 0) return -1;

    ssize_t rc;
    if (con) {
        const size_t n = strlen(con) + 1; // 写入包含 '\0'
        do { rc = write(fd, con, n); } while (rc < 0 && errno == EINTR);
    } else {
        // “清空/恢复默认”：写 0 字节（别传 nullptr 给 write）
        const char* empty = "";
        do { rc = write(fd, empty, 0); } while (rc < 0 && errno == EINTR);
    }

    const int saved = errno;
    close(fd);
    errno = saved;
    return (rc < 0) ? -1 : 0;
}

} // namespace detail

inline int setcon(const char* con) { return detail::write_attr("current", con); }

inline int setexeccon(const char* con) { return detail::write_attr("exec", con); }

} // namespace selinux_procattr

static_assert(sizeof(cg_v1::UniqueFd) == 4 && sizeof(cg_v2::UniqueFd) == 4);
static_assert(sizeof(cg_v1::Result) == 16 && alignof(cg_v1::Result) == 4);
static_assert(sizeof(cg_v2::Result) == 8 && alignof(cg_v2::Result) == 4);
