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

namespace maplesu::root_environment::cg_v1 {
struct UniqueFd {
    int fd{-1};
    UniqueFd() = default;
    explicit UniqueFd(int f) : fd(f) {}
    ~UniqueFd() { if (fd >= 0) { const int saved = errno; ::close(fd); errno = saved; } }
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
        if (w == 0) { errno = EIO; return false; }
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
inline bool path_exists(const char* p) {
    struct stat status{};
    return ::stat(p, &status) == 0;
}
inline bool missing_path(int error) { return error == ENOENT || error == ENOTDIR; }
inline void remember_error(int error, int& first) {
    if (!first && error) first = error;
}
inline const char* existing_path(const char* path, int& error) {
    if (!path) return nullptr;
    if (path_exists(path)) return path;
    const int failure = errno;
    if (!missing_path(failure)) remember_error(failure, error);
    return nullptr;
}
template <size_t N>
inline const char* pick_first_existing(const char* const (&paths)[N], int& error) {
    for (const char* path : paths)
        if (existing_path(path, error)) return path;
    return nullptr;
}

// 迁移结果
struct Result {
    int threads_total{0};
    int cpuset_moved{0};
    int stune_moved{0};
    int err_any{0};
    bool ok() const { return err_any == 0; }
};

template <typename Visit>
inline int visit_self_threads(Visit visit, int& error) {
    int total = 0;
    DIR* directory = ::opendir("/proc/self/task");
    if (!directory) { remember_error(errno, error); return total; }
    for (;;) {
        errno = 0;
        dirent* entry = ::readdir(directory);
        if (!entry) { remember_error(errno, error); break; }
        if (entry->d_name[0] == '.') continue;
        char* end = nullptr;
        const long tid = std::strtol(entry->d_name, &end, 10);
        if (!end || *end != '\0' || tid <= 0 || errno == ERANGE) continue;
        ++total;
        visit(tid);
    }
    if (::closedir(directory) != 0) remember_error(errno, error);
    return total;
}

inline int count_self_threads() {
    int error = 0;
    const int total = visit_self_threads([](long) {}, error);
    errno = error;
    return total;
}

inline bool thread_disappeared(long tid, int failure) {
    if (failure == ESRCH) return true;
    if (failure != ENOENT) return false;
    char path[64];
    const int length = std::snprintf(path, sizeof(path), "/proc/self/task/%ld", tid);
    if (length <= 0 || length >= static_cast<int>(sizeof(path))) return false;
    struct stat status{};
    if (::stat(path, &status) == 0) return false;
    return errno == ENOENT || errno == ESRCH;
}

inline Result migrate_targets(const char* const (&paths)[4]) {
    Result result{};
    if (!paths[0] && !paths[1] && !paths[2] && !paths[3]) return result;
    result.threads_total = visit_self_threads([&](long tid) {
        for (unsigned int controller = 0; controller < 4; ++controller) {
            if (!paths[controller]) continue;
            if (write_num_newline(paths[controller], tid)) {
                if (controller == 0) ++result.cpuset_moved;
                else if (controller == 1) ++result.stune_moved;
                continue;
            }
            const int failure = errno;
            if (thread_disappeared(tid, failure)) break;
            remember_error(failure, result.err_any);
        }
    }, result.err_any);
    return result;
}

inline int migrate_all_threads_to_tasks(const char* tasks_path) {
    int error = 0;
    const char* paths[4] = {existing_path(tasks_path, error), nullptr, nullptr, nullptr};
    Result result = migrate_targets(paths);
    if (error) result.err_any = error;
    errno = result.err_any;
    return result.cpuset_moved;
}

inline const char* pick_first_existing_cpuset(int* error = nullptr) {
    static const char* const C[] = {
        "/dev/cpuset/top-app/tasks",
        "/dev/cpuset/foreground/tasks",
        "/dev/cpuset/system-background/tasks",
        "/dev/cpuset/background/tasks",
        "/dev/cpuset/tasks"
    };
    int ignored = 0;
    return pick_first_existing(C, error ? *error : ignored);
}
inline const char* pick_first_existing_stune(int* error = nullptr) {
    static const char* const S[] = {
        "/dev/stune/top-app/tasks",
        "/dev/stune/foreground/tasks",
        "/dev/stune/background/tasks",
        "/dev/stune/tasks"
    };
    int ignored = 0;
    return pick_first_existing(S, error ? *error : ignored);
}

inline const char* pick_first_existing_acct(int* error = nullptr) {
    static const char* const A[] = {
        "/acct/tasks",
        "/sys/fs/cgroup/cpuacct/tasks",
        "/sys/fs/cgroup/cpu/tasks"
    };
    int ignored = 0;
    return pick_first_existing(A, error ? *error : ignored);
}

inline const char* pick_first_existing_memory(int* error = nullptr) {
    static const char* const M[] = {
        "/sys/fs/cgroup/memory/tasks",
        "/dev/memcg/tasks"
    };
    int ignored = 0;
    return pick_first_existing(M, error ? *error : ignored);
}

inline Result migrate_self_threads_v1(const char* cpuset_tasks_path = nullptr,
                                      const char* stune_tasks_path = nullptr) {
    int error = 0;
    const char* paths[4] = {
        cpuset_tasks_path ? existing_path(cpuset_tasks_path, error) : pick_first_existing_cpuset(&error),
        stune_tasks_path ? existing_path(stune_tasks_path, error) : pick_first_existing_stune(&error),
        pick_first_existing_acct(&error),
        pick_first_existing_memory(&error)
    };
    Result result = migrate_targets(paths);
    if (error) result.err_any = error;
    return result;
}

static_assert(sizeof(Result) == 16 && alignof(Result) == 4);

} // namespace maplesu::root_environment::cg_v1
