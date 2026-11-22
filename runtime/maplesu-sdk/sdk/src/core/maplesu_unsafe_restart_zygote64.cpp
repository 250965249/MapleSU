// MapleSU unsafe restart zygote64 implementation.
//
#include "core01/maplesu_fork_helper.h"

#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_storage_worker_private.h"
#include <cerrno>

// selinux_procattr 这一节，头里其它成员的 static 助手在本 TU 里不会被引用，
// 用 -Wunused-function 抑制掉它们的"已定义未使用"告警。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "private_module_selinux.h"
#pragma clang diagnostic pop

// module_err_def.h: OK=0 / ERR_MODULE_PARAM=-20000，AUTO 段从 -19999 起递增。
static_assert(static_cast<ssize_t>(KModErr::ERR_MODULE_PID_CYCLE) == -19993,
              "unexpected layout size");
static_assert(static_cast<ssize_t>(KModErr::ERR_MODULE_ZYGOTE64_EMPTY) == -19992,
              "unexpected layout size");

//
//   * 必须是 namespace pid_cycle_utils 里的 static 函数（mangling 里的 L）；
//   * 签名必须逐字是 (int*, int*, int, int) / (int, int*, int, int)；
//   * 每个函数里恰好一个 lambda，且 lambda 体必须内联进 __thread_proxy
namespace pid_cycle_utils {

// 重试上限与线程创建失败后的退避间隔。
constexpr int kPidCycleRetryLimit = 300000;
constexpr int kPidCycleIntervalMs = 1;

// 观察内核 pid 分配器是否已经回绕一圈。
//
// 每次迭代新建一个线程并读回它的 tid —— tid 就是分配器当前游标。连续两次采样
// 里出现「新 tid < 旧 tid」即说明游标越过 pid_max 回绕了；此刻旧 zygote64 的
// pid 已被内核从 pid 表里彻底放走，不会再被误认。
//
// 返回：观察到回绕时返回迭代序号（0..limit-1）；达到上限仍未观察到返回 limit。
//   out_cursor   —— 观察到的回绕瞬间游标（诊断用，可为 nullptr）
//   out_observed —— 1 = 已回绕，0 = 超时（诊断用，可为 nullptr）
//
// 失败路径：std::thread 构造可能抛 std::system_error（线程数上限/内存紧张），
// __cxa_begin_catch -> sleep_for -> __cxa_end_catch -> 回到循环头）。
static int wait_pid_wrap(int* out_cursor, int* out_observed, int retry_limit, int interval_ms) {
    int last_cursor = -1;
    for (int attempt = 0; attempt < retry_limit; ++attempt) {
        int cursor = -1;
        try {
            std::thread sampler([&cursor]() { cursor = static_cast<int>(::gettid()); });
            sampler.join();
        } catch (const std::system_error&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            continue;
        }
        // 第一轮 last_cursor 还是 -1，因此不会误判。
        if (last_cursor > -1 && cursor < last_cursor) {
            if (out_cursor != nullptr) *out_cursor = cursor;
            if (out_observed != nullptr) *out_observed = 1;
            return attempt;
        }
        last_cursor = cursor;
    }
    return retry_limit;
}

// 采样直到 pid 分配器游标越过 target_pid。
//
// 回绕之后游标从低位重新增长；等到游标 > 最旧的 zygote64 pid，说明旧 zygote64
// 占用的 pid 区间已经被完整越过，重启 zygote 不会撞到这些 pid。
//
// 返回：越过目标时返回迭代序号；达到上限仍未越过返回 limit（调用方判超时）。
//   out_cursor —— 越过瞬间的游标（诊断用，可为 nullptr）
//
static int wait_pid_greater_than(int target_pid, int* out_cursor, int retry_limit, int interval_ms) {
    for (int attempt = 0; attempt < retry_limit; ++attempt) {
        int cursor = -1;
        try {
            std::thread sampler([&cursor]() { cursor = static_cast<int>(::gettid()); });
            sampler.join();
        } catch (const std::system_error&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            continue;
        }
        if (cursor > target_pid) {
            if (out_cursor != nullptr) *out_cursor = cursor;
            return attempt;
        }
    }
    return retry_limit;
}

}  // namespace pid_cycle_utils

// 4 个函数都被完全内联进 unsafe_restart_zygote64，因此本 TU 不产生它们的符号。
namespace process_utils {

// `(unsigned)(c - '0') > 9` 的区间判定，遇非数字立刻放弃。
static bool is_all_digits(const char* text) {
    for (const char* cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
    }
    return true;
}

// _ZN13process_utilsL23read_proc_cmdline_firstEi —— 读 /proc/<pid>/cmdline 的
// 原始字节并截断到第一个 NUL（即 argv[0]）。
//
static std::string read_proc_cmdline_first(int pid) {
    std::string content;
    const std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    FILE* fp = ::fopen(path.c_str(), "rb");
    if (fp != nullptr) {
        char buffer[512];
        for (;;) {
            const size_t got = ::fread(buffer, 1, sizeof(buffer), fp);
            if (got == 0) {
                break;
            }
            content.append(buffer, got);
        }
        ::fclose(fp);
        if (!content.empty()) {
            const size_t end = content.find('\0');
            return (end == std::string::npos) ? content : content.substr(0, end);
        }
    }
    return "";
}

// _ZN13process_utilsL14read_proc_commEi —— 读 /proc/<pid>/comm 的第一行并去掉
// 结尾的 '\n' / '\r'。
//
static std::string read_proc_comm(int pid) {
    const std::string path = "/proc/" + std::to_string(pid) + "/comm";
    FILE* fp = ::fopen(path.c_str(), "r");
    if (fp == nullptr) {
        return "";
    }
    char buffer[256] = {0};
    const char* line = ::fgets(buffer, sizeof(buffer), fp);
    ::fclose(fp);
    if (line == nullptr) {
        return "";
    }
    std::string name(buffer);
    while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) {
        name.pop_back();
    }
    return name;
}

// _ZN13process_utilsL28find_all_pids_by_name_sortedEPKc —— 遍历 /proc，
// 收集所有进程名等于 name 的 pid，排序去重后返回。
//
static std::vector<int> find_all_pids_by_name_sorted(const char* name) {
    std::vector<int> pids;
    DIR* proc_dir = ::opendir("/proc");
    if (proc_dir != nullptr) {
        for (;;) {
            dirent* entry = ::readdir(proc_dir);
            if (entry == nullptr) {
                break;
            }
            if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) {
                continue;
            }
            if (entry->d_name[0] == '\0') {
                continue;
            }
            if (!is_all_digits(entry->d_name)) {
                continue;
            }
            const int pid = ::atoi(entry->d_name);
            if (pid < 1) {
                continue;
            }

            const std::string argv0 = read_proc_cmdline_first(pid);
            bool matched = (argv0 == name);
            if (!matched) {
                const size_t slash = argv0.rfind('/');
                if (slash != std::string::npos) {
                    // 末段 basename 等于进程名也算（如 /system/bin/zygote64）
                    matched = (argv0.substr(slash + 1) == name);
                }
            }
            if (!matched) {
                // cmdline 不可读或被改写时，退化为 /proc/<pid>/comm
                matched = (read_proc_comm(pid) == name);
            }
            if (matched) {
                pids.push_back(pid);
            }
        }
        ::closedir(proc_dir);
        std::sort(pids.begin(), pids.end());
        pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    }
    return pids;
}

// _ZN13process_utilsL18find_zygote64_pidsEv —— 本成员要的那个特化。
static std::vector<int> find_zygote64_pids() {
    return find_all_pids_by_name_sorted("zygote64");
}

}  // namespace process_utils

namespace maplesu::sdk {

// 由本 TU 定义（下方 unsafe_restart_zygote64）；safe_restart 先用到，故前置声明。
KModErr unsafe_restart_zygote64();

/***************************************************************************
 * safe_restart_zygote64 — 带错误回传与回收的 zygote64 重启。
 *
 *                 }
 *                     err = (KModErr)-19914;                 // ERR_READ_CHILD_ERRCODE
 *
 * 失败行为：读不到子进程错误码时返回 ERR_READ_CHILD_ERRCODE(-19914)，
 * 不会把 -19999（ERR_MODULE_TEST_CHANNEL 哨兵值）泄漏给调用方。
 * 子进程路径不会 return：它 _exit(0)，避免重复执行父进程的清理逻辑。
 ***************************************************************************/
KModErr safe_restart_zygote64() {
    fork_pipe_info pipe;

    KModErr err = KModErr::ERR_MODULE_TEST_CHANNEL;

    if (fork_pipe_child_process(pipe)) {
        // ---- 子进程分支：做完就退出，绝不再往下走 ----
        const bool sent = write_errcode_from_child(pipe, unsafe_restart_zygote64());
        pipe.close_all();
        ::_exit(sent ? 0 : 1);
    }

    // ---- 父进程分支 ----
    if (!read_errcode_from_child(pipe, err)) {
        err = KModErr::ERR_READ_CHILD_ERRCODE;
    }

    pipe.close_all();
    if (pipe.child_pid > 0) {
        int status = 0;
        pid_t waited;
        do { waited = ::waitpid(pipe.child_pid, &status, 0); } while (waited < 0 && errno == EINTR);
        if (is_ok(err) && (waited != pipe.child_pid || !WIFEXITED(status) || WEXITSTATUS(status)))
            err = KModErr::ERR_READ_CHILD_ERRCODE;
    } else if (is_ok(err)) err = KModErr::ERR_READ_CHILD_ERRCODE;
    return err;
}

/***************************************************************************
 * unsafe_restart_zygote64 — 真正执行 zygote64 重启（在 safe_restart 的
 * fork 子进程里跑）。
 *
 *   7. __system_property_set("ctl.restart", "zygote") 让 init 重启 zygote
 *
 * 错误码只用 module_err_def.h 既有枚举：
 *   -19992 ERR_MODULE_ZYGOTE64_EMPTY   /proc 里一个 zygote64 都没找到
 *   -19993 ERR_MODULE_PID_CYCLE        pid 分配器观察超时（两条等待任一超时）
 *   其它                              set_current_root 的错误原样透传
 *
 * 资源语义：opendir 成功后必 closedir；FILE* 在读完后必 fclose（含 fgets 判空
 * 之前）；std::thread 一定 join；pids 由 vector 自动释放。任何失败分支都不泄漏 fd。
 ***************************************************************************/
KModErr unsafe_restart_zygote64() {
    storage::WorkerScope worker;
    const auto execute = [&]() -> KModErr {
    RETURN_IF_ERROR(worker.root());

    const std::vector<int> zygote_pids = process_utils::find_zygote64_pids();

    if (zygote_pids.empty()) {
        return KModErr::ERR_MODULE_ZYGOTE64_EMPTY;
    }

    int wrap_cursor = -1;
    int wrap_observed = 0;
    const int wrap_attempt = pid_cycle_utils::wait_pid_wrap(
        &wrap_cursor, &wrap_observed,
        pid_cycle_utils::kPidCycleRetryLimit, pid_cycle_utils::kPidCycleIntervalMs);
    if (wrap_attempt >= pid_cycle_utils::kPidCycleRetryLimit) {
        return KModErr::ERR_MODULE_PID_CYCLE;
    }

    int greater_cursor = -1;
    const int greater_attempt = pid_cycle_utils::wait_pid_greater_than(
        zygote_pids.front(), &greater_cursor,
        pid_cycle_utils::kPidCycleRetryLimit, pid_cycle_utils::kPidCycleIntervalMs);
    if (greater_attempt >= pid_cycle_utils::kPidCycleRetryLimit) {
        return KModErr::ERR_MODULE_PID_CYCLE;
    }

    if (selinux_procattr::setcon("u:r:init:s0") != 0 ||
        selinux_procattr::setexeccon("u:r:init:s0") != 0 ||
        ::__system_property_set("ctl.restart", "zygote") != 0)
        return static_cast<KModErr>(-(errno ? errno : EIO));
    return KModErr::OK;
    };
    const auto error = execute();
    const auto closed = worker.close_checked();
    return is_failed(error) ? error : closed;
}

}  // namespace maplesu::sdk

#include "../maplesu/compat/install_zygote_exports_legacy_abi.h"
