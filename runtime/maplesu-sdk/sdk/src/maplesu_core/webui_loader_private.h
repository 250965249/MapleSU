// webui loader private implementation.
//
#pragma once

#define module_desc public_packed_module_desc
#define module_record public_packed_module_record
#include "kernel_module_kit_umbrella.h"
#undef module_desc
#undef module_record

#include <sched.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// 安装期注入的私有 helper（名字带固定 hash 后缀；声明处见
// include/third_party/____DO_NOT_EDIT____/private_desc_parser.h:40）。
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(
    const char* root_key);

// MapleSU 模块 ROOT 环境切换（实现在别的成员里，本 TU 只引用）。
namespace default_modules::module_root {
KModErr set_current_root(bool current);
}

namespace maplesu::sdk {

// 即 web_ui 在 9216、min_sdk_ver 三字段在 9220/9224/9228。
struct module_desc {
    char name[1024] = {};
    char version[1024] = {};
    char desc[4096] = {};
    char author[1024] = {};
    char id32[1024] = {};
    char update_json[1024] = {};
    bool web_ui = false;
    MapleSUSdkVersion min_sdk_ver = {};
};
struct module_record {
    module_desc desc;
    ModuleRunState state = ModuleRunState::NotRunning;
};
static_assert(sizeof(module_desc) == 9232 && alignof(module_desc) == 4,
              "layout constraint violated");
static_assert(offsetof(module_desc, web_ui) == 9216, "unexpected layout size");
static_assert(offsetof(module_desc, min_sdk_ver) == 9220, "unexpected layout size");
static_assert(sizeof(module_record) == 9236 && alignof(module_record) == 4,
              "natural module_record（packed 版是 9233）");

// 由 maplesu_module_elf_meta.o（idx 54）提供；本 TU 只引用（U 集里的一条）。
KModErr parse_module_meta_from_elf_bytes(const std::vector<uint8_t>& elf_bytes,
                                         module_desc& out_desc);

// fork 管道基座：4 个通信 fd + 本进程 pid + 子进程 pid = 6 × i32 = 24 B。
class fork_base_info {
public:
    fork_base_info() {
        fd_parent_to_child_read = -1;
        fd_parent_to_child_write = -1;
        fd_child_to_parent_read = -1;
        fd_child_to_parent_write = -1;
        self_pid = -1;
        child_pid = -1;
        reset();
    }

    ~fork_base_info() { close_all(); }

    void reset() {
        close_all();
        fd_parent_to_child_read = -1;
        fd_parent_to_child_write = -1;
        fd_child_to_parent_read = -1;
        fd_child_to_parent_write = -1;
        self_pid = static_cast<int32_t>(::getpid());
        child_pid = 0;
    }

    void close_all() {
        safe_close(fd_parent_to_child_read);
        safe_close(fd_parent_to_child_write);
        safe_close(fd_child_to_parent_read);
        safe_close(fd_child_to_parent_write);
    }

    static void safe_close(int32_t& fd) {
        if (fd > -1) {
            ::close(fd);
            fd = -1;
        }
    }

    int32_t fd_parent_to_child_read;
    int32_t fd_parent_to_child_write;
    int32_t fd_child_to_parent_read;
    int32_t fd_child_to_parent_write;
    int32_t self_pid;
    int32_t child_pid;
};

class fork_pipe_info : public fork_base_info {};

static_assert(sizeof(fork_base_info) == 24 && alignof(fork_base_info) == 4,
              "layout constraint violated");
static_assert(sizeof(fork_pipe_info) == 24, "layout constraint violated");
static_assert(offsetof(fork_base_info, self_pid) == 16 && offsetof(fork_base_info, child_pid) == 20,
              "unexpected layout size");

// 由 maplesu_fork_helper.o（idx 46）提供（U 集里的三条）。
bool fork_pipe_child_process(fork_pipe_info& pipe);
bool write_errcode_from_child(const fork_pipe_info& pipe, KModErr err);
bool read_errcode_from_child(const fork_pipe_info& pipe, KModErr& out_err);

}  // namespace maplesu::sdk

// CpuPinGuardAuto：把当前线程临时绑到 sched_getcpu() 返回的 CPU 上，
// 析构时把 sched_getaffinity() 抓到的原始掩码写回。全局命名空间。
//
// 都在下面逐条还原。
class CpuPinGuardAuto {
public:
    explicit CpuPinGuardAuto(bool verbose) {
        m_pinned = false;
        m_pinned_cpu = -1;
        m_verbose = verbose;
        CPU_ZERO(&m_original_affinity);
        if (sched_getaffinity(0, sizeof(cpu_set_t), &m_original_affinity) != 0) {
            if (m_verbose) {
                std::fprintf(stderr, "CpuPinGuardAuto: sched_getaffinity failed: %s\n",
                             std::strerror(errno));
            }
            return;
        }
        const int cpu = sched_getcpu();
        if (cpu < 0) {
            if (m_verbose) {
                std::fprintf(stderr, "CpuPinGuardAuto: sched_getcpu failed: %s\n",
                             std::strerror(errno));
            }
            return;
        }
        m_pinned_cpu = cpu;
        cpu_set_t target_set;
        CPU_ZERO(&target_set);
        CPU_SET(cpu, &target_set);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &target_set) != 0) {
            if (m_verbose) {
                std::fprintf(stderr,
                             "CpuPinGuardAuto: sched_setaffinity(cpu %d) failed: %s\n",
                             cpu, std::strerror(errno));
            }
            return;
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        m_pinned = true;
        if (m_verbose) {
            std::printf("CpuPinGuardAuto: pinned to CPU %d\n", m_pinned_cpu);
        }
    }

    ~CpuPinGuardAuto() {
        if (!m_pinned) {
            return;
        }
        if (sched_setaffinity(0, sizeof(cpu_set_t), &m_original_affinity) != 0) {
            if (m_verbose) {
                std::fprintf(stderr,
                             "CpuPinGuardAuto: restore sched_setaffinity failed: %s\n",
                             std::strerror(errno));
            }
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        if (m_verbose) {
            std::printf("CpuPinGuardAuto: restored from CPU %d\n", m_pinned_cpu);
        }
    }

    CpuPinGuardAuto(const CpuPinGuardAuto&) = delete;
    CpuPinGuardAuto& operator=(const CpuPinGuardAuto&) = delete;
    CpuPinGuardAuto(CpuPinGuardAuto&&) = delete;
    CpuPinGuardAuto& operator=(CpuPinGuardAuto&&) = delete;

private:
    cpu_set_t m_original_affinity;  // offset 0   (128 B)
    bool m_pinned;                  // offset 128 是否成功绑过核
    int m_pinned_cpu;               // offset 132 绑到的 CPU / 恢复时用于打印
    bool m_verbose;                 // offset 136
};

static_assert(sizeof(CpuPinGuardAuto) == 144 && alignof(CpuPinGuardAuto) == 8,
              "layout constraint violated");
