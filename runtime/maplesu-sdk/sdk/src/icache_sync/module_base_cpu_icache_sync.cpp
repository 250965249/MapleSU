// module base cpu icache sync implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <sched.h>

#include "icache_policy.h"

// 本成员的“内层”：把 invalidate 全部 CPU 的汇编函数生成成机器码并执行一次。
extern "C" __attribute__((visibility("hidden"))) long long maple_icache_execute_once();

namespace kernel_module {

__attribute__((visibility("hidden"))) KModErr icache_invalidate_all_cpus();

// 平台侧操作集合：host seam 与 Android wrapper 共用 icache_policy.h 的 run<>。
namespace {

static_assert(sizeof(maple_icache::Mask) == 128, "Match baseline 1024-CPU mask ABI");
static_assert(sizeof(cpu_set_t) == sizeof(maple_icache::Mask), "Match platform affinity ABI");
static_assert(alignof(maple_icache::Mask) >= alignof(cpu_set_t), "Match platform affinity alignment");
static_assert(sizeof(KModErr) == 8, "Match original i64 return ABI");
static_assert(static_cast<maple_icache::Error>(KModErr::ERR_MODULE_GET_CPU) == maple_icache::kGetCpu);
static_assert(static_cast<maple_icache::Error>(KModErr::ERR_MODULE_SET_CPU) == maple_icache::kSetCpu);
static_assert(static_cast<maple_icache::Error>(KModErr::ERR_MODULE_ASM) == maple_icache::kAsm);

struct AndroidOps {
    maple_icache::Error save(maple_icache::Mask& out) noexcept {
        return sched_getaffinity(0, sizeof(out), reinterpret_cast<cpu_set_t*>(&out)) == 0
                   ? 0
                   : maple_icache::kGetCpu;
    }
    maple_icache::Error online(maple_icache::Mask& out) noexcept {
        FILE* file = std::fopen("/sys/devices/system/cpu/online", "re");
        if (!file) {
            return maple_icache::kGetCpu;
        }
        char line[8192]{};
        const bool read = std::fgets(line, sizeof(line), file) != nullptr;
        const bool complete = std::fgetc(file) == EOF && !std::ferror(file);
        std::fclose(file);
        return read && complete && maple_icache::parse_online(line, out) ? 0
                                                                        : maple_icache::kGetCpu;
    }
    maple_icache::Error bind(int cpu) noexcept {
        maple_icache::Mask one{};
        maple_icache::set(one, cpu);
        if (sched_setaffinity(0, sizeof(one), reinterpret_cast<cpu_set_t*>(&one)) != 0) {
            return maple_icache::kSetCpu;
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return 0;
    }
    int current() noexcept { return sched_getcpu(); }
    maple_icache::Error execute() { return maple_icache_execute_once(); }
    maple_icache::Error restore(const maple_icache::Mask& original) noexcept {
        if (sched_setaffinity(0, sizeof(original),
                              reinterpret_cast<const cpu_set_t*>(&original)) != 0) {
            return maple_icache::kSetCpu;
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        maple_icache::Mask actual{};
        if (save(actual) != 0 || std::memcmp(&actual, &original, sizeof(maple_icache::Mask)) != 0) {
            return maple_icache::kSetCpu;
        }
        return 0;
    }
};

}  // namespace

__attribute__((visibility("hidden"))) KModErr icache_invalidate_all_cpus() {
    AndroidOps operations;
    return static_cast<KModErr>(maple_icache::run(operations));
}

}  // namespace kernel_module

// 生成并执行“本 CPU I-cache 全失效”内核汇编函数。
//                 ic   iallu
//                 dsb  ish
//                 isb  sy
//                 arm64_module_asm_func_end
//                 execute_kernel_asm_func(code, result)
// IALLU 操作数为 936；旧 IR 中的 4 是 Imm 类型签名，不是 IC 操作数。
extern "C" __attribute__((visibility("hidden"))) long long maple_icache_execute_once() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (!a) {
        return static_cast<long long>(KModErr::ERR_MODULE_ASM);
    }

    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_ic_iallu(a);
    a->dsb(Imm(11));       // DSB ISH
    a->isb(Imm(15));       // ISB SY
    kernel_module::arm64_module_asm_func_end(a);

    uint64_t result = 0;
    return static_cast<long long>(
        kernel_module::execute_kernel_asm_func(aarch64_asm_to_bytes(a), result));
}
