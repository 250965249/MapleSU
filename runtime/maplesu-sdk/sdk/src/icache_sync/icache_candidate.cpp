#include <atomic>
#include <cstdio>
#include <cstring>
#include <sched.h>
#include "module_err_def.h"
#include "icache_policy.h"

extern "C" __attribute__((visibility("hidden")))
long long maple_icache_execute_once();

namespace {
using namespace maple_icache;
static_assert(sizeof(Mask) == 128, "Match baseline 1024-CPU mask ABI");
static_assert(sizeof(cpu_set_t) == sizeof(Mask), "Match platform affinity ABI");
static_assert(alignof(Mask) >= alignof(cpu_set_t), "Match platform affinity alignment");
static_assert(sizeof(KModErr) == 8, "Match original i64 return ABI");
static_assert(static_cast<Error>(KModErr::ERR_MODULE_GET_CPU) == kGetCpu);
static_assert(static_cast<Error>(KModErr::ERR_MODULE_SET_CPU) == kSetCpu);
static_assert(static_cast<Error>(KModErr::ERR_MODULE_ASM) == kAsm);

struct AndroidOps {
    Error save(Mask& out) noexcept {
        return sched_getaffinity(0, sizeof(out), reinterpret_cast<cpu_set_t*>(&out)) == 0
            ? 0 : kGetCpu;
    }
    Error online(Mask& out) noexcept {
        FILE* file = std::fopen("/sys/devices/system/cpu/online", "re");
        if (!file) return kGetCpu;
        char line[8192]{};
        const bool read = std::fgets(line, sizeof(line), file) != nullptr;
        const bool complete = std::fgetc(file) == EOF && !std::ferror(file);
        std::fclose(file);
        return read && complete && parse_online(line, out) ? 0 : kGetCpu;
    }
    Error bind(int cpu) noexcept {
        Mask one{}; set(one, cpu);
        if (sched_setaffinity(0, sizeof(one), reinterpret_cast<cpu_set_t*>(&one)) != 0)
            return kSetCpu;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return 0;
    }
    int current() noexcept { return sched_getcpu(); }
    Error execute() { return maple_icache_execute_once(); }
    Error restore(const Mask& original) noexcept {
        if (sched_setaffinity(0, sizeof(original), reinterpret_cast<const cpu_set_t*>(&original)) != 0)
            return kSetCpu;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        Mask actual{};
        if (save(actual) != 0 || std::memcmp(&actual, &original, sizeof(Mask)) != 0)
            return kSetCpu;
        return 0;
    }
};
}

namespace kernel_module {
__attribute__((visibility("hidden"))) KModErr icache_invalidate_all_cpus() {
    AndroidOps operations;
    return static_cast<KModErr>(maple_icache::run(operations));
}
}
