#include "kernel_module_kit_umbrella.h"
#include "task_comm_scan.h"
#include <atomic>
#include <limits>
#include <sys/prctl.h>

namespace random_utils {
std::vector<uint8_t> generate_unique_non_zero_bytes(size_t);
}

namespace {
class RestoreName {
    const char* name_;
    bool active_ = true;
public:
    explicit RestoreName(const char* name) : name_(name) {}
    ~RestoreName() { if (active_) prctl(PR_SET_NAME, name_, 0, 0, 0); }
    KModErr restore() {
        if (prctl(PR_SET_NAME, name_, 0, 0, 0) != 0)
            return KModErr::ERR_MODULE_PR_SET_NAME;
        active_ = false;
        return KModErr::OK;
    }
};
}

namespace kernel_module {
KModErr get_task_struct_comm_offset(uint32_t& offset) {
    static std::atomic<uint32_t> cached{0};
    if (const auto known = cached.load(std::memory_order_relaxed)) {
        offset = known;
        return KModErr::OK;
    }
    char original[16]{};
    if (prctl(PR_GET_NAME, original, 0, 0, 0) != 0)
        return KModErr::ERR_MODULE_PR_GET_NAME;
    auto random = random_utils::generate_unique_non_zero_bytes(15);
    random.push_back(0);
    RestoreName restore(original);
    if (prctl(PR_SET_NAME, random.data(), 0, 0, 0) != 0)
        return KModErr::ERR_MODULE_PR_SET_NAME;
    uint8_t name[16]{};
    if (prctl(PR_GET_NAME, name, 0, 0, 0) != 0 ||
        std::memcmp(name, random.data(), sizeof(name)) != 0)
        return KModErr::ERR_MODULE_PR_SET_NAME;

    // Use the SDK's current-task emitter, retaining all THREAD_INFO variants,
    // and publish through its existing command-3 credential reply ABI.
    auto context = init_aarch64_asm();
    auto a = context.assembler();
    arm64_module_asm_func_start(a);
    export_symbol::get_current(a, asmjit::a64::x0);
    arm64_module_asm_func_end(a, asmjit::a64::x0);
    const auto bytes = aarch64_asm_to_bytes(a);
    if (context.has_error() || bytes.empty()) return KModErr::ERR_MODULE_ASM;
    uint64_t task = 0;
    auto error = execute_kernel_asm_func(bytes, task);
    if (is_failed(error)) return error;
    if (task < 0xffff000000000000ULL ||
        task > std::numeric_limits<uint64_t>::max() - 8191)
        return KModErr::ERR_MODULE_NOT_KADDR;
    error = maplesu_task_comm::scan(task, name, offset,
        [](uint64_t address, void* output, uint32_t size) {
            return read_kernel_mem(address, output, size);
        });
    const auto restored = restore.restore();
    if (is_failed(restored)) return restored;
    if (is_failed(error)) return error;
    cached.store(offset, std::memory_order_relaxed);
    return KModErr::OK;
}
}
