// Link against the delivered SDK; intercept kernel I/O before it is submitted.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include "kernel_module_kit_umbrella.h"

static int calls;
static int64_t failure;
static uint64_t reply;
extern "C" KModErr __wrap__ZN13kernel_module27get_task_struct_comm_offsetERj(uint32_t& out) {
    out = 2104;
    return KModErr::OK;
}
extern "C" bool __wrap__ZN13kernel_module29is_CONFIG_THREAD_INFO_IN_TASKEv() { return true; }
extern "C" KModErr __wrap__ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm(
    const std::vector<uint8_t>& code, uint64_t& out) {
    ++calls;
    std::printf("code=");
    for (auto byte : code) std::printf("%02x", byte);
    std::printf("\n");
    if (failure) return static_cast<KModErr>(failure);
    out = reply;
    return KModErr::OK;
}

int main(int argc, char** argv) {
    assert(argc == 3);
    failure = std::strtoll(argv[1], nullptr, 10);
    reply = std::strtoull(argv[2], nullptr, 10);
    uint32_t out = 0x12345678;
    const auto error = kernel_module::get_task_struct_real_cred_offset(out);
    if (failure || !reply || (reply != 2080 && reply != 2088)) {
        assert(is_failed(error) && out == 0x12345678 && calls == 1);
    } else {
        assert(is_ok(error) && out == reply && calls == 1);
        uint32_t cached = 0;
        assert(is_ok(kernel_module::get_task_struct_real_cred_offset(cached)));
        assert(cached == out && calls == 1);
    }
    std::printf("PASS error=%lld output=%u executions=%d\n", (long long)to_num(error), out, calls);
    return 0;
}
