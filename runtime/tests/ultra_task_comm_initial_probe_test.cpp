// Exercise the delivered SDK's first comm-offset lookup without kernel I/O.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include "kernel_module_kit_umbrella.h"

static constexpr uint64_t task = 0xffff800001000000ULL;
static int executions, reads, configs;

extern "C" bool __wrap__ZN13kernel_module29is_CONFIG_THREAD_INFO_IN_TASKEv() {
    ++configs;
    return true;
}
extern "C" bool __wrap__ZN13kernel_module34is_CURRENT_FROM_SP_EL0_THREAD_INFOEv() {
    std::printf("TRAP unexpected CURRENT_FROM_SP_EL0_THREAD_INFO\n");
    std::abort();
}
static KModErr capture(const uint8_t* code, size_t size, uint64_t& out) {
    ++executions;
    std::printf("code=");
    for (size_t i = 0; i < size; ++i) std::printf("%02x", code[i]);
    std::printf("\n");
    out = task;
    return KModErr::OK;
}
extern "C" KModErr __wrap__ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm(
    const std::vector<uint8_t>& code, uint64_t& out) {
    return capture(code.data(), code.size(), out);
}
extern "C" KModErr __wrap__ZN13kernel_module32execute_kernel_asm_func_with_bufEPKhjRm(
    const uint8_t* code, uint32_t size, uint64_t& out) {
    return capture(code, size, out);
}
extern "C" KModErr __wrap__ZN13kernel_module15read_kernel_memEmPvj(
    uint64_t address, void*, uint32_t size) {
    ++reads;
    std::printf("read=%016llx,%u\n", (unsigned long long)address, size);
    assert(address == task && size == 15 && reads == 1);
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}
extern "C" KModErr __wrap__ZN13kernel_module23request_kernel_read_memEmPvj(uint64_t, void*, uint32_t) {
    std::printf("TRAP request_kernel_read_mem\n");
    std::abort();
}
extern "C" KModErr __wrap__ZN13kernel_module24request_kernel_write_memEmPKvj(uint64_t, const void*, uint32_t) {
    std::printf("TRAP request_kernel_write_mem\n");
    std::abort();
}
extern "C" __attribute__((noreturn)) void fixture_forbidden_syscall(long number) {
    std::fprintf(stderr, "TRAP SDK exec syscall=%ld\n", number);
    std::abort();
}
// Forward libc's gettid/futex calls with the original argument registers intact.
// The SDK transports requests through execve; intercept both execution syscalls.
asm(".text\n.global __wrap_syscall\n.type __wrap_syscall,%function\n"
    "__wrap_syscall:\n cmp x0,#221\n b.eq fixture_forbidden_syscall\n"
    " cmp x0,#281\n b.eq fixture_forbidden_syscall\n b __real_syscall\n");
extern "C" int __wrap_execve(const char*, char* const*, char* const*) { std::printf("TRAP execve\n"); std::abort(); }

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::puts("fixture-start");
    uint32_t offset = 0x12345678;
    const auto error = kernel_module::get_task_struct_comm_offset(offset);
    assert(error == KModErr::ERR_MODULE_OFFSET_NOT_FOUND);
    assert(executions == 1 && reads == 1 && configs == 1);
    std::printf("PASS error=%lld executions=%d reads=%d configs=%d task=%016llx\n",
                (long long)to_num(error), executions, reads, configs, (unsigned long long)task);
}
