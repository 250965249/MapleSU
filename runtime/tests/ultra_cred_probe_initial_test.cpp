// Capture the delivered credential probes; every kernel transport is blocked.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "kernel_module_kit_umbrella.h"

static constexpr uint64_t initial_cred = 0xffff800001000000ULL;
static int executions, reads, lookups;
extern "C" bool __wrap__ZN13kernel_module29is_CONFIG_THREAD_INFO_IN_TASKEv() { return true; }
extern "C" bool __wrap__ZN13kernel_module34is_CURRENT_FROM_SP_EL0_THREAD_INFOEv() { std::abort(); }
extern "C" KModErr __wrap__ZN13kernel_module27get_task_struct_cred_offsetERj(uint32_t& out) {
    out = 0x588;
    return KModErr::OK;
}
extern "C" KModErr __wrap__ZN13kernel_module20kallsyms_lookup_nameEPKcRNS_9SymbolHitENS_15SymbolMatchModeE(
    const char* name, kernel_module::SymbolHit& out, kernel_module::SymbolMatchMode) {
    ++lookups;
    std::printf("lookup=%s\n", name);
    assert(std::strcmp(name, "init_cred") == 0);
    out.addr = initial_cred;
    return KModErr::OK;
}
static KModErr capture(const uint8_t* code, size_t size, uint64_t&) {
    ++executions;
    std::printf("code=");
    for (size_t i = 0; i < size; ++i) std::printf("%02x", code[i]);
    std::printf("\n");
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}
extern "C" KModErr __wrap__ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm(
    const std::vector<uint8_t>& code, uint64_t& out) { return capture(code.data(), code.size(), out); }
extern "C" KModErr __wrap__ZN13kernel_module32execute_kernel_asm_func_with_bufEPKhjRm(
    const uint8_t* code, uint32_t size, uint64_t& out) { return capture(code, size, out); }
extern "C" KModErr __wrap__ZN13kernel_module15read_kernel_memEmPvj(uint64_t address, void*, uint32_t size) {
    ++reads;
    std::printf("read=%016llx,%u\n", (unsigned long long)address, size);
    assert(address == initial_cred && size == 8 && reads == 1);
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}
extern "C" KModErr __wrap__ZN13kernel_module23request_kernel_read_memEmPvj(uint64_t, void*, uint32_t) { std::abort(); }
extern "C" KModErr __wrap__ZN13kernel_module24request_kernel_write_memEmPKvj(uint64_t, const void*, uint32_t) { std::abort(); }
extern "C" __attribute__((noreturn)) void fixture_forbidden_syscall(long number) {
    std::fprintf(stderr, "TRAP SDK exec syscall=%ld\n", number);
    std::abort();
}
asm(".text\n.global __wrap_syscall\n.type __wrap_syscall,%function\n"
    "__wrap_syscall:\n cmp x0,#221\n b.eq fixture_forbidden_syscall\n"
    " cmp x0,#281\n b.eq fixture_forbidden_syscall\n b __real_syscall\n");
extern "C" int __wrap_execve(const char*, char* const*, char* const*) { std::abort(); }
int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    assert(argc == 2);
    uint32_t offset = 0x12345678;
    const bool cap = std::strcmp(argv[1], "cap") == 0;
    const auto error = cap ? kernel_module::get_cred_cap_inheritable_offset(offset)
        : std::strcmp(argv[1], "euid") == 0 ? kernel_module::get_cred_euid_offset(offset)
        : kernel_module::get_cred_uid_offset(offset);
    assert(error == KModErr::ERR_MODULE_OFFSET_NOT_FOUND);
    assert(cap ? executions == 0 && reads == 1 && lookups == 1 : executions == 1 && reads == 0 && lookups == 0);
    std::printf("PASS probe=%s executions=%d reads=%d lookups=%d\n", argv[1], executions, reads, lookups);
}
