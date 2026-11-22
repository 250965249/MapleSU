#include "kernel_module_kit_umbrella.h"
#include <array>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <sys/prctl.h>

static std::string scenario;
static constexpr uint64_t task = 0xffff800001000000ULL;
static const char original[16] = "initial worker";
static char current[16];
static unsigned gets, sets, restores, reads, executions, emits;
static asmjit::a64::Assembler assembler;

extern "C" int __wrap_prctl(int option, ...) {
    va_list args;
    va_start(args, option);
    auto buffer = va_arg(args, char*);
    va_end(args);
    if (option == PR_GET_NAME) {
        ++gets;
        if ((gets == 1 && scenario == "initial-get-fail") ||
            (gets == 2 && scenario == "verify-get-fail")) return -1;
        std::memcpy(buffer, current, 16);
        if (gets == 2 && scenario == "mismatch") buffer[0] ^= 0x7f;
        return 0;
    }
    assert(option == PR_SET_NAME);
    ++sets;
    const bool restoring = std::memcmp(buffer, original, 16) == 0;
    if (restoring) {
        ++restores;
        if (scenario == "restore-fail" && restores == 1) return -1;
    } else if (scenario == "initial-set-fail") return -1;
    std::memcpy(current, buffer, 16);
    return 0;
}

namespace random_utils {
std::vector<uint8_t> generate_unique_non_zero_bytes(size_t size) {
    assert(size == 15);
    std::vector<uint8_t> value(size);
    for (size_t i = 0; i < size; ++i) value[i] = i + 1;
    return value;
}
}
aarch64_asm_ctx init_aarch64_asm() { return {}; }
asmjit::a64::Assembler* aarch64_asm_ctx::assembler() { return &::assembler; }
bool aarch64_asm_ctx::has_error() { return scenario == "asm-error"; }
std::vector<uint8_t> aarch64_asm_to_bytes(asmjit::a64::Assembler*) { return {0}; }
namespace kernel_module {
void arm64_module_asm_func_start(asmjit::a64::Assembler*) {}
void arm64_module_asm_func_end(asmjit::a64::Assembler*, asmjit::a64::GpX output) { assert(output.id == 0); }
namespace export_symbol {
void get_current(asmjit::a64::Assembler*, asmjit::a64::GpX output) { assert(output.id == 0); ++emits; }
}
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&, uint64_t& output) {
    ++executions;
    if (scenario == "exception") throw std::bad_alloc();
    if (scenario == "execute-error") return KModErr::ERR_MODULE_NOT_KADDR;
    output = scenario == "invalid-task" ? 0 : task;
    return KModErr::OK;
}
KModErr read_kernel_mem(uint64_t address, void* output, uint32_t size) {
    ++reads;
    if (scenario == "read-error") return KModErr::ERR_MODULE_NOT_KADDR;
    if (scenario == "read-exception") throw std::bad_alloc();
    assert(address >= task && address - task + size <= 8192);
    auto bytes = static_cast<uint8_t*>(output);
    for (unsigned i = 0; i < size; ++i) {
        const auto index = address - task + i;
        bytes[i] = scenario != "not-found" && index >= 2096 && index < 2111 ? index - 2095 : 0;
    }
    return KModErr::OK;
}
}
int main(int argc, char** argv) {
    assert(argc == 2);
    scenario = argv[1];
    std::memcpy(current, original, 16);
    uint32_t offset = 0;
    KModErr result = KModErr::ERR_MODULE_PARAM;
    bool threw = false;
    try { result = kernel_module::get_task_struct_comm_offset(offset); }
    catch (const std::bad_alloc&) { threw = true; }
    assert(std::memcmp(current, original, 16) == 0);
    if (scenario == "success") {
        assert(result == KModErr::OK && offset == 2096 && reads == 9 && executions == 1 && emits == 1);
        const auto old_reads = reads, old_gets = gets, old_sets = sets;
        offset = 0;
        assert(kernel_module::get_task_struct_comm_offset(offset) == KModErr::OK && offset == 2096);
        assert(reads == old_reads && gets == old_gets && sets == old_sets);
    } else if (scenario == "exception" || scenario == "read-exception") assert(threw);
    else if (scenario == "initial-get-fail") assert(result == KModErr::ERR_MODULE_PR_GET_NAME && restores == 0);
    else if (scenario == "asm-error") assert(result == KModErr::ERR_MODULE_ASM);
    else if (scenario == "execute-error" || scenario == "invalid-task" || scenario == "read-error")
        assert(result == KModErr::ERR_MODULE_NOT_KADDR);
    else if (scenario == "not-found") assert(result == KModErr::ERR_MODULE_OFFSET_NOT_FOUND);
    else assert(result == KModErr::ERR_MODULE_PR_SET_NAME);
    if (scenario != "initial-get-fail") assert(restores >= 1);
    std::printf("PASS task comm lifecycle: %s name restored, cache success only\n", argv[1]);
}
