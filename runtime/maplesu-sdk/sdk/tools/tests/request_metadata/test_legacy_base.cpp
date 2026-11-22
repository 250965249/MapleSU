// Actual m024 consumer; all kernel execution and metadata I/O are mocked.
#include "kernel_module_kit_umbrella.h"
#include "kernel_read_metadata.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

namespace {
constexpr uint64_t floor = UINT64_C(0xffff000000000000);
constexpr uint64_t append = floor + UINT64_C(0x200000);
constexpr uint64_t expected_base = append - UINT64_C(0x2000);
constexpr uint64_t unchanged = UINT64_C(0xa1b2c3d4e5f60718);
enum class Change { none, key, pid, short_key };
struct Fixture {
    std::string key = std::string(48, 'K');
    std::string parsed_key;
    pid_t pid = 123;
    bool missing_key = false, unterminated_key = false, supported = false;
    std::array<char, 1024> unterminated{};
    Change after_parse = Change::none, after_execute = Change::none, after_offset = Change::none;
    unsigned parsers = 0, executes = 0, offsets = 0;
    uint64_t probed = append;
    uint32_t append_offset = 0x2000;
    KModErr execute_error = KModErr::OK, offset_error = KModErr::OK, metadata_error = KModErr::OK;
};
Fixture state;
unsigned checks = 0, failures = 0;
void check(bool value, const char* label) {
    ++checks;
    if (!value) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); }
}
void change(Change requested) {
    if (requested == Change::key) state.key[0] = 'Z';
    if (requested == Change::pid) ++state.pid;
    if (requested == Change::short_key) state.key.pop_back();
}
void reset() {
    state = {};
    state.unterminated.fill('K');
    metadata_test::init_count = 0;
}
KModErr base(uint64_t& out) { return kernel_module::get_kernel_base_vaddr(out); }
void expect_error(KModErr expected, unsigned executes, unsigned offsets, const char* label) {
    uint64_t result = unchanged;
    check(base(result) == expected && result == unchanged && state.executes == executes &&
          state.offsets == offsets, label);
}
}

extern "C" pid_t getpid() { return state.pid; }
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return state.missing_key ? nullptr : state.unterminated_key ? state.unterminated.data() : state.key.c_str();
}

namespace kernel_module {
KModErr maplesu_kernel_metadata_v2(maplesu_metadata_v2& metadata, uint64_t& descriptor, bool& supported) {
    supported = state.supported;
    metadata = {};
    descriptor = append;
    metadata.kernel_base_displacement = -INT64_C(0x2000);
    return state.metadata_error;
}
void parser_root_key_info(const char* key, int32_t& result) {
    ++state.parsers;
    state.parsed_key = key;
    check(key != state.key.c_str(), "legacy parser receives the copied identity");
    result = 123;
    change(state.after_parse);
}
KModErr get_append_package_data_offset(uint32_t& result) {
    ++state.offsets;
    result = state.append_offset;
    change(state.after_offset);
    return state.offset_error;
}
void arm64_module_asm_func_start(Assembler*) {}
void arm64_module_asm_func_end(Assembler*) {}
void arm64_module_asm_func_end(Assembler*, GpX) {}
void maplesu_legacy_asm_func_start(Assembler*) {}
void maplesu_legacy_asm_func_end(Assembler*) {}
void maplesu_legacy_asm_func_end(Assembler*, GpX) {}
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&, uint64_t& result) {
    ++state.executes;
    result = state.probed;
    change(state.after_execute);
    return state.execute_error;
}
}

int main() {
    uint64_t result = unchanged;
    reset();
    check(base(result) == KModErr::OK && result == expected_base && state.executes == 1 &&
          state.offsets == 1 && state.parsed_key == state.key, "valid legacy base");
    reset(); state.key.assign(1023, 'K');
    check(base(result) == KModErr::OK && result == expected_base && state.parsed_key.size() == 1023,
          "legacy identity retains its 1024-byte bound");
    reset(); state.key.assign(1, 'K');
    check(base(result) == KModErr::OK && state.parsed_key == state.key,
          "consumer adds no new minimum Key length gate");
    for (unsigned kind = 0; kind < 3; ++kind) {
        reset();
        if (kind == 0) state.missing_key = true;
        if (kind == 1) state.key.clear();
        if (kind == 2) state.unterminated_key = true;
        expect_error(KModErr::ERR_MODULE_ROOT_KEY, 0, 0, "invalid Key stops before legacy execution");
    }
    for (uint64_t probed : {uint64_t(0), floor - 1}) {
        reset(); state.probed = probed;
        expect_error(KModErr::ERR_MODULE_INTERNAL_APPEND, 1, 0, "non-kernel locator never reaches offset I/O");
    }
    reset(); state.probed = floor; state.append_offset = 1;
    expect_error(KModErr::ERR_MODULE_INTERNAL_APPEND, 1, 1, "subtraction below kernel range preserves output");
    reset(); state.probed = 1; state.append_offset = UINT32_MAX;
    expect_error(KModErr::ERR_MODULE_INTERNAL_APPEND, 1, 0, "underflow candidate is rejected before offset I/O");
    reset(); state.probed = floor + UINT32_MAX; state.append_offset = UINT32_MAX;
    check(base(result) == KModErr::OK && result == floor, "full-width uint32 subtraction remains valid");
    for (Change changed : {Change::key, Change::pid, Change::short_key}) {
        reset(); state.after_parse = changed;
        expect_error(KModErr::ERR_MODULE_ROOT_KEY, 0, 0, "parse identity change stops before execution");
        reset(); state.after_execute = changed;
        expect_error(KModErr::ERR_MODULE_ROOT_KEY, 1, 0, "execution identity change stops before offset I/O");
        reset(); state.after_offset = changed;
        expect_error(KModErr::ERR_MODULE_ROOT_KEY, 1, 1, "offset identity change never publishes a mixed base");
    }
    reset(); state.execute_error = KModErr::ERR_MODULE_ASM;
    expect_error(KModErr::ERR_MODULE_ASM, 1, 0, "legacy execution error is preserved");
    reset(); state.offset_error = KModErr::ERR_MODULE_READ_FILE;
    expect_error(KModErr::ERR_MODULE_READ_FILE, 1, 1, "append offset error is preserved");
    reset(); state.supported = true;
    check(base(result) == KModErr::OK && result == expected_base && !state.parsers &&
          !state.executes && !state.offsets && !metadata_test::init_count,
          "v2 base retains its direct descriptor path");
    reset(); state.metadata_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    expect_error(KModErr::ERR_MODULE_TEST_CHANNEL, 0, 0, "metadata error never enters legacy");
    std::printf("legacy base: checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
