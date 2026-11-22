#include "module_err_def.h"
#include "aarch64_asm_helper.h"
#include "module_base_kernel_mem.h"
#include "module_base_kernel_symbol_kaddr.h"
#include <array>
#include <cassert>
#include <cstring>
#include <fstream>
#include <iterator>
#include "../ultra/authorization/kernel_read_metadata.h"

extern "C" KModErr __wrap__ZN13kernel_module23request_kernel_read_memEmPvj(uint64_t, void*, uint32_t);

namespace {
constexpr uint64_t source = 0xffff800000500ff8ULL;
constexpr uint64_t metadata = 0xffff800000700010ULL;
constexpr uint64_t nofault = 0xffff800000900000ULL;
constexpr uint64_t copy_user = 0xffff800000901000ULL;
std::vector<uint8_t> frame_start, frame_end;
std::array<uint8_t, 600> output;
std::string mode;
bool resolving;
int bootstrap_calls, read_calls, lookups;
uint32_t bootstrap_offset, bootstrap_remaining;
uint8_t pattern(size_t index) { return static_cast<uint8_t>(index * 37 + 11); }
}

namespace kernel_module {
KModErr get_append_package_run_fake_proc_path_addr(uint64_t& output) {
    output = mode == "bad-anchor" ? 0 : metadata + 8;
    return KModErr::OK;
}
void arm64_module_asm_func_start(asmjit::a64::Assembler* a) {
    a->embed(frame_start.data(), frame_start.size());
}
void arm64_module_asm_func_end(asmjit::a64::Assembler* a, asmjit::a64::GpX result) {
    assert(result.id() == 0);
    a->embed(frame_end.data(), frame_end.size());
}
KModErr kallsyms_lookup_name(const char* name, SymbolHit& out, SymbolMatchMode) {
    ++lookups;
    if (lookups == 1) {
        resolving = true;
        uint64_t value = 0;
        const auto before = bootstrap_calls;
        assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(metadata - 1, &value, 1)));
        assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(metadata + 8, &value, 1)));
        assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(metadata + 7, &value, 2)));
        assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(metadata + 0x29, &value, 2)));
        assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(metadata + 0x33, &value, 2)));
        assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(metadata + 0x1000, &value, 4)));
        assert(before == bootstrap_calls);
        bootstrap_offset = 0;
        bootstrap_remaining = 8;
        const auto error = __wrap__ZN13kernel_module23request_kernel_read_memEmPvj(metadata, &value, 8);
        if (is_failed(error)) { resolving = false; return error; }
        assert(value == 0x1716151413121110ULL);
        for (const auto request : {std::pair<uint32_t, uint32_t>{0x30, 4}, {0, 4}, {0x2a, 6}, {4, 4}}) {
            bootstrap_offset = request.first;
            bootstrap_remaining = request.second;
            value = 0;
            assert(is_ok(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(
                metadata + request.first, &value, request.second)));
            uint64_t expected = 0;
            for (uint32_t i = 0; i < request.second; ++i)
                expected |= uint64_t{0x10 + request.first + i} << (i * 8);
            assert(value == expected);
        }
        resolving = false;
    }
    const bool primary = std::strcmp(name, "copy_from_kernel_nofault") == 0;
    const bool older = std::strcmp(name, "probe_kernel_read") == 0;
    if (primary || older || std::strcmp(name, "__probe_kernel_read") == 0) {
        if (mode == "missing" || (primary && mode == "older")) return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
        out.addr = nofault;
    } else {
        assert(std::strcmp(name, "copy_to_user_nofault") == 0);
        if (mode == "raw-only") return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
        out.addr = copy_user;
    }
    return KModErr::OK;
}
KModErr execute_kernel_asm_func_with_buf(const uint8_t* code, uint32_t size, uint64_t& result) {
    const int index = resolving ? bootstrap_calls++ : read_calls++ % 3;
    const auto count = std::min(uint32_t{7}, bootstrap_remaining);
    std::printf("capture=%s,%d,%s,%u,%u,", resolving ? "bootstrap" : "read", index, mode.c_str(),
                resolving ? bootstrap_offset : 0, resolving ? count : 0);
    for (uint32_t i = 0; i < size; ++i) std::printf("%02x", code[i]);
    std::printf("\n");
    result = 0;
    if (resolving) {
        if (mode == "bootstrap-fault") result = 1ULL << 63;
        else {
            for (uint32_t i = 0; i < count; ++i)
                result |= uint64_t{0x10 + bootstrap_offset + i} << (i * 8);
            bootstrap_offset += count;
            bootstrap_remaining -= count;
        }
    } else {
        if (mode == "execute-error") return KModErr::ERR_MODULE_ASM;
        if (mode == "fault" || mode == "cross-page-fault" || mode == "copy-fault") {
            result = static_cast<uint64_t>(KModErr::ERR_MODULE_NOT_KADDR);
            if (mode == "copy-fault") output[0] = pattern(0);
        }
        else {
            const size_t begin = static_cast<size_t>(index) * 256;
            const size_t end = std::min(begin + 256, output.size());
            for (size_t i = begin; i < end; ++i) output[i] = pattern(i);
        }
    }
    return KModErr::OK;
}
}

int main(int argc, char** argv) {
    assert(argc == 4);
    mode = argv[1];
    auto load = [](const char* path) {
        std::ifstream file(path, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
    };
    frame_start = load(argv[2]);
    frame_end = load(argv[3]);
    assert(!frame_start.empty() && !frame_end.empty());
    output.fill(0xa5);
    const auto error = __wrap__ZN13kernel_module23request_kernel_read_memEmPvj(source, output.data(), output.size());
    const bool success = mode == "good" || mode == "older";
    assert(success ? is_ok(error) : is_failed(error));
    assert(bootstrap_calls == (mode == "bad-anchor" ? 0 : mode == "bootstrap-fault" ? 1 : 6));
    assert(read_calls == (success ? 3 : mode == "missing" || mode == "raw-only" || mode == "bootstrap-fault" || mode == "bad-anchor" ? 0 : 1));
    for (size_t i = 0; i < output.size(); ++i)
        assert(output[i] == (success || (mode == "copy-fault" && i == 0) ? pattern(i) : 0xa5));
    if (success) {
        const auto resolved = lookups;
        output.fill(0xa5);
        assert(is_ok(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(source, output.data(), output.size())));
        assert(lookups == resolved && bootstrap_calls == 6 && read_calls == 6);
        for (size_t i = 0; i < output.size(); ++i) assert(output[i] == pattern(i));
    }
    if (mode == "missing" || mode == "raw-only") {
        assert(error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST);
        const auto failed_lookups = lookups;
        const auto previous_mode = mode;
        mode = "good";
        assert(is_ok(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(source, output.data(), output.size())));
        assert(lookups == failed_lookups + 2 && read_calls == 3 && bootstrap_calls == 6);
        for (size_t i = 0; i < output.size(); ++i) assert(output[i] == pattern(i));
        mode = previous_mode;
    }
    const int before = bootstrap_calls + read_calls;
    assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(source, nullptr, 1)));
    assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(source, output.data(), 0)));
    assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(0x1000, output.data(), 1)));
    assert(is_failed(__wrap__ZN13kernel_module23request_kernel_read_memEmPvj(UINT64_MAX - 1, output.data(), 4)));
    assert(before == bootstrap_calls + read_calls);
    std::printf("PASS mode=%s bootstrap=%d batches=%d lookups=%d\n", mode.c_str(), bootstrap_calls, read_calls, lookups);
}
