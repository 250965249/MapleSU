#include "fixture.h"
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    auto& s = fixture::state;
    s.target = argv[1]; s.mode = argv[2];
    const uint32_t length = static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10));
    if (s.target != "stack" && s.target != "mm") return 2;
    s.image.assign(length, 0x5a);
    const bool cached = s.mode == "cache-zero" || s.mode == "cache-hit";
    const bool match = s.mode == "last" || s.mode == "first" || s.mode == "legacy"
        || s.mode == "cache-write-error" || s.mode == "cache-read-error";
    uint32_t candidate = 4;
    if (s.mode == "last") candidate = length - 8;
    if (s.mode == "first") candidate = 0;
    if (match) {
        if (length < 8 || candidate > length - 8) return 2;
        const uint64_t word = s.target == "stack" ? fixture::stack : fixture::mm;
        std::memcpy(s.image.data() + candidate, &word, sizeof(word));
    }
    KModErr expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    uint32_t expected_offset = 0;
    if (cached) { expected = KModErr::OK; expected_offset = s.mode == "cache-zero" ? 0 : 144; }
    else if (match && candidate != 0) { expected = KModErr::OK; expected_offset = candidate; }
    if (s.mode == "cache-write-error") expected = KModErr::ERR_MODULE_OFFSET_CACHE_WRITE;
    if (s.mode == "comm-error" || s.mode == "mm-get-error") expected = KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    if (s.mode == "task-symbol-error" || s.mode == "stack-symbol-error" || s.mode == "legacy-symbol-error")
        expected = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    if (s.mode == "read-error") expected = KModErr::ERR_MODULE_READ_FILE;
    if (s.mode == "mmput-error") expected = KModErr::ERR_MODULE_PARAM;
    if (s.mode == "execute-error") expected = KModErr::ERR_MODULE_TEST_CHANNEL;
    if (s.mode == "current-error") expected = KModErr::ERR_MODULE_NOT_KADDR;
    const bool early_error = !cached && !match && s.mode != "no-match";
    if (early_error) expected_offset = 999;
    const unsigned expected_put = match && candidate != 0 ? 1 : 0;
    std::printf("{\"phase\":\"start\",\"target\":\"%s\",\"mode\":\"%s\",\"length\":%u}\n",
        s.target.c_str(), s.mode.c_str(), length);
    std::fflush(stdout);
    uint32_t offset = 999;
    const KModErr actual = s.target == "stack" ? kernel_module::get_task_struct_stack_offset(offset)
        : kernel_module::get_task_struct_mm_offset(offset);
    bool calls = s.cache_get == 1 && s.cache_put == expected_put;
    if (expected_put) calls &= s.saved_offset == candidate;
    if (cached) calls &= s.reads == 0 && s.symbols == 0 && s.comm == 0 && s.execute == 0 && s.current == 0;
    if (s.mode == "comm-error" || s.mode.find("symbol-error") != std::string::npos) calls &= s.reads == 0;
    if (s.mode == "mm-get-error") calls &= s.mm_get == 1 && s.mm_put == 0 && s.execute == 0 && s.current == 0;
    if (s.mode == "mmput-error") calls &= s.mm_get == 1 && s.mm_put == 1 && s.execute == 0 && s.current == 0;
    if (s.mode == "execute-error") calls &= s.execute == 1 && s.current == 0 && s.reads == 0;
    if (s.mode == "current-error") calls &= s.execute == 1 && s.current == 1 && s.reads == 0;
    const bool passed = actual == expected && offset == expected_offset && s.contract && calls;
    std::printf("{\"phase\":\"complete\",\"passed\":%s,\"target\":\"%s\",\"mode\":\"%s\",\"length\":%u,\"error\":%zd,\"expected_error\":%zd,\"offset\":%u,\"expected_offset\":%u,\"cache_put\":%u,\"trace\":\"%s\"}\n",
        passed ? "true" : "false", s.target.c_str(), s.mode.c_str(), length,
        to_num(actual), to_num(expected), offset, expected_offset, s.cache_put, s.trace.c_str());
    return passed ? 0 : 1;
}
