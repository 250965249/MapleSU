// Exercise the production cache reader with real files, including sparse corruption.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <new>
#include "kernel_module_kit_umbrella.h"

namespace kernel_module { KModErr get_offset_cache(const char*, uint32_t&); }
static std::atomic<size_t> largest_allocation{0};

void* operator new(size_t size) {
    size_t previous = largest_allocation.load();
    while (previous < size && !largest_allocation.compare_exchange_weak(previous, size)) {}
    if (void* memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, size_t) noexcept { std::free(memory); }

extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c() {
    return "offset-reader-fixture";
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
}

int main() {
    namespace fs = std::filesystem;
    const fs::path directory = "/data/aaaaaaaaaaaaaaaaa/offset_cache/offset-reader-fixture";
    fs::create_directories(directory);
    unsigned checks = 0, failures = 0;
    auto expect = [&](bool condition) { ++checks; if (!condition) ++failures; };
    for (const auto length : {0u, 1u, 3u, 5u, 16u * 1024u * 1024u}) {
        const auto name = "length-" + std::to_string(length);
        const auto path = directory / name;
        std::ofstream(path, std::ios::binary).close();
        fs::resize_file(path, length);
        uint32_t value = 0xabcdef01;
        largest_allocation.store(0);
        expect(kernel_module::get_offset_cache(name.c_str(), value) == KModErr::ERR_MODULE_OFFSET_CACHE_TYPE);
        expect(value == 0xabcdef01);
        expect(largest_allocation.load() < 65536);
    }
    for (const uint32_t expected : {0u, 1u, UINT32_MAX}) {
        const auto name = "value-" + std::to_string(expected);
        const auto path = directory / name;
        std::ofstream output(path, std::ios::binary);
        output.write(reinterpret_cast<const char*>(&expected), sizeof(expected));
        output.close();
        uint32_t value = ~expected;
        expect(kernel_module::get_offset_cache(name.c_str(), value) == KModErr::OK && value == expected);
        fs::remove(path);
        value = ~expected;
        expect(kernel_module::get_offset_cache(name.c_str(), value) == KModErr::OK && value == expected);
    }
    uint32_t value = 0xabcdef01;
    expect(kernel_module::get_offset_cache("missing", value) == KModErr::ERR_MODULE_OFFSET_CACHE_NOT_FOUND);
    expect(value == 0xabcdef01);
    std::printf("{\"checks\":%u,\"failures\":%u}\n", checks, failures);
    return failures ? 1 : 0;
}
