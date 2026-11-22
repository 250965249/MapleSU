#include <stdint.h>
#include "kernel_read_metadata.h"

extern "C" {
__attribute__((visibility("hidden"))) int64_t helper_append(uint64_t&);
__attribute__((visibility("hidden"))) int64_t helper_lookup(const char*, uint64_t&);
__attribute__((visibility("hidden"))) int64_t helper_execute(const uint8_t*, uint32_t, uint64_t&);
#define TEMPLATE(name) \
    __attribute__((visibility("hidden"))) extern const uint8_t name[]
TEMPLATE(maplesu_read_template);
TEMPLATE(maplesu_read_template_end);
TEMPLATE(maplesu_read_source);
TEMPLATE(maplesu_read_destination);
TEMPLATE(maplesu_read_size);
TEMPLATE(maplesu_read_nofault);
TEMPLATE(maplesu_read_usercopy);
TEMPLATE(maplesu_metadata_template);
TEMPLATE(maplesu_metadata_template_end);
TEMPLATE(maplesu_metadata_source);
TEMPLATE(maplesu_metadata_size);
#undef TEMPLATE
}

namespace {
constexpr int64_t parameter_error = -20000;
constexpr int64_t address_error = -19987;
constexpr int64_t append_error = -19996;
constexpr int64_t missing_symbol = -19978;
constexpr uint64_t kernel_min = 0xffff000000000000ULL;
constexpr uint32_t batch_size = 256;

uint32_t copy_template(uint8_t* output, const uint8_t* begin, const uint8_t* end) {
    const auto size = static_cast<uint32_t>(end - begin);
    for (uint32_t i = 0; i < size; ++i) output[i] = begin[i];
    return size;
}
void parameter(uint8_t* code, const uint8_t* begin, const uint8_t* slot, uint64_t value) {
    const auto offset = static_cast<uint32_t>(slot - begin);
    for (uint32_t i = 0; i < 8; ++i) code[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}
int64_t metadata(uint64_t source, uint8_t* destination, uint32_t size) {
    for (uint32_t done = 0; done < size;) {
        const auto count = size - done > 7 ? 7 : size - done;
        uint8_t code[512];
        const auto length = copy_template(code, maplesu_metadata_template, maplesu_metadata_template_end);
        parameter(code, maplesu_metadata_template, maplesu_metadata_source, source + done);
        parameter(code, maplesu_metadata_template, maplesu_metadata_size, count);
        uint64_t result = 0;
        const auto error = helper_execute(code, length, result);
        if (error) return error;
        if (result >> 63) return address_error;
        for (uint32_t i = 0; i < count; ++i)
            destination[done + i] = static_cast<uint8_t>(result >> (i * 8));
        done += count;
    }
    return 0;
}
int64_t symbols(uint64_t& read, uint64_t& write) {
    // No mutable global or TLS cache is introduced into the stripped helper.
    auto error = helper_lookup("copy_from_kernel_nofault", read);
    if (error && error != missing_symbol) return error;
    if (error || read < kernel_min) {
        read = 0;
        error = helper_lookup("probe_kernel_read", read);
        if (error && error != missing_symbol) return error;
    }
    if (error || read < kernel_min) {
        read = 0;
        error = helper_lookup("__probe_kernel_read", read);
        if (error && error != missing_symbol) return error;
    }
    if (error || read < kernel_min) return missing_symbol;
    error = helper_lookup("copy_to_user_nofault", write);
    if (error) return error;
    return write >= kernel_min ? 0 : missing_symbol;
}
}

extern "C" __attribute__((visibility("hidden")))
int64_t maplesu_helper_kernel_read(uint64_t source, void* destination, uint32_t size) {
    const auto target = reinterpret_cast<uint64_t>(destination);
    if (!destination || !size || source < kernel_min || source > UINT64_MAX - (size - 1) ||
        target > UINT64_MAX - (size - 1)) return parameter_error;
    uint64_t path = 0;
    const auto anchor_error = helper_append(path);
    if (anchor_error) return anchor_error;
    if (path < kernel_min + 8) return append_error;
    auto bytes = static_cast<uint8_t*>(destination);
    if (maplesu_kernel_read::metadata_read_allowed(path - 8, source, size))
        return metadata(source, bytes, size);
    uint64_t read = 0, write = 0;
    const auto symbol_error = symbols(read, write);
    if (symbol_error) return symbol_error;
    for (uint32_t done = 0; done < size;) {
        const auto count = size - done > batch_size ? batch_size : size - done;
        uint8_t code[512];
        const auto length = copy_template(code, maplesu_read_template, maplesu_read_template_end);
        parameter(code, maplesu_read_template, maplesu_read_source, source + done);
        parameter(code, maplesu_read_template, maplesu_read_destination, target + done);
        parameter(code, maplesu_read_template, maplesu_read_size, count);
        parameter(code, maplesu_read_template, maplesu_read_nofault, read);
        parameter(code, maplesu_read_template, maplesu_read_usercopy, write);
        uint64_t result = 0;
        const auto error = helper_execute(code, length, result);
        if (error) return error;
        if (result) return static_cast<int64_t>(result);
        done += count;
    }
    return 0;
}
