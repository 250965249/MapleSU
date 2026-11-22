// Include the actual parser/helper text extracted by run.py; no parser stubs.
#include "actual_parser.cpp"
#include "actual_bind_key.cpp"

#include <cstdlib>
#include <iostream>
#include <new>
#include <stdexcept>
#include <vector>

static bool fail_allocation = false;
void* operator new(std::size_t size) {
    if (fail_allocation) throw std::bad_alloc();
    if (void* memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }

namespace {
const std::string digits62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
struct TestCase {
    std::string name;
    std::string key;
    int expected;
    bool null_input = false;
    bool allocation_failure = false;
    bool project_generator = false;
};

std::string magnitude62(uint64_t magnitude) {
    std::string result;
    do {
        result.insert(result.begin(), digits62[magnitude % 62]);
        magnitude /= 62;
    } while (magnitude);
    return result;
}

// Synthetic wire fixtures use the existing format; no fixture grants capabilities.
std::string wire_key(const std::string& magnitude, char sign = '1', size_t length = 48) {
    std::string key(length, 'a');
    key[0] = 'c';
    key[16] = 'g';
    const size_t count = magnitude.size() + 2;
    if (count > 61 || count > length + 2) throw std::logic_error("fixture length");
    std::string tail(1, key[16]);
    const std::string plain = magnitude + sign;
    for (size_t i = 0; i < plain.size(); ++i) {
        tail.push_back(digits62[(digits62.find(plain[i]) + digits62.find(key[16]) + i) % 62]);
    }
    key.replace(length + 2 - count, count - 2, tail, 0, count - 2);
    key[15] = tail[count - 2];
    key[2] = tail[count - 1];
    key[1] = digits62[(digits62.find(key[0]) + count) % 62];
    return key;
}

std::vector<TestCase> cases() {
    std::vector<TestCase> result = {
        {"null", "", 0, true}, {"empty", "", 0},
        {"short_1", "a", 0}, {"short_15", std::string(15, 'a'), 0},
    };
    for (long delta : {-134217728L, -4096L, -4L, 4L, 4096L, 134217728L}) {
        std::string key = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL";
        if (msu_sdk_bind_key(key.data(), delta) != 0) throw std::logic_error("project binder");
        result.push_back({"project_" + std::to_string(delta), key, static_cast<int>(delta), false, false, true});
    }
    result.push_back({"int_max", wire_key(magnitude62(2147483647)), 2147483647});
    result.push_back({"int_min", wire_key(magnitude62(2147483648), '0'), (-2147483647 - 1)});
    result.push_back({"negative_int_max", wire_key(magnitude62(2147483647), '0'), -2147483647});
    result.push_back({"positive_zero", wire_key("0"), 0});
    result.push_back({"negative_zero", wire_key("0", '0'), 0});
    result.push_back({"leading_zero", wire_key("000" + magnitude62(4321)), 4321});
    result.push_back({"nonzero_sign", wire_key(magnitude62(4321), 'Z'), 4321});
    for (size_t length : {size_t(253), size_t(254), size_t(255), size_t(256), size_t(4096), size_t(65536)}) {
        result.push_back({"length_" + std::to_string(length), wire_key("4", '1', length), 4});
    }
    for (size_t count : {size_t(0), size_t(1), size_t(2), size_t(61)}) {
        std::string key(16, 'a');
        key[0] = '0';
        key[1] = digits62[count];
        result.push_back({"prefix_" + std::to_string(count), key, 0});
    }
    for (size_t at : {size_t(0), size_t(1), size_t(15), size_t(2), size_t(45), size_t(46)}) {
        auto key = wire_key(magnitude62(4321));
        key[at] = '!';
        result.push_back({"invalid_at_" + std::to_string(at), key, 0});
    }
    auto ignored = wire_key(magnitude62(4321));
    ignored[10] = '!';
    result.push_back({"ignored_character", ignored, 4321});
    result.push_back({"positive_int_overflow", wire_key(magnitude62(2147483648)), 0});
    result.push_back({"negative_int_overflow", wire_key(magnitude62(2147483649), '0'), 0});
    result.push_back({"negative_i64_min", wire_key(magnitude62(uint64_t(1) << 63), '0'), 0});
    result.push_back({"u64_max", wire_key(magnitude62(UINT64_MAX)), 0});
    result.push_back({"u64_max_negative", wire_key(magnitude62(UINT64_MAX), '0'), 0});
    result.push_back({"u64_overflow", wire_key(magnitude62(UINT64_MAX) + "0"), 0});
    result.push_back({"many_digits_overflow", wire_key(std::string(20, 'Z')), 0});
    result.push_back({"allocation_failure", wire_key("4"), 0, false, true});
    return result;
}
}  // namespace

int main(int argc, char** argv) {
    const auto tests = cases();
    if (argc == 2 && std::string(argv[1]) == "--list") {
        for (const auto& test : tests) std::cout << test.name << '\n';
        return 0;
    }
    if (argc != 2) return 2;
    for (const auto& test : tests) {
        if (test.name != argv[1]) continue;
        int actual = 0x12345678;
        bool escaped = false;
        try {
            fail_allocation = test.allocation_failure;
            kernel_module::parser_root_key_info(test.null_input ? nullptr : test.key.c_str(), actual);
        } catch (const std::exception&) {
            escaped = true;
        }
        fail_allocation = false;
        const bool passed = !escaped && actual == test.expected;
        std::cout << "{\"case\":\"" << test.name << "\",\"bytes\":" << test.key.size()
                  << ",\"expected\":" << test.expected << ",\"actual\":" << actual
                  << ",\"escaped\":" << (escaped ? "true" : "false")
                  << ",\"projectGenerator\":" << (test.project_generator ? "true" : "false")
                  << ",\"passed\":" << (passed ? "true" : "false") << "}\n";
        return passed ? 0 : 1;
    }
    return 2;
}
