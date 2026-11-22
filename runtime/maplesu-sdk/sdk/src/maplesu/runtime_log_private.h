// MapleSU runtime log implementation details; included by one translation unit.
#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace maplesu::runtime_log {
namespace {
namespace file_utils {

static bool file_exists(const std::filesystem::path& path, std::error_code& error) {
    return std::filesystem::exists(path, error);
}

static bool read_text_file(const char* path, std::string& text) {
    std::vector<uint8_t> buffer;
    {
        std::ifstream input(path, std::ios::binary);
        if (input.fail()) {
            return false;
        }
        input.seekg(0, std::ios::end);
        const std::streamoff size = input.tellg();
        if (size < 0) {
            return false;
        }
        input.seekg(0, std::ios::beg);
        buffer.resize(static_cast<size_t>(size));
        if (input.read(reinterpret_cast<char*>(buffer.data()), size).fail()) {
            return false;
        }
    }
    text.assign(buffer.begin(), buffer.end());
    return true;
}

static bool create_empty_file(const char* path) {
    std::ofstream output(path, std::ios::out | std::ios::trunc | std::ios::binary);
    const bool opened = output.is_open();
    if (opened) {
        output.close();
    }
    return opened && !output.fail();
}

}  // namespace file_utils

class RunFlagFile {
public:
    explicit RunFlagFile(const std::string& path) : path_(path) {}
    int read() {
        std::ifstream input(path_, std::ios::in);
        if (!input.is_open()) {
            return 0;
        }
        char value = 0;
        input >> value;
        switch (value) {
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            default: return 0;
        }
    }

private:
    std::string path_;
};
static_assert(sizeof(RunFlagFile) == 24 && alignof(RunFlagFile) == 8);
}  // namespace
}  // namespace maplesu::runtime_log
