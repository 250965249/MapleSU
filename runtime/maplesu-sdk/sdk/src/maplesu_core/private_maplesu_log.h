// private MapleSU log implementation.
//
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

#include "module_err_def.h"

namespace maplesu::sdk {

class fork_base_info {
public:
    int fd_parent_to_child_read;
    int fd_parent_to_child_write;
    int fd_child_to_parent_read;
    int fd_child_to_parent_write;
    int self_pid;
    int child_pid;

    fork_base_info() {
        fd_parent_to_child_read = -1;
        fd_parent_to_child_write = -1;
        fd_child_to_parent_read = -1;
        fd_child_to_parent_write = -1;
        self_pid = -1;
        child_pid = -1;
        reset();
    }
    ~fork_base_info() { close_all(); }
    static void safe_close(int& fd) {
        if (fd > -1) {
            close(fd);
            fd = -1;
        }
    }
    void close_all() {
        safe_close(fd_parent_to_child_read);
        safe_close(fd_parent_to_child_write);
        safe_close(fd_child_to_parent_read);
        safe_close(fd_child_to_parent_write);
    }
    void reset() {
        close_all();
        fd_parent_to_child_read = -1;
        fd_parent_to_child_write = -1;
        fd_child_to_parent_read = -1;
        fd_child_to_parent_write = -1;
        self_pid = getpid();
        child_pid = 0;
    }
};
class fork_pipe_info : public fork_base_info {};
static_assert(sizeof(fork_pipe_info) == 24 && alignof(fork_pipe_info) == 4);
static_assert(sizeof(fork_base_info) == 24 && alignof(fork_base_info) == 4);
static_assert(offsetof(fork_base_info, child_pid) == 20);

bool fork_pipe_child_process(fork_pipe_info&);
bool write_errcode_from_child(const fork_pipe_info&, KModErr);
bool write_string_from_child(const fork_pipe_info&, const std::string&);
bool write_int_from_child(const fork_pipe_info&, int);
bool read_errcode_from_child(const fork_pipe_info&, KModErr&);
bool read_string_from_child(fork_pipe_info&, std::string&);
bool read_int_from_child(const fork_pipe_info&, int&);

}  // namespace maplesu::sdk

namespace file_utils {

static bool file_exists(const std::filesystem::path& path) {
    std::error_code error;
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
    return opened;
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
