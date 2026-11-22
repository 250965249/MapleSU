#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "module_err_def.h"

namespace maplesu::sdk {

struct fork_base_info {
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
        if (fd >= 0) {
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

struct fork_pipe_info : fork_base_info {};
static_assert(sizeof(fork_base_info) == 24 && alignof(fork_base_info) == 4);
static_assert(sizeof(fork_pipe_info) == 24 && alignof(fork_pipe_info) == 4);
static_assert(offsetof(fork_base_info, fd_parent_to_child_read) == 0);
static_assert(offsetof(fork_base_info, fd_parent_to_child_write) == 4);
static_assert(offsetof(fork_base_info, fd_child_to_parent_read) == 8);
static_assert(offsetof(fork_base_info, fd_child_to_parent_write) == 12);
static_assert(offsetof(fork_base_info, self_pid) == 16);
static_assert(offsetof(fork_base_info, child_pid) == 20);

bool fork_pipe_child_process(fork_pipe_info&);
bool write_errcode_from_child(const fork_pipe_info&, KModErr);
bool read_errcode_from_child(const fork_pipe_info&, KModErr&);
bool write_bool_from_child(const fork_pipe_info&, bool);
bool read_bool_from_child(const fork_pipe_info&, bool&);
bool write_int_from_child(const fork_pipe_info&, int);
bool read_int_from_child(const fork_pipe_info&, int&);
bool write_uint64_from_child(const fork_pipe_info&, uint64_t);
bool read_uint64_from_child(const fork_pipe_info&, uint64_t&);
bool write_string_from_child(const fork_pipe_info&, const std::string&);
bool read_string_from_child(fork_pipe_info&, std::string&);
bool write_transfer_data_from_child(const fork_pipe_info&, const std::vector<uint8_t>&);
bool read_transfer_data_from_child(fork_pipe_info&, std::vector<uint8_t>&);
bool write_set_int_from_child(const fork_pipe_info&, const std::set<int>&);
bool read_set_int_from_child(fork_pipe_info&, std::set<int>&);
bool write_set_string_from_child(const fork_pipe_info&, const std::set<std::string>&);
bool read_set_string_from_child(fork_pipe_info&, std::set<std::string>&);
bool write_map_i_s_from_child(const fork_pipe_info&, const std::map<int, std::string>&);
bool read_map_i_s_from_child(fork_pipe_info&, std::map<int, std::string>&);
bool write_map_s_i_from_child(const fork_pipe_info&, const std::map<std::string, int>&);
bool read_map_s_i_from_child(fork_pipe_info&, std::map<std::string, int>&);

}  // namespace maplesu::sdk
