// MapleSU fork helper implementation.
//
#include "module_err_def.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "private_maplesu_fork.h"

namespace maplesu::sdk {

// 其他错误立刻返回 false。返回“是否把 remaining 写到了 0”。
static bool write_full(int fd, const void* data, size_t size) {
    const uint8_t* cursor = static_cast<const uint8_t*>(data);
    size_t remaining = size;
    for (;;) {
        if (remaining == 0) {
            break;
        }
        const ssize_t written = write(fd, cursor, remaining);
        if (written > 0) {
            cursor += written;
            remaining -= static_cast<size_t>(written);
            continue;
        }
        if (written == -1) {
            const int error = errno;
            if (error == EINTR) {
                continue;
            }
            if (error == EAGAIN) {
                usleep(1000);
                continue;
            }
        }
        break;
    }
    return remaining == 0;
}

static bool read_full(int fd, void* data, size_t size) {
    uint8_t* cursor = static_cast<uint8_t*>(data);
    size_t remaining = size;
    for (;;) {
        if (remaining == 0) {
            break;
        }
        const ssize_t got = read(fd, cursor, remaining);
        if (got > 0) {
            cursor += got;
            remaining -= static_cast<size_t>(got);
            continue;
        }
        if (got == -1) {
            const int error = errno;
            if (error == EINTR) {
                continue;
            }
            if (error == EAGAIN) {
                usleep(1000);
                continue;
            }
        }
        break;
    }
    return remaining == 0;
}

//   int cmd[2] = {-1,-1}; int data[2] = {-1,-1};
//   if (pipe2(cmd, O_CLOEXEC) == -1) return false;
//   if (pipe2(data, O_CLOEXEC) == -1) { close(cmd[0]); close(cmd[1]); return false; }
//   fflush(nullptr);
//   pid_t pid = fork();
//   if (pid < 0) { close 4 fds; return false; }
//   if (pid == 0) {                       // 子
//       close(cmd[1]); close(data[0]);
//       field4 = getppid(); field5 = 0;
//       field0 = cmd[0];  field3 = data[1];
//       field1 = -1;      field2 = -1;
//       return true;
//   }
//   close(cmd[0]); close(data[1]);        // 父
//   field5 = pid; field4 = getpid();
//   field1 = cmd[1]; field2 = data[0];
//   field0 = -1;  field3 = -1;
//   return false;
bool fork_pipe_child_process(fork_pipe_info& pipe) {
    int command_pipe[2] = {-1, -1};
    int data_pipe[2] = {-1, -1};

    if (pipe2(command_pipe, O_CLOEXEC) == -1) {
        return false;
    }
    if (pipe2(data_pipe, O_CLOEXEC) == -1) {
        close(command_pipe[0]);
        close(command_pipe[1]);
        return false;
    }

    (void)fflush(nullptr);
    const pid_t child_pid = fork();
    if (child_pid < 0) {
        close(command_pipe[0]);
        close(command_pipe[1]);
        close(data_pipe[0]);
        close(data_pipe[1]);
        return false;
    }

    if (child_pid == 0) {
        close(command_pipe[1]);
        close(data_pipe[0]);
        pipe.fd_parent_to_child_read = command_pipe[0];
        pipe.fd_child_to_parent_write = data_pipe[1];
        pipe.fd_parent_to_child_write = -1;
        pipe.fd_child_to_parent_read = -1;
        pipe.self_pid = getppid();
        pipe.child_pid = 0;
        return true;
    }

    close(command_pipe[0]);
    close(data_pipe[1]);
    pipe.fd_parent_to_child_write = command_pipe[1];
    pipe.fd_child_to_parent_read = data_pipe[0];
    pipe.fd_parent_to_child_read = -1;
    pipe.fd_child_to_parent_write = -1;
    pipe.self_pid = getpid();
    pipe.child_pid = child_pid;
    return false;
}

// --------------------------- 标量 -------------------------------------------------
bool write_bool_from_child(const fork_pipe_info& pipe, bool value) {
    return write_full(pipe.fd_child_to_parent_write, &value, sizeof(value));
}

bool read_bool_from_child(const fork_pipe_info& pipe, bool& out_value) {
    return read_full(pipe.fd_child_to_parent_read, &out_value, sizeof(out_value));
}

bool write_int_from_child(const fork_pipe_info& pipe, int value) {
    return write_full(pipe.fd_child_to_parent_write, &value, sizeof(value));
}

bool read_int_from_child(const fork_pipe_info& pipe, int& out_value) {
    return read_full(pipe.fd_child_to_parent_read, &out_value, sizeof(out_value));
}

bool write_uint64_from_child(const fork_pipe_info& pipe, uint64_t value) {
    return write_full(pipe.fd_child_to_parent_write, &value, sizeof(value));
}

bool read_uint64_from_child(const fork_pipe_info& pipe, uint64_t& out_value) {
    return read_full(pipe.fd_child_to_parent_read, &out_value, sizeof(out_value));
}

bool write_errcode_from_child(const fork_pipe_info& pipe, KModErr err) {
    return write_full(pipe.fd_child_to_parent_write, &err, sizeof(err));
}

bool read_errcode_from_child(const fork_pipe_info& pipe, KModErr& out_err) {
    return read_full(pipe.fd_child_to_parent_read, &out_err, sizeof(out_err));
}

// --------------------------- 字节流 -----------------------------------------------
//   先写 8 字节长度，再写原始字节；长度为 0 时只写长度。
bool write_transfer_data_from_child(const fork_pipe_info& pipe, const std::vector<uint8_t>& data) {
    const uint64_t size = static_cast<uint64_t>(data.size());
    if (!write_full(pipe.fd_child_to_parent_write, &size, sizeof(size))) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    return write_full(pipe.fd_child_to_parent_write, data.data(), data.size());
}

bool read_transfer_data_from_child(fork_pipe_info& pipe, std::vector<uint8_t>& out_data) {
    out_data.clear();
    uint64_t size = 0;
    if (!read_full(pipe.fd_child_to_parent_read, &size, sizeof(size))) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    out_data.resize(static_cast<size_t>(size));
    return read_full(pipe.fd_child_to_parent_read, out_data.data(), out_data.size());
}

// --------------------------- string -----------------------------------------------
//   8 字节长度 + 原始字节（UTF-8/ASCII 原样，无结尾 NUL）。
bool write_string_from_child(const fork_pipe_info& pipe, const std::string& text) {
    const uint8_t* begin = reinterpret_cast<const uint8_t*>(text.data());
    const std::vector<uint8_t> buffer(begin, begin + text.size());
    return write_transfer_data_from_child(pipe, buffer);
}

bool read_string_from_child(fork_pipe_info& pipe, std::string& out_text) {
    std::vector<uint8_t> buffer;
    const bool ok = read_transfer_data_from_child(pipe, buffer);
    if (ok) {
        out_text.assign(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    }
    return ok;
}

// --------------------------- set<int> ---------------------------------------------
//   n = tree.size(); vector<uint8_t> tmp(n * 4);
//   逐个 int 以 4 字节小端序拷进 tmp；再按 transfer_data 格式发送。
bool write_set_int_from_child(const fork_pipe_info& pipe, const std::set<int>& values) {
    std::vector<uint8_t> buffer(values.size() * sizeof(int32_t));
    uint8_t* cursor = buffer.data();
    for (const int& value : values) {
        memcpy(cursor, &value, sizeof(int32_t));
        cursor += sizeof(int32_t);
    }
    return write_transfer_data_from_child(pipe, buffer);
}

bool read_set_int_from_child(fork_pipe_info& pipe, std::set<int>& out_values) {
    std::vector<uint8_t> buffer;
    const bool ok = read_transfer_data_from_child(pipe, buffer);
    if (ok) {
        if (!buffer.empty()) {
            const size_t count = buffer.size() / sizeof(int32_t);
            const uint8_t* cursor = buffer.data();
            for (size_t index = 0; index < count; ++index) {
                int32_t value = 0;
                memcpy(&value, cursor, sizeof(int32_t));
                cursor += sizeof(int32_t);
                out_values.insert(value);
            }
        }
    }
    return ok;
}

// --------------------------- set<string> ------------------------------------------
// 【推断格式】按 string 逐个长度前缀 + 字节，序列化进 vector 后走 transfer_data。
// 依据：set<int> 用定长元素打包，string 无法定长，同族实现只能逐条带长度。
bool write_set_string_from_child(const fork_pipe_info& pipe, const std::set<std::string>& values) {
    size_t total = 0;
    for (const std::string& value : values) {
        total += sizeof(uint64_t) + value.size();
    }
    std::vector<uint8_t> buffer(total);
    uint8_t* cursor = buffer.data();
    for (const std::string& value : values) {
        const uint64_t size = static_cast<uint64_t>(value.size());
        memcpy(cursor, &size, sizeof(size));
        cursor += sizeof(size);
        memcpy(cursor, value.data(), static_cast<size_t>(size));
        cursor += static_cast<size_t>(size);
    }
    return write_transfer_data_from_child(pipe, buffer);
}

bool read_set_string_from_child(fork_pipe_info& pipe, std::set<std::string>& out_values) {
    std::vector<uint8_t> buffer;
    if (!read_transfer_data_from_child(pipe, buffer)) {
        return false;
    }
    const uint8_t* cursor = buffer.data();
    const uint8_t* const end = cursor + buffer.size();
    while (cursor < end) {
        uint64_t size = 0;
        memcpy(&size, cursor, sizeof(size));
        cursor += sizeof(size);
        std::string value(reinterpret_cast<const char*>(cursor), static_cast<size_t>(size));
        out_values.insert(value);
        cursor += size;
    }
    return true;
}

// --------------------------- map<int,string> --------------------------------------
// 【推断格式】条数(u64) + 每条 (key i32 + value 长度 u64 + value 字节)。
bool write_map_i_s_from_child(const fork_pipe_info& pipe,
                              const std::map<int, std::string>& values) {
    size_t total = 0;
    for (const auto& entry : values) {
        total += sizeof(int32_t) + sizeof(uint64_t) + entry.second.size();
    }
    std::vector<uint8_t> buffer(total);
    uint8_t* cursor = buffer.data();
    for (const auto& entry : values) {
        memcpy(cursor, &entry.first, sizeof(int32_t));
        cursor += sizeof(int32_t);
        const uint64_t size = static_cast<uint64_t>(entry.second.size());
        memcpy(cursor, &size, sizeof(size));
        cursor += sizeof(size);
        memcpy(cursor, entry.second.data(), static_cast<size_t>(size));
        cursor += static_cast<size_t>(size);
    }
    return write_transfer_data_from_child(pipe, buffer);
}

bool read_map_i_s_from_child(fork_pipe_info& pipe, std::map<int, std::string>& out_values) {
    std::vector<uint8_t> buffer;
    if (!read_transfer_data_from_child(pipe, buffer)) {
        return false;
    }
    const uint8_t* cursor = buffer.data();
    const uint8_t* const end = cursor + buffer.size();
    while (cursor < end) {
        int32_t key = 0;
        memcpy(&key, cursor, sizeof(key));
        cursor += sizeof(key);
        uint64_t size = 0;
        memcpy(&size, cursor, sizeof(size));
        cursor += sizeof(size);
        std::string value(reinterpret_cast<const char*>(cursor), static_cast<size_t>(size));
        cursor += size;
        out_values[key] = value;
    }
    return true;
}

// --------------------------- map<string,int> --------------------------------------
// 【推断格式】条数(u64) + 每条 (key 长度 u64 + key 字节 + value i32)。
bool write_map_s_i_from_child(const fork_pipe_info& pipe,
                              const std::map<std::string, int>& values) {
    size_t total = 0;
    for (const auto& entry : values) {
        total += sizeof(uint64_t) + entry.first.size() + sizeof(int32_t);
    }
    std::vector<uint8_t> buffer(total);
    uint8_t* cursor = buffer.data();
    for (const auto& entry : values) {
        const uint64_t size = static_cast<uint64_t>(entry.first.size());
        memcpy(cursor, &size, sizeof(size));
        cursor += sizeof(size);
        memcpy(cursor, entry.first.data(), static_cast<size_t>(size));
        cursor += static_cast<size_t>(size);
        memcpy(cursor, &entry.second, sizeof(int32_t));
        cursor += sizeof(int32_t);
    }
    return write_transfer_data_from_child(pipe, buffer);
}

bool read_map_s_i_from_child(fork_pipe_info& pipe, std::map<std::string, int>& out_values) {
    std::vector<uint8_t> buffer;
    if (!read_transfer_data_from_child(pipe, buffer)) {
        return false;
    }
    const uint8_t* cursor = buffer.data();
    const uint8_t* const end = cursor + buffer.size();
    while (cursor < end) {
        uint64_t size = 0;
        memcpy(&size, cursor, sizeof(size));
        cursor += sizeof(size);
        std::string key(reinterpret_cast<const char*>(cursor), static_cast<size_t>(size));
        cursor += size;
        int32_t value = 0;
        memcpy(&value, cursor, sizeof(value));
        cursor += sizeof(value);
        out_values[key] = value;
    }
    return true;
}

}  // namespace maplesu::sdk
