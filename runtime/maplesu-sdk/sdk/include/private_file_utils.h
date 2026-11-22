// private file utils implementation.
//
#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <vector>

namespace file_utils {

//   NS_15SelinuxFileFlagE == file_utils::SelinuxFileFlag
enum class SelinuxFileFlag : int {
    Default = 0,  // 仅 chmod 0777 + 打标签（默认行为）
};

// 把文件权限设为 0777 并打上 u:object_r:system_file:s0 的 SELinux 标签。
//   chmod(path, 511);                      // 511 == 0777
//   if (chmod 成功) setxattr(path, "security.selinux",
//                            "u:object_r:system_file:s0", 26, 0);
//   return (chmod 成功 && setxattr 成功);
static bool set_file_selinux_access_mode(const char* file_path, SelinuxFileFlag /*flag*/) {
    if (chmod(file_path, 0777) != 0) {
        return false;
    }
    if (setxattr(file_path, "security.selinux", "u:object_r:system_file:s0", 26, 0) != 0) {
        return false;
    }
    return true;
}

// 打内核侧 SELinux 标签（u:object_r:kernel:s0）。
//   setxattr(path, "security.selinux", "u:object_r:kernel:s0", 21, 0)
// 21 == sizeof("u:object_r:kernel:s0")（含结尾 NUL）。
static bool set_file_kernel_selinux_access_mode(const char* file_path) {
    if (chmod(file_path, 0777) != 0) {
        return false;
    }
    const char kKernelContext[] = "u:object_r:kernel:s0";
    if (setxattr(file_path, "security.selinux", kKernelContext, sizeof(kKernelContext), 0) != 0) {
        return false;
    }
    return true;
}

// 路径是否存在（不抛异常版本）。
//   std::error_code ec; ec 先置 0 并绑定 system_category()；
//   return std::filesystem::exists(path, ec);
static bool file_exists(const std::filesystem::path& path) {
    std::error_code err;
    return std::filesystem::exists(path, err);
}

// 建一个空文件（截断模式）。
//   std::ofstream ofs(path, 52);      // 52 == out(16)|trunc(32)|binary(4)
//   bool ok = (ofs.rdbuf() != nullptr);
//   if (ok) ofs.close();
//   return ok;
static bool create_empty_file(const char* file_path) {
    std::ofstream ofs(file_path, std::ios::out | std::ios::trunc | std::ios::binary);
    const bool opened = ofs.rdbuf() != nullptr;
    if (opened) {
        ofs.close();
    }
    return opened;
}

// 读整个文本文件到 out。
//   std::vector<uint8_t> buf;
//   std::ifstream f(path, 4);        // 4 == ios::binary
//   if (f.rdstate() & (badbit|failbit)) return false;
//   f.seekg(0, end); auto pos = f.tellg(); if (pos < 0) return false;
//   f.seekg(0, beg); buf.resize((size_t)pos); f.read(buf.data(), pos);
//   out.assign(buf.begin(), buf.end()); return true;
static bool read_text_file(const char* file_path, std::string& out_text) {
    std::vector<uint8_t> buffer;
    std::ifstream ifs(file_path, std::ios::binary);
    if ((ifs.rdstate() & (std::ios::badbit | std::ios::failbit)) != 0) {
        return false;
    }
    ifs.seekg(0, std::ios::end);
    const std::streamoff size = ifs.tellg();
    if (size < 0) {
        return false;
    }
    ifs.seekg(0, std::ios::beg);
    buffer.resize(static_cast<size_t>(size));
    if (!buffer.empty()) {
        ifs.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    }
    out_text.assign(buffer.begin(), buffer.end());
    return true;
}

// 删除文件/目录（不抛异常版本）。
static bool delete_path(const std::filesystem::path& path) {
    std::error_code err;
    const auto removed = std::filesystem::remove_all(path, err);
    return removed != 0 && !err;
}

}  // namespace file_utils
