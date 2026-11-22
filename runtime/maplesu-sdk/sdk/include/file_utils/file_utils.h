// file utils implementation.
//
#pragma once

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <filesystem>
#include <system_error>

// Private permission helper of the kit runtime: replaces the file mode with a
// hardened default and refuses to touch anything the runtime does not own.
// `mode == 0` selects the default (0600 for files, 0700 for directories).
extern "C" int maplesu_private_chmod(const char* path, unsigned int mode);

namespace file_utils {

enum class SelinuxFileFlag : int {
    UNSPECIFIED = 0,  // 占位；无证据表明存在其它具名取值
};

// 文件/目录存在性判定；error_code 版本，任何错误都视为"不存在"。
static bool file_exists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

// 收紧文件的访问权限并打上 system_file 标签。
//
// 权限不再直接写成 0777：交给运行时的私有校验器，由它确认文件属于运行时、
// 类型允许（普通文件或目录）之后把权限收紧到受限默认值；只有收紧成功才继续
// 打 SELinux 标签。两者任一失败都按失败返回。
static bool set_file_selinux_access_mode(const char* path,
                                         SelinuxFileFlag flag = SelinuxFileFlag::UNSPECIFIED) {
    (void)flag;
    if (maplesu_private_chmod(path, 0) != 0) {
        return false;
    }
    return ::setxattr(path, "security.selinux", "u:object_r:system_file:s0", 26, 0) == 0;
}

}  // namespace file_utils
