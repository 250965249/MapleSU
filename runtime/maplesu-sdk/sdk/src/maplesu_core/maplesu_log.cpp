// MapleSU log implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "private_maplesu_log.h"
#include "private_maple_runtime.h"

namespace maplesu::sdk {

static_assert(static_cast<ssize_t>(KModErr::ERR_MODULE_ROOT_KEY) == -19997);
static_assert(static_cast<ssize_t>(KModErr::ERR_MODULE_FILE_NOT_EXIST) == -19936);
static_assert(static_cast<ssize_t>(KModErr::ERR_MODULE_CREATE_EMPTY_FILE) == -19935);
static_assert(static_cast<ssize_t>(KModErr::ERR_MODULE_READ_FILE) == -19932);
static_assert(static_cast<ssize_t>(KModErr::ERR_SET_FILE_SELINUX) == -19915);

//   char buf[1024] = {0};
//   std::string root_key(__get_current_module_root_key_...());
//   std::string head = root_key.substr(0, 16);          // FOLDER_HEAD_ROOT_KEY_LEN
//   snprintf(buf, 1024, "/data/%s/", head.c_str());
//   std::filesystem::path dir = std::string(buf);
//   return std::string(dir / "init");
// 注意：与 module_base_change_status.o 里的 get_system_file_dir_path 不同——
// 那一份用 head + head[0]（17 字符），这一份只用 head（16 字符）。两处实测。
static std::string get_autorun_bootstrap_path() {
    char path_buf[1024] = {0};
    std::string root_key(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW());
    std::string head = root_key.substr(0, FOLDER_HEAD_ROOT_KEY_LEN);
    snprintf(path_buf, sizeof(path_buf), "/data/%s/", head.c_str());
    std::filesystem::path dir = std::string(path_buf);
    std::filesystem::path bootstrap = dir / "init";
    return std::string(bootstrap);
}

static std::string get_maplesu_log_path() {
    return get_autorun_bootstrap_path() + ".log";
}

static std::string get_log_enable_flag_path() {
    return get_maplesu_log_path() + ".enable";
}

// 结构（逐块实测）：
//   root_key == nullptr                                   -> KModErr::ERR_MODULE_ROOT_KEY (-19997)
//   strnlen(root_key, 1024) 不在 [16, 1023]               -> KModErr::ERR_MODULE_ROOT_KEY
//   __set_current_module_root_key_...(root_key)
//   log_text = ""; fork_base_info info; int64 code = 0;
//   if (fork_pipe_child_process(info)) {                   // ---- 子进程 ----
//       if (set_current_root(true) == 0) {
//           if (!file_exists(get_maplesu_log_path()))      code = -19936 (FILE_NOT_EXIST)
//           else if (!read_text_file(log_path, log_text)) code = -19932 (READ_FILE)
//           else if (RunFlagFile(get_autorun_bootstrap_path() + ".safe_flag").read() == 3) {
//               std::string crash;
//               read_text_file((get_maplesu_log_path() + ".crash").c_str(), crash);
//               if (!crash.empty()) {
//                   log_text += "=========================\n";
//                   log_text += "\tLast Crash Log\n";
//                   log_text += "=========================\n";
//                   log_text += crash;
//               }
//           }
//       } else code = set_current_root 返回值;
//       write_errcode_from_child(info, code);
//       write_string_from_child(info, log_text);
//       info.close_all();
//       _exit(0);
//   }
//   // ---- 父进程 ----
//   if (!read_errcode_from_child(info, code)) code = -19914 (READ_CHILD_ERRCODE)
//   if (!read_string_from_child(info, log_text)) code = -19913 (READ_CHILD_STRING)
//   int status = 0; waitpid(info.child_pid, &status, 0);
//   return code;
KModErr read_maplesu_log_cb(const char* root_key, void (*on_log_text)(const char*)) {
    if (root_key == nullptr) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const size_t root_key_len = strnlen(root_key, 1024);
    if (root_key_len < FOLDER_HEAD_ROOT_KEY_LEN || root_key_len >= 1024) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }

    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    std::string log_text;
    KModErr code = KModErr::OK;
    {
        fork_pipe_info pipe_info;

        if (fork_pipe_child_process(pipe_info)) {
            // ---------------- 子进程：真正读文件（需要 root 视图） ----------------
            const KModErr set_root_err = default_modules::module_root::set_current_root(true);
            if (set_root_err == KModErr::OK) {
                const std::string log_path = get_maplesu_log_path();
                if (!file_utils::file_exists(std::filesystem::path(log_path))) {
                    code = KModErr::ERR_MODULE_FILE_NOT_EXIST;
                } else if (!file_utils::read_text_file(log_path.c_str(), log_text)) {
                    code = KModErr::ERR_MODULE_READ_FILE;
                } else {
                    RunFlagFile safe_flag(get_autorun_bootstrap_path() + ".safe_flag");
                    if (safe_flag.read() == 3) {
                        // 安全模式：把上次崩溃日志附在正常日志后面一起回传。
                        const std::string crash_path = get_maplesu_log_path() + ".crash";
                        std::string crash_text;
                        (void)file_utils::read_text_file(crash_path.c_str(), crash_text);
                        if (!crash_text.empty()) {
                            log_text.append("=========================\n");
                            log_text.append("\tLast Crash Log\n");
                            log_text.append("=========================\n");
                            log_text.append(crash_text);
                        }
                    }
                }
            } else {
                code = set_root_err;
            }

            (void)write_errcode_from_child(pipe_info, code);
            (void)write_string_from_child(pipe_info, log_text);
            pipe_info.close_all();
            _exit(0);
        }

        // ---------------- 父进程：收错误码 + 收字符串 + 等子进程 ----------------
        if (!read_errcode_from_child(pipe_info, code)) {
            code = KModErr::ERR_READ_CHILD_ERRCODE;
        }
        if (!read_string_from_child(pipe_info, log_text)) {
            code = KModErr::ERR_READ_CHILD_STRING;
        }

        int child_status = 0;
        (void)waitpid(pipe_info.child_pid, &child_status, 0);
    }

    if (is_ok(code)) {
        on_log_text(log_text.c_str());
    }
    return code;
}

//   root_key 校验同上（失败 -> KModErr::ERR_MODULE_ROOT_KEY）
//   子进程：
//     if (set_current_root(true) == 0) {
//         flag_path = get_log_enable_flag_path();
//         if (enable) {
//             create_empty_file(flag_path) 失败 -> 走失败出口
//             chmod(flag_path, 0777) != 0   -> 走失败出口
//             setxattr(flag_path, "security.selinux",
//                      "u:object_r:kernel:s0", 21, 0) != 0 -> 走失败出口
//         } else {
//             std::filesystem::remove_all(std::filesystem::path(flag_path), &ec);
//             file_exists(std::filesystem::path(flag_path));
//         }
//     }
//     write_errcode_from_child(code); _exit(0)
//   父进程：read_errcode_from_child -> waitpid -> return code
KModErr set_maplesu_log_enabled(const char* root_key, bool enable) {
    if (root_key == nullptr) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const size_t root_key_len = strnlen(root_key, 1024);
    if (root_key_len < FOLDER_HEAD_ROOT_KEY_LEN || root_key_len >= 1024) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }

    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);
    fork_pipe_info pipe_info;
    KModErr code = KModErr::OK;

    if (fork_pipe_child_process(pipe_info)) {
        const KModErr set_root_err = default_modules::module_root::set_current_root(true);
        if (set_root_err == KModErr::OK) {
            const std::string flag_path = get_log_enable_flag_path();
            if (enable) {
                if (!file_utils::create_empty_file(flag_path.c_str())) {
                    code = KModErr::ERR_MODULE_CREATE_EMPTY_FILE;
                } else if (chmod(flag_path.c_str(), 0777) != 0) {
                    code = KModErr::ERR_SET_FILE_SELINUX;
                } else if (setxattr(flag_path.c_str(), "security.selinux",
                                    "u:object_r:kernel:s0", 21, 0) != 0) {
                    code = KModErr::ERR_SET_FILE_SELINUX;
                }
            } else {
                const std::filesystem::path path(flag_path);
                std::error_code err;
                (void)std::filesystem::remove_all(path, err);
                (void)file_utils::file_exists(path);
            }
            if (is_ok(code)) {
                sync();
            }
        } else {
            code = set_root_err;
        }

        (void)write_errcode_from_child(pipe_info, code);
        pipe_info.close_all();
        _exit(0);
    }

    if (!read_errcode_from_child(pipe_info, code)) {
        code = KModErr::ERR_READ_CHILD_ERRCODE;
    }

    int child_status = 0;
    (void)waitpid(pipe_info.child_pid, &child_status, 0);
    return code;
}

//   子进程：set_current_root(true) 成功后
//     flag_path = get_log_enable_flag_path();
//     enabled = file_exists(path(flag_path)) ? 1 : 0;
//     write_errcode_from_child(code);
//     write_int_from_child(enabled);
//   父进程：read_errcode_from_child -> 失败 => -19914
//           read_int_from_child     -> 失败 => -19912（READ_CHILD_INT）
//           waitpid; return enabled == 1（不检查 code，原件就是如此）
bool is_maplesu_log_enabled(const char* root_key) {
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);
    fork_pipe_info pipe_info;
    KModErr code = KModErr::OK;
    if (fork_pipe_child_process(pipe_info)) {
        int enabled = 1;
        const KModErr set_root_err = default_modules::module_root::set_current_root(true);
        if (set_root_err == KModErr::OK) {
            const std::string flag_path = get_log_enable_flag_path();
            enabled = file_utils::file_exists(std::filesystem::path(flag_path)) ? 1 : 0;
        } else {
            code = set_root_err;
        }

        (void)write_errcode_from_child(pipe_info, code);
        (void)write_int_from_child(pipe_info, enabled);
        pipe_info.close_all();
        _exit(0);
    }

    if (!read_errcode_from_child(pipe_info, code)) {
        code = KModErr::ERR_READ_CHILD_ERRCODE;
    }
    int enabled = 0;
    if (!read_int_from_child(pipe_info, enabled)) {
        code = KModErr::ERR_READ_CHILD_INT;
    }

    int child_status = 0;
    (void)waitpid(pipe_info.child_pid, &child_status, 0);
    return enabled == 1;
}

//   子进程：set_current_root(true) 成功后
//     log_path = get_maplesu_log_path();
//     if (file_exists(path(log_path))) create_empty_file(log_path.c_str())
//         ? 0 : -19935 (CREATE_EMPTY_FILE)
//   父进程：read_errcode_from_child -> waitpid -> return code
KModErr clear_maplesu_log(const char* root_key) {
    if (root_key == nullptr) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const size_t root_key_len = strnlen(root_key, 1024);
    if (root_key_len < FOLDER_HEAD_ROOT_KEY_LEN || root_key_len >= 1024) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }

    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);
    fork_pipe_info pipe_info;
    KModErr code = KModErr::OK;

    if (fork_pipe_child_process(pipe_info)) {
        const KModErr set_root_err = default_modules::module_root::set_current_root(true);
        if (set_root_err == KModErr::OK) {
            const std::string log_path = get_maplesu_log_path();
            if (file_utils::file_exists(std::filesystem::path(log_path))) {
                if (!file_utils::create_empty_file(log_path.c_str())) {
                    code = KModErr::ERR_MODULE_CREATE_EMPTY_FILE;
                }
            } else {
                code = KModErr::ERR_MODULE_FILE_NOT_EXIST;
            }
        } else {
            code = set_root_err;
        }

        (void)write_errcode_from_child(pipe_info, code);
        pipe_info.close_all();
        _exit(0);
    }

    if (!read_errcode_from_child(pipe_info, code)) {
        code = KModErr::ERR_READ_CHILD_ERRCODE;
    }

    int child_status = 0;
    (void)waitpid(pipe_info.child_pid, &child_status, 0);
    return code;
}

}  // namespace maplesu::sdk
