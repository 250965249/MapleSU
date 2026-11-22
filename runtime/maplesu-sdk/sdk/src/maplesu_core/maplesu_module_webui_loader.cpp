// MapleSU module webui loader implementation.
//
#include "webui_loader_private.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "third_party/____DO_NOT_EDIT____/private_desc_parser.h"

#include "maplesu_sdk/maplesu_log.h"

namespace maplesu::sdk {

// 本模块根密钥前 16 个字符：/data/<16 字符>/ 目录名的来源。
static std::string get_kernel_file_dir_name() {
    const std::string root_key = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    return root_key.substr(0, 16);
}

// 目录名 = 前 16 字符 + 首字符（首字符重复一次）。
static std::string get_system_file_dir_name() {
    const std::string folder_head = get_kernel_file_dir_name();
    return folder_head + folder_head[0];
}

// /data/<目录名>/ —— 所有模块私有路径的根。
static std::string get_system_file_dir_path() {
    char path_buffer[1024] = {};
    std::snprintf(path_buffer, sizeof(path_buffer), "/data/%s/", get_system_file_dir_name().c_str());
    return path_buffer;
}

// /data/<目录名>/modules/ —— 模块安装与加载共用的列表目录。
static std::string get_module_list_dir_path() {
    return (std::filesystem::path(get_system_file_dir_path()) / "modules" / "").string();
}

//   return (path(get_module_list_dir_path()) / "webui_loader");
static std::string get_webui_loader_path() {
    return (std::filesystem::path(get_module_list_dir_path()) / "webui_loader");
}

//   return (path(get_module_list_dir_path()) / module_id32 / "").string();
static std::string get_module_private_dir_path(const char* module_id32) {
    return (std::filesystem::path(get_module_list_dir_path()) / module_id32 / "").string();
}

//                 std::filesystem::path(dir) / id       （dir 是左值 → path 模板构造）
static inline __attribute__((always_inline))
std::string get_module_elf_path(const char* module_id32) {
    if (module_id32 == nullptr || strlen(module_id32) == 0) {
        return std::string();
    }
    const std::string module_private_dir = get_module_private_dir_path(module_id32);
    return (std::filesystem::path(module_private_dir) / module_id32).string();
}

namespace features {
namespace web_ui {

//                                          const char* mod_id32,
//                                          int& out_port)
//
//                打开/seek/tell/read 任一步失败          → ERR_MODULE_OPEN_DIR
//                解析失败 → 原样返回解析错误；web_ui==false
//                                                        → ERR_MODULE_WEB_UI_SERVER_NOT_EXIST
//       read_errcode_from_child(); 读失败 → ERR_READ_CHILD_ERRCODE；
//       子进程 OK → out_port = port；返回 err。
KModErr start_module_web_ui_server_async(const char* root_key, const char* mod_id32,
                                         int& out_port) {
    if (root_key == nullptr) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const size_t root_key_len = strnlen(root_key, 1024);
    if (root_key_len < 16 || root_key_len >= 1024) {
        return KModErr::ERR_MODULE_ROOT_KEY;
    }

    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    CpuPinGuardAuto cpu_pin_guard(false);

    KModErr err = KModErr::OK;

    // webui_loader 用它判断调用方是否还在；端口区间 [20000, 60000]。
    const int32_t caller_pid = static_cast<int32_t>(getpid());
    srand(static_cast<unsigned int>(time(nullptr)));
    const int port = 20000 + rand() % 40001;

    fork_pipe_info pipe;
    if (fork_pipe_child_process(pipe)) {
        // ================= 子进程 =================
        err = default_modules::module_root::set_current_root(true);
        if (is_ok(err)) {
            const std::string webui_loader_path = get_webui_loader_path();
            std::error_code exists_error;
            if (!std::filesystem::exists(std::filesystem::path(webui_loader_path),
                                         exists_error)) {
                err = KModErr::ERR_MODULE_WEB_UI_LOADER_NOT_EXIST;
            } else {
                // 随后 ifstream 必然失败 → ERR_MODULE_OPEN_DIR。
                std::string module_elf_path = get_module_elf_path(mod_id32);
                // module_private_dir（其结果在 main 里未再被使用）；保持同一次求值，
                std::string module_private_dir = get_module_private_dir_path(mod_id32);
                (void)module_private_dir;

                std::vector<uint8_t> elf_bytes;
                std::ifstream module_elf(module_elf_path.c_str(), std::ios::binary);
                if (!module_elf) {
                    err = KModErr::ERR_MODULE_OPEN_DIR;
                } else {
                    module_elf.seekg(0, std::ios::end);
                    const std::streamoff elf_size = module_elf.tellg();
                    if (elf_size < 0) {
                        err = KModErr::ERR_MODULE_OPEN_DIR;
                    } else {
                        module_elf.seekg(0, std::ios::beg);
                        elf_bytes.resize(static_cast<size_t>(elf_size));
                        module_elf.read(reinterpret_cast<char*>(elf_bytes.data()), elf_size);
                        if (!module_elf) {
                            err = KModErr::ERR_MODULE_OPEN_DIR;
                        } else {
                            module_desc desc{};
                            err = parse_module_meta_from_elf_bytes(elf_bytes, desc);
                            if (is_ok(err) && !desc.web_ui) {
                                err = KModErr::ERR_MODULE_WEB_UI_SERVER_NOT_EXIST;
                            }
                        }
                    }
                }
            }
        }

        write_errcode_from_child(pipe, err);
        pipe.close_all();

        if (is_failed(err)) {
            _exit(0);
        }

        // 本次会话是否开了 MapleSU 日志（"1"/"0"）。环境变量原样继承。
        std::string loader_path = get_webui_loader_path();
        std::string port_text = std::to_string(port);
        std::string caller_pid_text = std::to_string(caller_pid);
        const char* loader_argv[] = {
            loader_path.c_str(),
            mod_id32,
            port_text.c_str(),
            caller_pid_text.c_str(),
            is_maplesu_log_enabled(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW())
                ? "1"
                : "0",
            nullptr,
        };
        execve(loader_path.c_str(), const_cast<char* const*>(loader_argv), environ);
        _exit(0);
    }

    // ================= 父进程 =================
    // 子进程成功（err==OK）时把随机端口回填给调用方。
    if (!read_errcode_from_child(pipe, err)) {
        err = KModErr::ERR_READ_CHILD_ERRCODE;
    } else if (is_ok(err)) {
        out_port = port;
    }
    return err;
}

}  // namespace web_ui
}  // namespace features

}  // namespace maplesu::sdk
