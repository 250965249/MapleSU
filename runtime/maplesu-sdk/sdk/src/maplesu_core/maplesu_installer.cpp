// MapleSU installer implementation.
//
#include "maplesu/compat/persisted_inputs.h"
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

// maplesu::sdk/{maplesu_installer,maplesu_module,…}.h、module_descriptor.h
// （→ third_party/____DO_NOT_EDIT____/private_desc_parser.h：3 个 weak
//   __maplesu_module_* 入口 + maplesu_web_ui_handler/enable_flag inline 变量）
// 以及 module_base_kernel_export_symbol.inl（3 张 static 符号表 + 其动态初始化）。
#include "kernel_module_kit_umbrella.h"

namespace {

// 固定目标缓冲的定长格式化：由调用方保证缓冲区与宽度一致。
int format_text(char* buffer, std::size_t buffer_size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int (*const write_fn)(char*, std::size_t, const char*, va_list) = &::vsnprintf;
    const int written = write_fn(buffer, buffer_size, format, args);
    va_end(args);
    return written;
}

// bionic 的带对象大小 strlen 检查入口；上限由调用方编译期数组宽度给出。
extern "C" std::size_t length_check_entry(const char* text, std::size_t size)
    asm("__strlen_chk");

// 定长前缀的带界长度检查：长度上限由数组本身给出，越界读取会被拦下。
std::size_t checked_length(const char* text, std::size_t size) {
    return length_check_entry(text, size);
}

}  // namespace

namespace maplesu::sdk {

class fork_base_info {
public:
    fork_base_info() { reset(); }
    ~fork_base_info() { close_all(); }

    void reset() {
        close_all();
        _fds[0] = -1;
        _fds[1] = -1;
        _fds[2] = -1;
        _fds[3] = -1;
        _pid = ::getpid();
        _child_pid = 0;
    }

    void close_all() {
        safe_close(_fds[0]);
        safe_close(_fds[1]);
        safe_close(_fds[2]);
        safe_close(_fds[3]);
    }

    void safe_close(int& fd) {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

    int child_pid() const { return _child_pid; }

private:
    int _fds[4] = {-1, -1, -1, -1};  // 偏移 0/4/8/12
    pid_t _pid = -1;                 // 偏移 16，reset 时=getpid()
    int _child_pid = -1;             // 偏移 20，reset 时=0
};

class fork_pipe_info final : public fork_base_info {};

bool fork_pipe_child_process(fork_pipe_info& pipe);                     // 子进程返回 true
bool read_errcode_from_child(const fork_pipe_info& pipe, KModErr& out_err);
bool write_errcode_from_child(const fork_pipe_info& pipe, KModErr err);
bool read_string_from_child(fork_pipe_info& pipe, std::string& out_text);
bool write_string_from_child(const fork_pipe_info& pipe, const std::string& text);
bool read_int_from_child(const fork_pipe_info& pipe, int& out_value);
bool write_int_from_child(const fork_pipe_info& pipe, int value);

// ---- MapleSU 私有 unsafe_* 安装原语（实现在其它成员，U 集） ----
KModErr unsafe_clean_older_hide_dir();
KModErr unsafe_create_hide_dir();
KModErr unsafe_del_hide_dir();
KModErr unsafe_install_su();
KModErr unsafe_install_webui_loader();
KModErr unsafe_install_autorun_bootstrap();
KModErr unsafe_install_resetprop();
KModErr unsafe_reset_autorun_bootstrap_safe_flag();
KModErr unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag();
KModErr unsafe_restart_zygote64();
KModErr unsafe_get_all_modules(std::vector<module_record>& out_modules);
KModErr safe_uninstall_module(const char* mod_id32);

}  // namespace maplesu::sdk

// ---- default_modules 私有入口（U 集：_ZN15default_modules…） ----
namespace default_modules::module_root {
KModErr set_current_root(bool enable);
}
namespace default_modules::module_bypass_oplus_secure_guard {
bool first_install_init();
}

// ---- module root-key 运行时（符号为 C linkage，名字带内容哈希） ----
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char* root_key);

// ---- helper-allowlist 环境状态助手（实现在 maplesu_environment_state.o） ----
extern "C" uint32_t maplesu_environment_state();
extern "C" pid_t maplesu_wait_environment_child(pid_t child, int* status);
extern "C" long maplesu_installer_launch_error(int stage, const char* helper);
extern "C" int maplesu_installer_exec(const char*, char* const[], char* const[]);
extern "C" pid_t maplesu_installer_wait_child(pid_t, int*, const char*);
extern "C" long maplesu_installer_result_open(int, int[2]);
extern "C" long maplesu_installer_result_parent(pid_t, int, int[2]);
extern "C" void maplesu_installer_result_worker(int[2]);
extern "C" int maplesu_installer_result_complete(int[2], const char*, int);

// 语义 = 分别原地构造 <kernel_file_dir>/init 与 <kernel_file_dir>/MapleSU.sdk.ver
extern "C" __attribute__((visibility("hidden"))) void maplesu_environment_paths(
    std::string* helper, std::string* version);

namespace maplesu::sdk {

namespace {
constexpr const char* kSdkVersionText = "5.2.0";
constexpr const char* kSdkVersionFormat = "%u.%u.%u";
// private_desc_parser.h 的 FOLDER_HEAD_ROOT_KEY_LEN = 16。
constexpr size_t kRootKeyBufferSize = 1024;
}  // namespace

//   char buf[1024] = {0};
//   snprintf(buf, sizeof(buf), "/data/%s/", std::string(root_key()).substr(0,16).c_str());
//   return buf;
static std::string get_kernel_file_dir_path() {
    char path[kRootKeyBufferSize] = {0};
    const std::string root_key = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    // 根密钥必须能完整装进路径缓冲，否则后续拼接会被截断。
    if (checked_length(root_key.c_str(), kRootKeyBufferSize) >= kRootKeyBufferSize) {
        return std::string();
    }
    format_text(path, sizeof(path), "/data/%s/",
                  root_key.substr(0, FOLDER_HEAD_ROOT_KEY_LEN).c_str());
    return std::string(path);
}

//   return std::filesystem::path(get_kernel_file_dir_path()) / "init";
static std::string get_autorun_bootstrap_path() {
    return std::filesystem::path(get_kernel_file_dir_path()) / "init";
}

//   return std::filesystem::path(get_kernel_file_dir_path()) / maplesu::compat::kEnvironmentVersionFile;
static std::string get_maplesu_sdk_ver_path() {
    return std::filesystem::path(get_kernel_file_dir_path()) / maplesu::compat::kEnvironmentVersionFile;
}

//       { return (int)maplesu_environment_state(); }
// 该函数是 environment-state 修补点：真值来自 helper member。
static int unsafe_get_maplesu_environment_state() {
    return static_cast<int>(maplesu_environment_state());
}

}  // namespace maplesu::sdk

namespace file_utils {

// 参数仅参与 mangling（U 集内 _ZN10file_utilsL28…NS_15SelinuxFileFlagE）。
enum class SelinuxFileFlag : uint32_t {
    None = 0,
    KernelExec = 1,
};

static bool file_exists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

//     → vector<uint8_t>::resize(size) → read → string.assign(begin,end)
static bool read_text_file(const char* path, std::string& out_text) {
    std::vector<uint8_t> bytes;
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;

    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size < 0) return false;

    stream.seekg(0, std::ios::beg);
    bytes.resize(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(bytes.data()), size);
    if (!stream) return false;

    out_text.assign(bytes.begin(), bytes.end());
    return true;
}

static bool create_empty_file(const char* path) {
    std::ofstream stream(path, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!stream.is_open()) return false;
    stream.close();
    return true;
}

//     "u:object_r:kernel:s0", sizeof(值), 0)==0
static bool set_file_selinux_access_mode(const char* path,
                                         SelinuxFileFlag flag = SelinuxFileFlag::None) {
    (void)flag;
    if (::chmod(path, 0777) != 0) return false;
    static constexpr char kSelinuxKey[] = "security.selinux";
    static constexpr char kSelinuxValue[] = "u:object_r:kernel:s0";
    return ::setxattr(path, kSelinuxKey, kSelinuxValue, sizeof(kSelinuxValue), 0) == 0;
}

static bool write_text_file(const char* path, std::string_view text) {
    if (path == nullptr) return false;
    std::ofstream stream(path, std::ios::out | std::ios::trunc);
    if (!stream.is_open()) return false;
    stream << text;
    return stream.good();
}

}  // namespace file_utils

namespace boot_session_utils {
namespace detail {

//     若发生裁剪则 text = text.substr(first, last-first)（substr + move assign）。
static void trim_ascii_space_inplace(std::string& text) {
    const auto is_ascii_space = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    };
    const std::size_t size = text.size();
    std::size_t first = 0;
    while (first < size && is_ascii_space(text[first])) ++first;
    std::size_t last = size;
    while (last > first && is_ascii_space(text[last - 1])) --last;
    if (first != 0 || last != size) text = text.substr(first, last - first);
}

}  // namespace detail

//     → 失败/空则返回空串；成功则构造 string 并 trim。
static std::string read_boot_session() {
    std::FILE* fp = std::fopen("/proc/sys/kernel/random/boot_id", "r");
    if (fp == nullptr) return std::string();
    char line[128] = {0};
    char* got = std::fgets(line, static_cast<int>(sizeof(line)), fp);
    std::fclose(fp);
    if (got == nullptr) return std::string();
    std::string session(line);
    detail::trim_ascii_space_inplace(session);
    return session;
}

}  // namespace boot_session_utils

static void linux_reboot() {
    std::FILE* fp = ::popen("reboot", "r");
    if (fp != nullptr) ::pclose(fp);
}

namespace maplesu::sdk {

//   set_current_root(true) → 失败直接返回；
//   unsafe_get_state()==NotInstalled(0) → ERR_MAPLESU_ENV_NOT_INSTALL；
//   版本文件不存在 → ERR_MODULE_FILE_NOT_EXIST；
//   读失败 → ERR_MODULE_READ_FILE；成功回填 out_version。
static KModErr unsafe_get_installed_maplesu_environment_version(std::string& out_version) {
    const KModErr root_err = default_modules::module_root::set_current_root(true);
    if (is_failed(root_err)) return root_err;

    if (unsafe_get_maplesu_environment_state() == 0) {
        return KModErr::ERR_MAPLESU_ENV_NOT_INSTALL;
    }

    const std::string version_path = get_maplesu_sdk_ver_path();
    if (!file_utils::file_exists(std::filesystem::path(version_path))) {
        return KModErr::ERR_MODULE_FILE_NOT_EXIST;
    }
    if (!file_utils::read_text_file(version_path.c_str(), out_version)) {
        return KModErr::ERR_MODULE_READ_FILE;
    }
    return KModErr::OK;
}

//   strdup 命令行 → calloc(9, sizeof(char*))、capacity=8，容量不足时
//   capacity = capacity*2+1 并 realloc + __memset_chk 清零新槽；
//   逐段按空白切分，支持 ' 与 " 引号（引号内保留空白，引号本身去掉）；
//   无 token 或分配失败 → _exit(127)；否则 execve(argv[0], argv, environ)；
//   execve 返回（失败）→ 释放后 _exit(127)。
static void exec_bootstrap_command(const char* command) {
    const auto is_space = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    };
    if (command == nullptr || *command == '\0') ::_exit(127);
    char* buffer = ::strdup(command);
    if (buffer == nullptr) ::_exit(127);

    constexpr std::size_t kInitialCapacity = 8;
    char** argv = static_cast<char**>(::calloc(kInitialCapacity + 1, sizeof(char*)));
    if (argv == nullptr) {
        ::free(buffer);
        ::_exit(127);
    }

    std::size_t argc = 0;
    std::size_t capacity = kInitialCapacity;
    char* cursor = buffer;
    while (*cursor != '\0') {
        while (*cursor != '\0' && is_space(*cursor)) ++cursor;
        if (*cursor == '\0') break;

        if (argc >= capacity) {
            const std::size_t grown_capacity = capacity * 2 + 1;
            char** grown = static_cast<char**>(::realloc(argv, grown_capacity * sizeof(char*)));
            if (grown == nullptr) {
                ::free(argv);
                ::free(buffer);
                ::_exit(127);
            }
            ::memset(grown + capacity, 0, (grown_capacity - capacity) * sizeof(char*));
            argv = grown;
            capacity = grown_capacity;
        }

        argv[argc] = cursor;
        ++argc;

        if (*cursor == '"' || *cursor == '\'') {
            const char quote = *cursor;
            argv[argc - 1] = cursor + 1;
            char* scan = argv[argc - 1];
            while (*scan != '\0' && *scan != quote) ++scan;
            const bool quote_closed = (*scan == quote);
            *scan = '\0';
            cursor = scan + (quote_closed ? 1 : 0);
        } else {
            char* scan = cursor;
            while (*scan != '\0' && !is_space(*scan)) ++scan;
            if (*scan != '\0') {
                *scan = '\0';
                cursor = scan + 1;
            } else {
                cursor = scan;
            }
        }
    }

    if (argc == 0) {
        ::free(argv);
        ::free(buffer);
        ::_exit(127);
    }
    argv[argc] = nullptr;
    maplesu_installer_exec(argv[0], argv, environ);
    ::free(argv);
    ::free(buffer);
    ::_exit(127);
}

// 三、MapleSU 环境安装
//
//    校验 root_key → set_root_key
//    fork_pipe_child_process(pipe)
//      ├─ 子进程（返回 true）：
//      │    set_current_root → unsafe_clean_older_hide_dir
//      │    → read_boot_session（空 ⇒ ERR_MODULE_BOOT_SESSION）
//      │    → 探测已装版本 → 判断是否需要安装
//      │       需要安装：create_hide_dir → install_su → install_webui_loader
//      │                → install_autorun_bootstrap → install_resetprop
//      │                → set_current_root → 建 .log.enable
//      │                → set_current_root → 建 .boot_fail_protect
//      │                → first_install_init
//      │    → set_current_root → 写 install.mode → set_current_root
//      │    → 写 install_config.exploit
//      │    → reset safe_flag → reset duplicate_boot_session_flag → sync
//      │    → fork()：
//      │        ├─ 分离子进程：Boot ⇒ sleep(3)+reboot；HotLoad ⇒ fork 执行
//      │        │   bootstrap，等其结束，非 CVE 模式再 restart_zygote64；
//      │        │   两条路最终 _exit(0)
//      │        └─ 原 fork 子进程：write_errcode(OK)+close_all+_exit(0)
//      │    任一步失败：write_errcode(err)+close_all+_exit(0)
//      └─ 父进程（返回 false）：read_errcode_from_child + waitpid → 返回 err
KModErr install_maplesu_environment(const char* root_key, InstallMode mode,
                                   const InstallConfig& config) {
    // 其中 len = strnlen(root_key, 1024)；null 与非法长度都返回 ERR_MODULE_ROOT_KEY）
    if (root_key == nullptr) return KModErr::ERR_MODULE_ROOT_KEY;
    {
        const std::size_t root_key_len = ::strnlen(root_key, kRootKeyBufferSize);
        if (root_key_len < FOLDER_HEAD_ROOT_KEY_LEN || root_key_len >= kRootKeyBufferSize) {
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
    }

    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    fork_pipe_info pipe;
    KModErr err = KModErr::OK;
    if (fork_pipe_child_process(pipe)) {
        // 子进程统一的失败/成功出口：回传错误码、关闭管道、退出。
        const auto child_exit = [&](KModErr child_err) {
            (void)write_errcode_from_child(pipe, child_err);
            pipe.close_all();
            ::_exit(0);
        };

        err = default_modules::module_root::set_current_root(true);
        if (is_failed(err)) child_exit(err);

        err = unsafe_clean_older_hide_dir();
        if (is_failed(err)) child_exit(err);

        const std::string boot_session = boot_session_utils::read_boot_session();
        if (boot_session.empty()) child_exit(KModErr::ERR_MODULE_BOOT_SESSION);

        std::string installed_version;
        (void)unsafe_get_installed_maplesu_environment_version(installed_version);

        //   (mode == Boot) || (mode == HotLoad && installed_version != 当前SDK版本)
        // 即：Boot 模式总是重装；HotLoad 只有在已装版本不是当前版本时才重装；
        const bool need_install =
            (mode == InstallMode::Boot) ||
            (mode == InstallMode::HotLoad && installed_version != kSdkVersionText);

        if (need_install) {
            err = unsafe_create_hide_dir();
            if (is_failed(err)) child_exit(err);

            err = unsafe_install_su();
            if (is_failed(err)) child_exit(err);

            err = unsafe_install_webui_loader();
            if (is_failed(err)) child_exit(err);

            err = unsafe_install_autorun_bootstrap();
            if (is_failed(err)) child_exit(err);

            err = unsafe_install_resetprop();
            if (is_failed(err)) child_exit(err);

            err = default_modules::module_root::set_current_root(true);
            if (is_failed(err)) child_exit(err);

            // <autorun_bootstrap>.log.enable：存在性开关文件
            {
                const std::string enable_flag_path =
                    get_autorun_bootstrap_path() + ".log" + ".enable";
                if (!file_utils::create_empty_file(enable_flag_path.c_str())) {
                    child_exit(KModErr::ERR_MODULE_CREATE_EMPTY_FILE);
                }
                if (!file_utils::set_file_selinux_access_mode(enable_flag_path.c_str())) {
                    child_exit(KModErr::ERR_SET_FILE_SELINUX);
                }
                ::sync();
            }

            err = default_modules::module_root::set_current_root(true);
            if (is_failed(err)) child_exit(err);

            // <autorun_bootstrap>.boot_fail_protect：本次启动故障保护标记
            {
                const std::string fail_protect_path =
                    get_autorun_bootstrap_path() + ".boot_fail_protect";
                if (!file_utils::create_empty_file(fail_protect_path.c_str())) {
                    child_exit(KModErr::ERR_MODULE_CREATE_EMPTY_FILE);
                }
                if (!file_utils::set_file_selinux_access_mode(fail_protect_path.c_str())) {
                    child_exit(KModErr::ERR_SET_FILE_SELINUX);
                }
                ::sync();
            }

            (void)default_modules::module_bypass_oplus_secure_guard::first_install_init();
        }

        // ---- 安装模式 / 漏洞策略落盘（HotLoad 跳过重装时也要刷新） ----
        err = default_modules::module_root::set_current_root(true);
        if (is_failed(err)) child_exit(err);

        {
            const std::string mode_path =
                std::filesystem::path(get_kernel_file_dir_path()) / "install.mode";
            std::string mode_text;
            switch (mode) {
                case InstallMode::Boot: mode_text = "boot"; break;
                case InstallMode::HotLoad: mode_text = "hotload"; break;
                default: break;
            }
            if (!file_utils::write_text_file(mode_path.c_str(), mode_text)) {
                child_exit(KModErr::ERR_MODULE_WRITE_FILE);
            }
            if (!file_utils::set_file_selinux_access_mode(mode_path.c_str())) {
                child_exit(KModErr::ERR_SET_FILE_SELINUX);
            }
        }

        err = default_modules::module_root::set_current_root(true);
        if (is_failed(err)) child_exit(err);

        {
            const std::string exploit_path =
                std::filesystem::path(get_kernel_file_dir_path()) / "install_config.exploit";
            const std::string exploit_text =
                config.exploit == ExploitMethod::Magica
                    ? "magica"
                    : (config.exploit == ExploitMethod::CVE2026_43499 ? "cve2026_43499" : "none");
            if (!file_utils::write_text_file(exploit_path.c_str(), exploit_text)) {
                child_exit(KModErr::ERR_MODULE_WRITE_FILE);
            }
            if (!file_utils::set_file_selinux_access_mode(exploit_path.c_str())) {
                child_exit(KModErr::ERR_SET_FILE_SELINUX);
            }
        }

        err = unsafe_reset_autorun_bootstrap_safe_flag();
        if (is_failed(err)) child_exit(err);

        err = unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag();
        if (is_failed(err)) child_exit(err);

        ::sync();

        // ---- 分离出重启 / 热装载子进程，让安装调用本身尽快返回 ----
        int result_pipe[2] = {-1, -1};
        const int mode_value = static_cast<int>(mode);
        const auto pipe_error = maplesu_installer_result_open(mode_value, result_pipe);
        if (pipe_error != 0) child_exit(static_cast<KModErr>(pipe_error));
        const pid_t detached_pid = ::fork();
        if (detached_pid < 0) {
            (void)maplesu_installer_launch_error(1, nullptr);
            child_exit(static_cast<KModErr>(maplesu_installer_result_parent(detached_pid, mode_value, result_pipe)));
        }
        if (detached_pid == 0) {
            maplesu_installer_result_worker(result_pipe);
            if (mode == InstallMode::Boot) {
                // Boot 模式：等待写入落盘后重启，让新内核/环境生效。
                (void)::sleep(3);
                linux_reboot();
            } else if (mode == InstallMode::HotLoad) {
                // HotLoad 模式：执行 bootstrap（argv 由命令行切分而来）。
                const std::string bootstrap_path = get_autorun_bootstrap_path();
                const pid_t exec_pid = ::fork();
                if (exec_pid == 0) {
                    exec_bootstrap_command(bootstrap_path.c_str());  // 不返回
                }
                if (exec_pid < 0) {
                    (void)maplesu_installer_launch_error(2, bootstrap_path.c_str());
                    (void)maplesu_installer_result_complete(result_pipe, bootstrap_path.c_str(), 0);
                    ::_exit(127);
                }
                int exec_status = 0;
                const bool launched = maplesu_installer_wait_child(exec_pid, &exec_status, bootstrap_path.c_str()) == exec_pid &&
                    exec_status == 0;
                if (!maplesu_installer_result_complete(result_pipe, bootstrap_path.c_str(), launched)) {
                    ::_exit(127);
                }
                // 非 CVE 模式需要显式重启 zygote64；CVE 模式由漏洞路径自行完成。
                if (config.exploit == ExploitMethod::None ||
                    config.exploit == ExploitMethod::Magica) {
                    const KModErr restart_err = unsafe_restart_zygote64();
                    if (is_failed(restart_err)) child_exit(restart_err);
                }
            }
            ::_exit(0);
        }

        // HotLoad only reports the worker's validated result; Boot retains asynchronous reboot.
        child_exit(static_cast<KModErr>(maplesu_installer_result_parent(detached_pid, mode_value, result_pipe)));
    }

    // ---- 父进程：收子进程错误码并回收子进程 ----
    if (!read_errcode_from_child(pipe, err)) err = KModErr::ERR_READ_CHILD_ERRCODE;
    int child_status = 0;
    const pid_t waited = maplesu_wait_environment_child(pipe.child_pid(), &child_status);
    if (waited != pipe.child_pid() || child_status != 0) return static_cast<KModErr>(-21002);
    return err;
}

// 四、MapleSU 环境卸载
//
//    校验 root_key → set_root_key → fork_pipe_child_process
//      子进程：set_current_root → unsafe_get_all_modules（逐个 safe_uninstall_module）
//              → unsafe_clean_older_hide_dir → remove_all(<bootstrap>) → 仍存在则
//              ERR_MODULE_DEL_FILE；否则 unsafe_del_hide_dir → sync → fork 后
//              sleep(3)+reboot（分离子进程），原进程回传 errcode
//      父进程：read_errcode + waitpid → 返回 err
KModErr uninstall_maplesu_environment(const char* root_key) {
    // 其中 len = strnlen(root_key, 1024)；null 与非法长度都返回 ERR_MODULE_ROOT_KEY）
    if (root_key == nullptr) return KModErr::ERR_MODULE_ROOT_KEY;
    {
        const std::size_t root_key_len = ::strnlen(root_key, kRootKeyBufferSize);
        if (root_key_len < FOLDER_HEAD_ROOT_KEY_LEN || root_key_len >= kRootKeyBufferSize) {
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
    }

    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    fork_pipe_info pipe;
    KModErr err = KModErr::OK;
    if (fork_pipe_child_process(pipe)) {
        const auto child_exit = [&](KModErr child_err) {
            (void)write_errcode_from_child(pipe, child_err);
            pipe.close_all();
            ::_exit(0);
        };

        err = default_modules::module_root::set_current_root(true);
        if (is_ok(err)) {
            std::vector<module_record> modules;
            (void)unsafe_get_all_modules(modules);
            for (const module_record& record : modules) {
                (void)safe_uninstall_module(record.desc.id32);
            }

            err = unsafe_clean_older_hide_dir();
            if (is_ok(err)) {
                const std::string bootstrap_path = get_autorun_bootstrap_path();
                const std::filesystem::path bootstrap_file(bootstrap_path.c_str());
                std::error_code ec;
                (void)std::filesystem::remove_all(bootstrap_file, ec);
                if (file_utils::file_exists(bootstrap_file)) {
                    err = KModErr::ERR_MODULE_DEL_FILE;  // -19931：删除后仍存在
                } else {
                    err = unsafe_del_hide_dir();
                    if (is_ok(err)) {
                        ::sync();
                        // 分离子进程延时重启；父进程（本子进程）回传 OK。
                        if (::fork() == 0) {
                            (void)::sleep(3);
                            linux_reboot();
                            ::_exit(0);
                        }
                        err = KModErr::OK;
                    }
                }
            }
        }
        child_exit(err);
    }

    if (!read_errcode_from_child(pipe, err)) err = KModErr::ERR_READ_CHILD_ERRCODE;
    int child_status = 0;
    (void)::waitpid(pipe.child_pid(), &child_status, 0);
    return err;
}

// 五、MapleSU 环境状态查询
//
//    set_root_key → fork_pipe_child_process
//      子进程：调用 unsafe_get_maplesu_environment_state()（= maplesu_environment_state）
//              把结果 write_int_from_child 回传，close_all，_exit(0)
//      父进程：read_int_from_child（初值 Unknown=3）→
//              maplesu_wait_environment_child(child_pid, &status)
//              → 只有 “读回成功 && wait 命中该 pid && pid>0 && 子进程正常退出 &&
//                状态值 < 4” 才算可信，否则返回 Unknown（禁止推断）。
MapleSUEnvState get_maplesu_environment_state(const char* root_key) {
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    fork_pipe_info pipe;
    if (fork_pipe_child_process(pipe)) {
        const int state = unsafe_get_maplesu_environment_state();
        (void)write_int_from_child(pipe, state);
        pipe.close_all();
        ::_exit(0);
    }

    int state = static_cast<int>(MapleSUEnvState::Unknown);
    const bool read_ok = read_int_from_child(pipe, state);

    int child_status = 0;
    const int child_pid = pipe.child_pid();
    const pid_t waited = maplesu_wait_environment_child(static_cast<pid_t>(child_pid), &child_status);

    const bool reply_ok = read_ok && waited == child_pid && child_pid > 0 &&
                          child_status == 0 && static_cast<unsigned int>(state) < 4u;
    return reply_ok ? static_cast<MapleSUEnvState>(state) : MapleSUEnvState::Unknown;
}

// 六、已安装环境版本查询
//
//    校验 root_key → set_root_key → fork_pipe_child_process
//      子进程：unsafe_get_installed_maplesu_environment_version(text) →
//              write_errcode + write_string + close_all + _exit(0)
//      父进程：read_errcode（失败记 ERR_READ_CHILD_ERRCODE）→
//              read_string（失败记 ERR_READ_CHILD_STRING）→ waitpid →
//              err==OK 时 sscanf(text,"%u.%u.%u", major,minor,patch)
KModErr get_installed_maplesu_environment_version(const char* root_key,
                                                MapleSUSdkVersion& out_ver) {
    // 其中 len = strnlen(root_key, 1024)；null 与非法长度都返回 ERR_MODULE_ROOT_KEY）
    if (root_key == nullptr) return KModErr::ERR_MODULE_ROOT_KEY;
    {
        const std::size_t root_key_len = ::strnlen(root_key, kRootKeyBufferSize);
        if (root_key_len < FOLDER_HEAD_ROOT_KEY_LEN || root_key_len >= kRootKeyBufferSize) {
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
    }

    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);

    std::string version_text;
    fork_pipe_info pipe;
    KModErr err = KModErr::OK;
    if (fork_pipe_child_process(pipe)) {
        err = unsafe_get_installed_maplesu_environment_version(version_text);
        (void)write_errcode_from_child(pipe, err);
        (void)write_string_from_child(pipe, version_text);
        pipe.close_all();
        ::_exit(0);
    }

    if (!read_errcode_from_child(pipe, err)) err = KModErr::ERR_READ_CHILD_ERRCODE;
    if (!read_string_from_child(pipe, version_text)) err = KModErr::ERR_READ_CHILD_STRING;
    int child_status = 0;
    (void)::waitpid(pipe.child_pid(), &child_status, 0);

    if (is_ok(err)) {
        std::sscanf(version_text.c_str(), kSdkVersionFormat, &out_ver.major,
                    &out_ver.minor, &out_ver.patch);
    }
    return err;
}

// 七、当前 SDK 版本
//
//      &ver.major,&ver.minor,&ver.patch); return ver;（12 B 结构按寄存器对返回）
MapleSUSdkVersion get_sdk_version() {
    MapleSUSdkVersion version{};
    std::sscanf(kSdkVersionText, kSdkVersionFormat, &version.major, &version.minor,
                &version.patch);
    return version;
}

}  // namespace maplesu::sdk

// 八、helper-allowlist 环境状态助手的路径提供者
//
//    define hidden void @maplesu_environment_paths(ptr %helper, ptr %version) {
//      call fastcc void @get_autorun_bootstrap_path(ptr sret(...) %helper)
//      call fastcc void @get_maplesu_sdk_ver_path(ptr sret(...) %version)
//      ret void
//    }
//  语义：把两条 key 派生路径**原地构造**进调用方给定的 std::string 对象，
//  与 runtime/ultra/boot/environment_state.cpp 的
//  `extern "C" void maplesu_environment_paths(std::string*, std::string*);` 契约一致。
//  placement-new + 纯右值保证复制消除，直接以 sret 写入目标对象（无额外拷贝）。
extern "C" __attribute__((visibility("hidden"))) void maplesu_environment_paths(
    std::string* helper, std::string* version) {
    ::new (static_cast<void*>(helper)) std::string(maplesu::sdk::get_autorun_bootstrap_path());
    ::new (static_cast<void*>(version)) std::string(maplesu::sdk::get_maplesu_sdk_ver_path());
}
