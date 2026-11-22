// MapleSU module install callback implementation.
//
#include "maplesu/compat/native_module_abi.h"
#include "kernel_module_kit_umbrella.h"
#include "maplesu_module_install_callback_private.h"

#include <algorithm>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <sched.h>
#include <string>
#include <sys/prctl.h>
#include <vector>

extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();

class RedirectStdToFile {
public:
    enum class OpenMode { Truncate, Append };
    static RedirectStdToFile& instance() {
        static RedirectStdToFile inst;
        return inst;
    }
    bool redirect(const std::string& path, OpenMode mode) {
        if (redirected_) return true;
        fflush(nullptr);
        stdout_fd_ = dup(STDOUT_FILENO);
        stderr_fd_ = dup(STDERR_FILENO);
        if (stdout_fd_ < 0 || stderr_fd_ < 0) {
            if (stdout_fd_ >= 0) { close(stdout_fd_); stdout_fd_ = -1; }
            if (stderr_fd_ >= 0) { close(stderr_fd_); stderr_fd_ = -1; }
            return false;
        }
        file_fd_ = open(path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC |
                        (mode == OpenMode::Truncate ? O_TRUNC : O_APPEND), 0644);
        if (file_fd_ < 0) {
            dup2(stdout_fd_, STDOUT_FILENO);
            dup2(stderr_fd_, STDERR_FILENO);
            close(stdout_fd_); stdout_fd_ = -1;
            close(stderr_fd_); stderr_fd_ = -1;
            return false;
        }
        if (dup2(file_fd_, STDOUT_FILENO) < 0 || dup2(file_fd_, STDERR_FILENO) < 0) {
            close(file_fd_); file_fd_ = -1;
            dup2(stdout_fd_, STDOUT_FILENO);
            dup2(stderr_fd_, STDERR_FILENO);
            close(stdout_fd_); stdout_fd_ = -1;
            close(stderr_fd_); stderr_fd_ = -1;
            return false;
        }
        setvbuf(stdout, nullptr, _IOLBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        redirected_ = true;
        return true;
    }
    bool restore() {
        if (!redirected_) return true;
        fflush(nullptr);
        bool ok = true;
        if (stdout_fd_ >= 0) {
            ok = dup2(stdout_fd_, STDOUT_FILENO) >= 0;
            close(stdout_fd_); stdout_fd_ = -1;
        }
        if (stderr_fd_ >= 0) {
            ok = (dup2(stderr_fd_, STDERR_FILENO) >= 0) && ok;
            close(stderr_fd_); stderr_fd_ = -1;
        }
        if (file_fd_ >= 0) { close(file_fd_); file_fd_ = -1; }
        setvbuf(stdout, nullptr, _IOLBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        redirected_ = false;
        return ok;
    }
    ~RedirectStdToFile() { restore(); }
private:
    int stdout_fd_ = -1;
    int stderr_fd_ = -1;
    int file_fd_ = -1;
    bool redirected_ = false;
};
static_assert(sizeof(RedirectStdToFile) == 16 && alignof(RedirectStdToFile) == 4);

namespace random_utils {
namespace detail {
inline std::mt19937& mt19937_32() {
    static thread_local std::mt19937 gen(std::random_device{}());
    return gen;
}
inline std::mt19937_64& mt19937_64() {
    static thread_local std::mt19937_64 gen(std::chrono::steady_clock::now().time_since_epoch().count());
    return gen;
}
}
inline uint32_t random_u32_from_i32() {
    static thread_local std::uniform_int_distribution<int32_t> dist(INT32_MIN, INT32_MAX);
    return static_cast<uint32_t>(dist(detail::mt19937_32()));
}
inline uint32_t random_u32_from_i32(uint32_t a, uint32_t b) {
    const uint32_t lo = std::min(a, b), hi = std::max(a, b);
    if (lo == hi) return hi;
    const uint64_t range = static_cast<uint64_t>(hi) - lo + 1;
    constexpr uint64_t full_range = uint64_t{1} << 32;
    if (range == full_range) return random_u32_from_i32();
    const uint64_t limit = full_range - full_range % range;
    uint32_t value;
    do { value = random_u32_from_i32(); } while (value >= limit);
    return lo + static_cast<uint32_t>(value % range);
}
inline std::string generate_random_str_with_dot(size_t size) {
    if (!size) return {};
    static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.";
    static thread_local std::uniform_int_distribution<size_t> dist(0, sizeof(alphabet) - 2);
    std::string result;
    result.reserve(size);
    auto& generator = detail::mt19937_64();
    for (size_t i = 0; i < size; ++i) result.push_back(alphabet[dist(generator)]);
    return result;
}
}

namespace maplesu::sdk {
bool module_has_install_callback(const std::vector<uint8_t>&);
bool module_has_uninstall_callback(const std::vector<uint8_t>&);

// 本模块根密钥前 16 个字符：/data/<16 字符>/ 目录名的来源。
static std::string get_kernel_file_dir_name() {
    return std::string(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW()).substr(0, 16);
}
// /data/<16 字符>/ —— 只由密钥名构成的目录前缀。
static std::string get_kernel_file_dir_path() {
    char path[1024]{};
    snprintf(path, sizeof(path), "/data/%s/", get_kernel_file_dir_name().c_str());
    return path;
}
// /data/<16 字符>/init —— 开机自举脚本路径；日志文件是它加 ".log"。
static std::string get_autorun_bootstrap_path() {
    return (std::filesystem::path(get_kernel_file_dir_path()) / "init").string();
}
static std::string get_maplesu_log_path() { return get_autorun_bootstrap_path() + ".log"; }
// 目录名 = 前 16 字符 + 首字符（首字符重复一次）。
static std::string get_system_file_dir_name() {
    const std::string folder_head = get_kernel_file_dir_name();
    return folder_head + folder_head[0];
}
// /data/<目录名>/ —— 模块私有路径的根。
static std::string get_system_file_dir_path() {
    char path[1024]{};
    snprintf(path, sizeof(path), "/data/%s/", get_system_file_dir_name().c_str());
    return path;
}
// /data/<目录名>/modules/ —— 模块安装与加载共用的列表目录。
static std::string get_module_list_dir_path() {
    return (std::filesystem::path(get_system_file_dir_path()) / "modules" / "").string();
}
static std::string get_module_private_dir_path(const char* module_id32) {
    return (std::filesystem::path(get_module_list_dir_path()) / module_id32 / "").string();
}
static std::string get_module_elf_file_path(const char* module_id32) {
    if (!module_id32 || strlen(module_id32) == 0) return {};
    std::string private_dir = get_module_private_dir_path(module_id32);
    return (std::filesystem::path(private_dir) / module_id32).string();
}
}

namespace file_utils {
static bool read_file_bytes(const char* path, std::vector<uint8_t>& bytes) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size < 0) return false;
    stream.seekg(0, std::ios::beg);
    bytes.resize(static_cast<size_t>(size));
    return static_cast<bool>(stream.read(reinterpret_cast<char*>(bytes.data()), size));
}
}

namespace env_path_util {
namespace detail {
// 去掉路径尾部多余的 '/'（保留根 "/" 本身）。
static std::string trim_trailing_slashes(std::string text) {
    while (text.size() > 1 && text.back() == '/') text.pop_back();
    return text;
}
}  // namespace detail
}  // namespace env_path_util

static void reset_module_process_env(const std::string& module_private_dir) {
    if (setsid() < 0) setpgid(0, 0);
    signal(SIGPIPE, SIG_IGN);
    int mount_namespace = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (mount_namespace >= 0) {
        const int joined = setns(mount_namespace, CLONE_NEWNS);
        close(mount_namespace);
        if (joined >= 0) unshare(CLONE_NEWNS);
    }
    cg_v2::migrate_self_to_root();
    cg_v1::migrate_self_threads_v1();
    selinux_procattr::setcon("u:r:shell:s0");
    selinux_procattr::setexeccon("u:r:shell:s0");
    std::string process_name = random_utils::generate_random_str_with_dot(random_utils::random_u32_from_i32(1, 15));
    prctl(PR_SET_NAME, process_name.c_str(), 0, 0, 0);
    if (!module_private_dir.empty()) {
        const char* old_path = getenv("PATH");
        std::string path = old_path ? old_path : "";
        const std::string trimmed = env_path_util::detail::trim_trailing_slashes(module_private_dir);
        if (!trimmed.empty()) {
            bool found = false;
            for (size_t start = 0; start <= path.size();) {
                size_t end = path.find(':', start);
                if (end == std::string::npos) end = path.size();
                if (path.substr(start, end - start) == trimmed) {
                    found = true;
                    break;
                }
                start = end + 1;
            }
            if (!found) {
                std::string combined;
                if (path.empty()) combined = trimmed;
                else combined = trimmed + ":" + path;
                setenv("PATH", combined.c_str(), 1);
            }
        }
    }
    chdir(module_private_dir.c_str());
}

namespace maplesu::sdk::features::callback {
// Kept in its original static function so the thread-local and lambda ABI names match.
static KModErr __invoke_module_on_install(const std::string& module_id32, std::string& out_reason) {
    std::string elf_path = get_module_elf_file_path(module_id32.c_str());
    std::string private_dir = get_module_private_dir_path(module_id32.c_str());
    std::vector<uint8_t> bytes;
    if (!file_utils::read_file_bytes(elf_path.c_str(), bytes)) return KModErr::ERR_MODULE_READ_FILE;
    if (!module_has_install_callback(bytes)) return KModErr::OK;
    reset_module_process_env(private_dir);
    void* handle = dlopen(elf_path.c_str(), RTLD_NOW);
    if (!handle) {
        if (const char* error = dlerror()) fprintf(stderr, "dlopen: %s, failed: %s\n", elf_path.c_str(), error);
        return KModErr::ERR_MODULE_DLOPEN;
    }
    auto inject = reinterpret_cast<void (*)()>(dlsym(handle, maplesu::compat::native_module::kModuleIdentitySymbol));
    using Install = const char* (*)(const char*, const char*, void (*)(const char*));
    auto install = reinterpret_cast<Install>(dlsym(handle, maplesu::compat::native_module::kModuleInstallSymbol));
    if (!install) {
        if (const char* error = dlerror()) fprintf(stderr, "dlsym failed: %s\n", error);
        dlclose(handle);
        return KModErr::ERR_MODULE_DLSYM;
    }
    static thread_local std::string* tls_out = nullptr;
    tls_out = &out_reason;
    if (inject) inject();
    install(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), private_dir.c_str(),
            [](const char* reason) { if (tls_out) tls_out->assign(reason); });
    tls_out = nullptr;
    dlclose(handle);
    return out_reason.empty() ? KModErr::OK : KModErr::ERR_MODULE_REJECT_INSTALL;
}

KModErr invoke_module_on_install(const std::string& module_id32, std::string& out_reason) {
    std::string log_path = get_maplesu_log_path();
    RedirectStdToFile::instance().redirect(log_path, RedirectStdToFile::OpenMode::Append);
    KModErr result = __invoke_module_on_install(module_id32, out_reason);
    RedirectStdToFile::instance().restore();
    return result;
}

KModErr invoke_module_on_uninstall(const std::string& module_id32) {
    std::string log_path = get_maplesu_log_path();
    RedirectStdToFile::instance().redirect(log_path, RedirectStdToFile::OpenMode::Append);
    KModErr result = [&module_id32] {
        std::string elf_path = get_module_elf_file_path(module_id32.c_str());
        std::string private_dir = get_module_private_dir_path(module_id32.c_str());
        std::vector<uint8_t> bytes;
        if (!file_utils::read_file_bytes(elf_path.c_str(), bytes)) return KModErr::ERR_MODULE_READ_FILE;
        if (!module_has_uninstall_callback(bytes)) return KModErr::OK;
        reset_module_process_env(private_dir);
        void* handle = dlopen(elf_path.c_str(), RTLD_NOW);
        if (!handle) {
            if (const char* error = dlerror()) fprintf(stderr, "dlopen: %s, failed: %s\n", elf_path.c_str(), error);
            return KModErr::ERR_MODULE_DLOPEN;
        }
        auto inject = reinterpret_cast<void (*)()>(dlsym(handle, maplesu::compat::native_module::kModuleIdentitySymbol));
        auto uninstall = reinterpret_cast<void (*)(const char*, const char*)>(dlsym(handle, maplesu::compat::native_module::kModuleUninstallSymbol));
        if (!uninstall) {
            if (const char* error = dlerror()) fprintf(stderr, "dlsym failed: %s\n", error);
            dlclose(handle);
            return KModErr::ERR_MODULE_DLSYM;
        }
        if (inject) inject();
        uninstall(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), private_dir.c_str());
        dlclose(handle);
        return KModErr::OK;
    }();
    RedirectStdToFile::instance().restore();
    return result;
}
}
