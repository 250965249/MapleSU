// MapleSU root private implementation.
//
#pragma once

#include "miss_a_native_private.h"

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace default_modules {

class module_bypass_mtk_mkp {
public:
    static const char* get_module_eng_name();
    static KModErr init();
};

class module_bypass_oplus_secure_guard {
public:
    static const char* get_module_eng_name();
    static KModErr init();
};

class module_bypass_oplus_inte {
public:
    static const char* get_module_eng_name();
    static KModErr init();
};

}  // namespace default_modules

// API21 headers spell stdout/stderr as __sF array addresses, while modern
// bionic exports writable FILE* data slots. Resolve those without dlopen/dlsym
// inside a fork worker and retain the SDK's API21 link target.
namespace maplesu_root_stdio {
#if defined(__BIONIC__) && __ANDROID_API__ < 23
extern "C" FILE* runtime_stdout __asm__("stdout") __attribute__((weak, visibility("default")));
extern "C" FILE* runtime_stderr __asm__("stderr") __attribute__((weak, visibility("default")));
inline FILE** output_slot() { return &runtime_stdout; }
inline FILE** error_slot() { return &runtime_stderr; }
#else
inline FILE** output_slot() { return &stdout; }
inline FILE** error_slot() { return &stderr; }
#endif
inline FILE* output() {
    FILE** slot = output_slot();
    return slot ? *slot : stdout;
}
inline FILE* error() {
    FILE** slot = error_slot();
    return slot ? *slot : stderr;
}
}  // namespace maplesu_root_stdio


// Used only by the isolated vendor fork worker. Inherited FILE objects belong
// to the requesting process; their locks and buffered bytes are never ours.
class ScopedStdToDevNull {
public:
    explicit ScopedStdToDevNull(bool redirect_stderr)
        : saved_stdout_(-1), saved_stderr_(-1), dev_null_fd_(-1),
          redirect_stderr_(redirect_stderr), restored_(false),
          original_stdout_(maplesu_root_stdio::output()),
          original_stderr_(maplesu_root_stdio::error()),
          owned_stdout_(nullptr), owned_stderr_(nullptr), error_(0),
          stdout_redirected_(false), stderr_redirected_(false),
          stdout_slot_(maplesu_root_stdio::output_slot()),
          stderr_slot_(maplesu_root_stdio::error_slot()),
          stdout_locked_(false), stderr_locked_(false) {
        // On old bionic no writable slots exist. Never wait for an inherited
        // FILE lock: only the thread that acquired it may use and release it.
        if (!stdout_slot_) {
            if (ftrylockfile(original_stdout_)) { error_ = EBUSY; return; }
            stdout_locked_ = true;
        }
        if (redirect_stderr_ && !stderr_slot_) {
            if (ftrylockfile(original_stderr_)) { error_ = EBUSY; return; }
            stderr_locked_ = true;
        }
        dev_null_fd_ = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (dev_null_fd_ < 0) { record_error(); return; }
        saved_stdout_ = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0);
        if (saved_stdout_ < 0) { record_error(); return; }
        if (stdout_slot_) {
            owned_stdout_ = open_private_stream();
            if (!owned_stdout_) { record_error(); return; }
        }
        if (redirect_stderr_) {
            saved_stderr_ = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 0);
            if (saved_stderr_ < 0) { record_error(); return; }
            if (stderr_slot_) {
                owned_stderr_ = open_private_stream();
                if (!owned_stderr_) { record_error(); return; }
            }
        }
        if (dup2(dev_null_fd_, STDOUT_FILENO) < 0) { record_error(); return; }
        stdout_redirected_ = true;
        if (stdout_slot_) *stdout_slot_ = owned_stdout_;
        if (redirect_stderr_) {
            if (dup2(dev_null_fd_, STDERR_FILENO) < 0) { record_error(); return; }
            stderr_redirected_ = true;
            if (stderr_slot_) *stderr_slot_ = owned_stderr_;
        }
    }

    ~ScopedStdToDevNull() { restore(); }

    int error() const { return error_; }

    void restore() {
        if (restored_) return;
        restored_ = true;
        const int saved_errno = errno;
        if (stdout_redirected_) {
            if (fflush(owned_stdout_ ? owned_stdout_ : original_stdout_) != 0) record_error();
            if (stdout_slot_) *stdout_slot_ = original_stdout_;
            if (dup2(saved_stdout_, STDOUT_FILENO) < 0) record_error();
        }
        if (stderr_redirected_) {
            if (fflush(owned_stderr_ ? owned_stderr_ : original_stderr_) != 0) record_error();
            if (stderr_slot_) *stderr_slot_ = original_stderr_;
            if (dup2(saved_stderr_, STDERR_FILENO) < 0) record_error();
        }
        if (owned_stdout_ && fclose(owned_stdout_) != 0) record_error();
        if (owned_stderr_ && fclose(owned_stderr_) != 0) record_error();
        owned_stdout_ = owned_stderr_ = nullptr;
        if (saved_stdout_ >= 0 && close(saved_stdout_) < 0) record_error();
        if (saved_stderr_ >= 0 && close(saved_stderr_) < 0) record_error();
        if (dev_null_fd_ >= 0 && close(dev_null_fd_) < 0) record_error();
        saved_stdout_ = saved_stderr_ = dev_null_fd_ = -1;
        if (stdout_locked_) funlockfile(original_stdout_);
        if (stderr_locked_) funlockfile(original_stderr_);
        stdout_locked_ = stderr_locked_ = false;
        errno = saved_errno;
    }

    ScopedStdToDevNull(const ScopedStdToDevNull&) = delete;
    ScopedStdToDevNull& operator=(const ScopedStdToDevNull&) = delete;

private:
    FILE* open_private_stream() {
        const int fd = fcntl(dev_null_fd_, F_DUPFD_CLOEXEC, 0);
        if (fd < 0) return nullptr;
        FILE* stream = fdopen(fd, "w");
        if (!stream) {
            const int error = errno;
            close(fd);
            errno = error;
        }
        return stream;
    }

    void record_error() {
        if (!error_) error_ = errno ? errno : EIO;
    }

    int saved_stdout_;
    int saved_stderr_;
    int dev_null_fd_;
    bool redirect_stderr_;
    bool restored_;
    FILE* original_stdout_;
    FILE* original_stderr_;
    FILE* owned_stdout_;
    FILE* owned_stderr_;
    int error_;
    bool stdout_redirected_;
    bool stderr_redirected_;
    FILE** stdout_slot_;
    FILE** stderr_slot_;
    bool stdout_locked_;
    bool stderr_locked_;
};

// Private stack-only state; the sole production instance is get_root's worker.
// Public SDK types and the frozen pipe/Root receipt ABI are unchanged.
static_assert(sizeof(ScopedStdToDevNull) == 80, "private worker FILE ownership");


namespace maplesu::sdk {

// 构造：module_name_(desc.name)，module_entry_=0，module_err_=OK，
//       start_time_=steady_clock::now()；打印分隔线('*')、模块类型行
//       （is_default_module ? "MapleSU built-in mods" : "MapleSU mod"）、
//       "Name: %s"；非 default 模块再打印 Version/ID32/MinSDK；
//       update_json 非空或 web_ui 为真时打印 "Features:" 与两个 feature；
//       最后再画一次分隔线并 fflush(stdout)。
// 析构：elapsed = (now-begin) 截断到毫秒；module_err_==OK 打
//       "[Module End] name=%s, module_entry=%s, elapsed=%lld ms"，
//       否则打 "[Module Error] name=%s, error=%s, elapsed=%lld ms"，再 fflush。
//
// "MapleSU Default Module" / "MapleSU Module" / "...maplesu_module_main=%s..."，
// "...module_entry=%s..."（freeze 的 helper-allowlist 变体把 MapleSU 品牌串改成
class RootModuleBannerGuard {
public:
    RootModuleBannerGuard(const module_desc& desc, bool is_default_module)
        : module_name_(desc.name),
          module_entry_(0),
          module_err_(KModErr::OK),
          start_time_(std::chrono::steady_clock::now()) {
        print_sep('*');
        printf(is_default_module ? "MapleSU built-in mods\n" : "MapleSU mod\n");
        printf("Name: %s\n", module_name_.c_str());
        if (!is_default_module) {
            printf("Version: %s\n", desc.version);
            printf("ID32: %s\n", desc.id32);
            printf("MinSDK: %u.%u.%u\n", desc.min_sdk_ver.major, desc.min_sdk_ver.minor,
                   desc.min_sdk_ver.patch);
        }
        const bool has_update_json = strlen(desc.update_json) != 0;
        const bool has_web_ui = desc.web_ui;
        if (has_update_json || has_web_ui) {
            puts("Features:");
            print_feature("Web UI", has_web_ui);
            print_feature("Online Update", has_update_json);
        }
        print_sep('*');
        fflush(maplesu_root_stdio::output());
    }

    ~RootModuleBannerGuard() noexcept {
        const int saved_errno = errno;
        const long long elapsed_ms = static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start_time_)
                .count());
        if (module_err_ == KModErr::OK) {
            printf("[Module End] name=%s, module_entry=%d, elapsed=%lld ms\n",
                   module_name_.c_str(), module_entry_, elapsed_ms);
        } else {
            const auto name = kmoderr_name_sv(module_err_);
            if (!name.empty())
                printf("[Module Error] name=%s, error=%.*s, elapsed=%lld ms\n",
                       module_name_.c_str(), static_cast<int>(name.size()), name.data(), elapsed_ms);
            else
                printf("[Module Error] name=%s, error=Unknown(%lld), elapsed=%lld ms\n",
                       module_name_.c_str(), static_cast<long long>(module_err_), elapsed_ms);
        }
        fflush(maplesu_root_stdio::output());
        errno = saved_errno;
    }

    static void print_sep(char sep) {
        for (int i = 0; i < 30; ++i) {
            putchar(sep);
        }
        putchar('\n');
    }

    // 特性列表的一行输出：仅当特性开启时打印。构造器里多处复用，不内联。
    static __attribute__((noinline)) void print_feature(const char* feature, bool enabled) {
        if (enabled) {
            printf("   [+] %s\n", feature);
        }
    }

    RootModuleBannerGuard(const RootModuleBannerGuard&) = delete;
    RootModuleBannerGuard& operator=(const RootModuleBannerGuard&) = delete;

    std::string module_name_;                              // +0
    int module_entry_;                                     // +24（banner 里按整数转字符串）
    KModErr module_err_;                                   // +32（init() 结果，由调用方写）
    std::chrono::steady_clock::time_point start_time_;     // +40
};

static_assert(sizeof(RootModuleBannerGuard) == 48, "layout constraint violated");
static_assert(sizeof(RootModuleBannerGuard::module_name_) == 24, "std::string is 24 bytes");

}  // namespace maplesu::sdk
