// oneplus bypass private helpers.
//
// 这里只放本成员自用的两个基础设施：
//   * RedirectStdToString：把进程 stdout/stderr 收集进 std::string，供 fork 出去的
//     子进程把日志回传给父进程；
//   * ForkChildStdMode：子进程内 stdio 的处置方式。
#pragma once

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <thread>

class RedirectStdToString {
public:
    // 重定向的输出如何写入目标字符串：
    //   Reset  = 先清空再收集；
    //   Append = 追加到原内容之后。
    enum class OpenMode : int {
        Reset = 0,
        Append = 1,
    };

    // fork 出的子进程里如何处理继承来的 stdout/stderr：
    //   Restore  = 接回重定向前的原始 fd；
    //   ToDevNull = 改接到 /dev/null，避免子进程写满收集管道。
    enum class ForkChildStdMode : int {
        Restore = 0,
        ToDevNull = 1,
    };

    static RedirectStdToString& instance() {
        static RedirectStdToString inst;
        return inst;
    }

    bool redirect(std::string& out_text, OpenMode mode) {
        if (redirecting_) return true;
        if (mode == OpenMode::Reset) out_text.clear();
        consumer_ = [&out_text](const char* data, size_t size) { out_text.append(data, size); };
        return start_redirect_impl();
    }

    bool restore() {
        if (!redirecting_) return true;
        fflush(nullptr);
        bool ok = true;
        if (saved_stdout_ > -1) {
            ok = dup2(saved_stdout_, 1) > -1;
            close(saved_stdout_);
            saved_stdout_ = -1;
        }
        if (saved_stderr_ > -1) {
            ok = (dup2(saved_stderr_, 2) > -1) && ok;
            close(saved_stderr_);
            saved_stderr_ = -1;
        }
        if (thread_.joinable()) thread_.join();
        consumer_ = nullptr;
        redirecting_ = false;
        return ok;
    }

    // 本进程 fork 出子进程后，不恢复收集（父进程还要读），而是按 mode 处置
    // 继承来的 stdio：先关掉读端，再把 stdout/stderr 改接到 /dev/null 或原始 fd，
    // 最后清掉收集器状态。
    void detach_stdio_after_fork_in_child(ForkChildStdMode mode) noexcept {
        fflush(nullptr);
        if (mode != ForkChildStdMode::Restore) {
            const int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
            if (null_fd > -1) {
                dup2(null_fd, 1);
                dup2(null_fd, 2);
                if (null_fd > 2) close(null_fd);
            }
        } else {
            if (saved_stdout_ > -1) dup2(saved_stdout_, 1);
            if (saved_stderr_ > -1) dup2(saved_stderr_, 2);
        }
        if (read_fd_ > -1) {
            close(read_fd_);
            read_fd_ = -1;
        }
        if (saved_stdout_ > -1) {
            close(saved_stdout_);
            saved_stdout_ = -1;
        }
        if (saved_stderr_ > -1) {
            close(saved_stderr_);
            saved_stderr_ = -1;
        }
        redirecting_ = false;
        consumer_ = nullptr;
    }

    // 延迟 delay 后再处置 stdio（由子进程里的独立线程执行，调用方立刻返回）。
    template <typename Rep, typename Period>
    void detach_stdio_after_fork_in_child_delay(std::chrono::duration<Rep, Period> delay,
                                                ForkChildStdMode mode) noexcept {
        if (read_fd_ > -1) {
            close(read_fd_);
            read_fd_ = -1;
        }
        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        std::thread worker([this, delay, mode]() noexcept {
            std::this_thread::sleep_for(delay);
            detach_stdio_after_fork_in_child(mode);
        });
        worker.detach();
    }

    ~RedirectStdToString() {
        if (redirecting_) {
            restore();
        }
    }

    RedirectStdToString(const RedirectStdToString&) = delete;
    RedirectStdToString& operator=(const RedirectStdToString&) = delete;

private:
    RedirectStdToString() = default;

    bool start_redirect_impl() {
        int pipe_fds[2];
        if (pipe(pipe_fds) != 0) {
            consumer_ = nullptr;
            return false;
        }
        read_fd_ = pipe_fds[0];
        const int write_fd = pipe_fds[1];
        saved_stdout_ = dup(1);
        saved_stderr_ = dup(2);
        if (saved_stdout_ < 0 || saved_stderr_ < 0) {
            if (saved_stdout_ > -1) {
                close(saved_stdout_);
                saved_stdout_ = -1;
            }
            if (saved_stderr_ > -1) {
                close(saved_stderr_);
                saved_stderr_ = -1;
            }
            close(read_fd_);
            read_fd_ = -1;
            close(write_fd);
            consumer_ = nullptr;
            return false;
        }
        if (dup2(write_fd, 1) < 0 || dup2(write_fd, 2) < 0) {
            close(write_fd);
            dup2(saved_stdout_, 1);
            dup2(saved_stderr_, 2);
            close(saved_stdout_);
            saved_stdout_ = -1;
            close(saved_stderr_);
            saved_stderr_ = -1;
            close(read_fd_);
            read_fd_ = -1;
            consumer_ = nullptr;
            return false;
        }
        close(write_fd);
        setvbuf(stdout, nullptr, _IOLBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        redirecting_ = true;
        std::thread reader([this]() {
            char buffer[4096];
            for (;;) {
                const ssize_t got = read(read_fd_, buffer, sizeof(buffer));
                if (got > 0) {
                    if (consumer_) consumer_(buffer, static_cast<size_t>(got));
                    continue;
                }
                if (got == 0) break;
                if (errno == EINTR) continue;
                break;
            }
            if (read_fd_ > -1) {
                close(read_fd_);
                read_fd_ = -1;
            }
        });
        thread_ = std::move(reader);
        return true;
    }

    int saved_stdout_ = -1;
    int saved_stderr_ = -1;
    int read_fd_ = -1;
    bool redirecting_ = false;
    std::function<void(const char*, size_t)> consumer_;
    std::thread thread_;
};
