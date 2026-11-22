// Shared support helpers for the embedded payload programs.
//
// The payload programs are ordinary Android userland executables that the SDK
// installs next to the kernel module kit.  They share nothing but plain C/C++
// behaviour: an optional debug trace, integer parsing that matches the shell
// conventions the CLI contracts use, and a small file helper.  Keeping these
// three in one header keeps each program tree compilable on its own.
//
#pragma once

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// The POSIX close-on-exec flag is not part of every host build used by the
// contract tests; the payload programs are Android-only, this only keeps the
// shared header compilable on the test host.
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

namespace maplesu::payload {

// --------------------------------------------------------------------------
// logging
// --------------------------------------------------------------------------
// Payload programs talk to the SDK helper through their standard streams: a
// human-readable trace goes to stdout, hard errors to stderr.  `verbose` is the
// state the CLIs toggle with -v; release builds compile the debug trace out,
// exactly like the shipped images (the release logger has no debug sink).
inline bool& verbose_state() {
    static bool verbose = false;
    return verbose;
}

inline void set_verbose(bool value) { verbose_state() = value; }

inline void out_printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    std::vprintf(format, args);
    va_end(args);
}

inline void err_printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
}

#if defined(NDEBUG)
inline void debug_printf(const char*, ...) {}
#else
inline void debug_printf(const char* format, ...) {
    if (!verbose_state()) return;
    va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
}
#endif

// --------------------------------------------------------------------------
// integer parsing (decimal, base 10, no sign, full-string match)
// --------------------------------------------------------------------------
inline bool parse_decimal(const char* text, long long& out) {
    if (text == nullptr || *text == '\0') return false;
    long long value = 0;
    for (const char* p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
        value = value * 10 + (*p - '0');
        if (value > 0x7fffffffLL) return false;
    }
    out = value;
    return true;
}

inline int parse_decimal_or(const char* text, int fallback) {
    long long value = 0;
    if (!parse_decimal(text, value)) return fallback;
    return static_cast<int>(value);
}

// --------------------------------------------------------------------------
// file helpers
// --------------------------------------------------------------------------
inline bool read_file(const std::string& path, std::string& out) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    char buffer[8192];
    while (true) {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        if (n == 0) break;
        out.append(buffer, static_cast<size_t>(n));
    }
    ::close(fd);
    return true;
}

inline bool file_exists(const std::string& path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
}

inline bool is_directory(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

// Reads one line (including its trailing newline) like POSIX getline(3); returns
// false at end of file.  Lines of arbitrary length are supported.
inline bool read_line(std::FILE* file, std::string& line) {
    line.clear();
    bool got_anything = false;
    while (true) {
        const int c = std::fgetc(file);
        if (c == EOF) return got_anything;
        got_anything = true;
        line.push_back(static_cast<char>(c));
        if (c == '\n') return true;
    }
}

inline bool write_all(int fd, const char* data, size_t size) {
    while (size > 0) {
        const ssize_t n = ::write(fd, data, size);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += n;
        size -= static_cast<size_t>(n);
    }
    return true;
}

}  // namespace maplesu::payload
