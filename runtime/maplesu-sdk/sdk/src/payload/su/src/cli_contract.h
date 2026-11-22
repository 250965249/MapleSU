// su -- command line contract.
//
// Ported from the vendor's open-edition su client
// (``.research/MapleSU/Lite_version/src/testRoot/kernel_root_kit/src/jni/su/su.cpp``
// and ``su.h``): the legacy options and usage, the two legacy
// spelling rewrites (``-cn`` -> ``-z``, ``-mm`` -> ``-M``) and the same
// "--" free-standing login marker. The Ultra build keeps the same surface; the
// version identity below is the vendor's ``ROOT_VER_CODE`` / ``ROOT_VERSION``.
// Group options follow the pinned KernelSU userspace/ksud/src/su.rs contract.
//
// This header is self-contained so the host contract tests compile the same
// parser the device program runs.
//
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <vector>

#include <getopt.h>
#include <sys/types.h>

namespace maplesu::payload::su {

inline constexpr const char* kDefaultShell = "/system/bin/sh";
inline constexpr int kRootVerCode = 1;
inline constexpr const char* kRootVersion = "1.0";
inline constexpr unsigned int kUidRoot = 0;
inline constexpr const char* kUsageHeader = "linux kernel root";

struct SuRequest {
    int uid = static_cast<int>(kUidRoot);
    bool login = false;
    bool keepenv = false;
    bool mount_master = false;
    bool has_gid = false;
    unsigned int gid = 0;
    std::vector<gid_t> groups;
    char shell[512] = {0};
    char command[4096] = {0};
    char context[256] = {0};   // legacy -z/--context value, accepted and ignored
    bool has_command = false;

    SuRequest() { copy_literal(shell, sizeof(shell), kDefaultShell); }

    static void copy_literal(char* target, size_t capacity, const char* text) {
        if (capacity == 0) return;
        const size_t length = std::strlen(text);
        const size_t copied = length < capacity - 1 ? length : capacity - 1;
        std::memcpy(target, text, copied);
        target[copied] = '\0';
    }
};

enum class SuParseKind {
    Run,
    Help,          // -h/--help : print usage to stdout, exit 0
    Version,       // -v/--version : print version text, exit 0
    VersionCode,   // -V : print version code, exit 0
};

struct SuParseResult {
    SuParseKind kind = SuParseKind::Run;
    SuRequest request;
    bool failed = false;
    int first_positional = 0;   // optional user name, or argc
    int first_shell_argument = 0;
};

inline void print_usage(FILE* stream) {
    std::fprintf(stream,
                 "%s\n"
                 "\n"
                 "Usage: su [options] [-] [user [argument...]]\n"
                 "\n"
                 "Options:\n"
                 "  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
                 "  -h, --help                    display this help message and exit\n"
                 "  -, -l, --login                pretend the shell to be a login shell\n"
                 "  -m, -p,\n"
                 "  --preserve-environment        preserve the entire environment\n"
                 "  -s, --shell SHELL             use SHELL instead of the default ",
                 kUsageHeader);
    std::fprintf(stream,
                 "%s\n"
                 "  -v, --version                 display version number and exit\n"
                 "  -V                            display version code and exit\n"
                 "  -g, --group GROUP             specify the primary group\n"
                 "  -G, --supp-group GROUP        specify a supplementary group (repeatable)\n"
                 "  -mm, -M,\n"
                 "  --mount-master                force run in the global mount namespace\n"
                 "\n",
                 kDefaultShell);
}

// Appends the remaining arguments to the command buffer separated by single
// spaces (the reference applet folds its own command tail this way).
inline bool collect_command_tail(SuRequest& request, const char* command,
                                 int argc, char* const* argv, int first) {
    size_t length = std::strlen(command);
    if (length >= sizeof(request.command)) return false;
    std::memcpy(request.command, command, length + 1);
    request.has_command = true;
    for (int index = first; index < argc; ++index) {
        const char* piece = argv[index] != nullptr ? argv[index] : "";
        const size_t piece_length = std::strlen(piece);
        const size_t separator = length != 0 ? 1 : 0;
        if (piece_length >= sizeof(request.command) - length - separator) return false;
        if (length != 0) request.command[length++] = ' ';
        std::memcpy(request.command + length, piece, piece_length);
        length += piece_length;
        request.command[length] = '\0';
        request.has_command = true;
    }
    return true;
}

inline bool parse_gid(const char* text, unsigned int& gid) {
    if (text == nullptr || *text == '\0') return false;
    unsigned int value = 0;
    for (const char* cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
        const unsigned int digit = static_cast<unsigned int>(*cursor - '0');
        if (value > (UINT_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    if (value == UINT_MAX) return false; // setresgid treats (gid_t)-1 as unchanged.
    gid = value;
    return true;
}

// Parses the whole argument vector.  `argv` must be mutable because the vendor
// client rewrites the two legacy spellings in place before getopt runs; the same
// rewrite is reproduced here on the caller's strings.
inline SuParseResult parse_su_args(int argc, char* const* argv) {
    SuParseResult result;
    result.first_positional = argc;
    result.first_shell_argument = argc;

    static const struct option kLongOptions[] = {
        {"command", required_argument, nullptr, 'c'},
        {"help", no_argument, nullptr, 'h'},
        {"login", no_argument, nullptr, 'l'},
        {"preserve-environment", no_argument, nullptr, 'p'},
        {"shell", required_argument, nullptr, 's'},
        {"version", no_argument, nullptr, 'v'},
        {"context", required_argument, nullptr, 'z'},
        {"mount-master", no_argument, nullptr, 'M'},
        {"group", required_argument, nullptr, 'g'},
        {"supp-group", required_argument, nullptr, 'G'},
        {nullptr, 0, nullptr, 0},
    };

    optind = 0;
    optarg = nullptr;
    int option = 0;
    while (true) {
        // Only rewrite an option about to be parsed, never command/argument data.
        const int index = optind == 0 ? 1 : optind;
        if (index < argc && std::strcmp(argv[index], "-cn") == 0) {
            SuRequest::copy_literal(argv[index], 4, "-z");
        } else if (index < argc && std::strcmp(argv[index], "-mm") == 0) {
            SuRequest::copy_literal(argv[index], 4, "-M");
        }
        // RETURN_IN_ORDER keeps the optional user before -c on both libc ABIs.
        option = ::getopt_long(argc, const_cast<char**>(argv), "-c:hlmps:Vvuz:Mg:G:",
                               kLongOptions, nullptr);
        if (option == -1) break;
        switch (option) {
            case 1:
                if (result.first_positional == argc) {
                    if (std::strcmp(optarg, "-") == 0) result.request.login = true;
                    else result.first_positional = optind - 1;
                    break;
                }
                result.first_shell_argument = optind - 1;
                return result;
            case 'c':
                if (!collect_command_tail(result.request, optarg, argc, argv, optind)) {
                    std::fprintf(stderr, "su: command is too long\n");
                    result.failed = true;
                }
                return result;
            case 'h':
                result.kind = SuParseKind::Help;
                return result;
            case 'l':
                result.request.login = true;
                break;
            case 'm':
            case 'p':
                result.request.keepenv = true;
                break;
            case 's':
                if (optarg == nullptr || optarg[0] == '\0' ||
                    std::strlen(optarg) >= sizeof(result.request.shell)) {
                    std::fprintf(stderr, "su: invalid shell path\n");
                    result.failed = true;
                    return result;
                }
                SuRequest::copy_literal(result.request.shell, sizeof(result.request.shell),
                                        optarg != nullptr ? optarg : "");
                break;
            case 'V':
                result.kind = SuParseKind::VersionCode;
                return result;
            case 'v':
                result.kind = SuParseKind::Version;
                return result;
            case 'z':
                if (optarg == nullptr || std::strlen(optarg) >= sizeof(result.request.context)) {
                    std::fprintf(stderr, "su: context is too long\n");
                    result.failed = true;
                    return result;
                }
                SuRequest::copy_literal(result.request.context,
                                        sizeof(result.request.context),
                                        optarg != nullptr ? optarg : "");
                break;
            case 'M':
                result.request.mount_master = true;
                break;
            case 'g':
                if (!parse_gid(optarg, result.request.gid)) {
                    std::fprintf(stderr, "su: invalid primary group\n");
                    result.failed = true;
                    return result;
                }
                result.request.has_gid = true;
                break;
            case 'G': {
                unsigned int group = 0;
                if (!parse_gid(optarg, group)) {
                    std::fprintf(stderr, "su: invalid supplementary group\n");
                    result.failed = true;
                    return result;
                }
                result.request.groups.push_back(group);
                break;
            }
            default:
                // Bionic getopt_long does not terminate its diagnostic with a
                // newline; the reference client adds one before showing usage.
                std::fprintf(stderr, "\n");
                print_usage(stderr);
                result.failed = true;
                return result;
        }
    }

    if (optind < argc && std::strcmp(argv[optind], "-") == 0) {
        result.request.login = true;
        ++optind;
    }
    if (optind < argc && result.first_positional == argc) result.first_positional = optind++;
    result.first_shell_argument = optind;
    return result;
}

}  // namespace maplesu::payload::su
