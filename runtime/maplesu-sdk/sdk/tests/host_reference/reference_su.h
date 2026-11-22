// Reference model: the vendor's open-edition su client CLI.
//
// This is the parsing/usage section of
// ``.research/SKRoot/Lite_version/src/testRoot/kernel_root_kit/src/jni/su/su.cpp``
// kept in its original shape, with two mechanical changes so it can run inside a
// host test:
//
//   * ``usage()`` returns its text instead of printing to a stream and exiting,
//   * ``exit()``-based outcomes are returned as a kind.
//
// Everything else (option table, getopt string, ``-cn``/``-mm`` rewrites, ``-c``
// folding loop, ``-`` login handling) is the reference code verbatim, so the
// differential test compares our port against the reference implementation
// rather than against a hand-written expectation table.
//
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <getopt.h>
#include <unistd.h>

namespace reference {

inline constexpr const char* kDefaultShell = "/system/bin/sh";
inline constexpr int kRootVerCode = 1;
inline constexpr const char* kRootVersion = "1.0";

struct SuRequest {
    int uid = 0;
    bool login = false;
    bool keepenv = false;
    bool mount_master = false;
    std::string shell = kDefaultShell;
    std::string command;
    std::string context;
};

enum class SuKind { Run, Help, Version, VersionCode, Error };

struct SuOutcome {
    SuKind kind = SuKind::Run;
    SuRequest request;
    int first_positional = 0;
    std::string usage;
};

inline std::string usage_text() {
    std::string text;
    text += "linux kernel root\n\n";
    text += "Usage: su [options] [-] [user [argument...]]\n\n";
    text += "Options:\n";
    text += "  -c, --command COMMAND         pass COMMAND to the invoked shell\n";
    text += "  -h, --help                    display this help message and exit\n";
    text += "  -, -l, --login                pretend the shell to be a login shell\n";
    text += "  -m, -p,\n";
    text += "  --preserve-environment        preserve the entire environment\n";
    text += "  -s, --shell SHELL             use SHELL instead of the default ";
    text += kDefaultShell;
    text += "\n";
    text += "  -v, --version                 display version number and exit\n";
    text += "  -V                            display version code and exit\n";
    text += "  -mm, -M,\n";
    text += "  --mount-master                force run in the global mount namespace\n\n";
    return text;
}

inline SuOutcome parse(int argc, char* const* argv) {
    SuOutcome outcome;
    outcome.usage = usage_text();

    for (int i = 0; i < argc; i++) {
        if (std::strcmp(argv[i], "-cn") == 0) {
            std::strcpy(const_cast<char*>(argv[i]), "-z");
        } else if (std::strcmp(argv[i], "-mm") == 0) {
            std::strcpy(const_cast<char*>(argv[i]), "-M");
        }
    }

    static const struct option long_opts[] = {
        {"command", required_argument, nullptr, 'c'},
        {"help", no_argument, nullptr, 'h'},
        {"login", no_argument, nullptr, 'l'},
        {"preserve-environment", no_argument, nullptr, 'p'},
        {"shell", required_argument, nullptr, 's'},
        {"version", no_argument, nullptr, 'v'},
        {"context", required_argument, nullptr, 'z'},
        {"mount-master", no_argument, nullptr, 'M'},
        {nullptr, 0, nullptr, 0},
    };

    optind = 0;
    optarg = nullptr;
    int option = 0;
    while ((option = ::getopt_long(argc, const_cast<char**>(argv), "c:hlmps:Vvuz:M",
                                   long_opts, nullptr)) != -1) {
        switch (option) {
            case 'c':
                for (int i = optind - 1; i < argc; ++i) {
                    if (!outcome.request.command.empty()) {
                        outcome.request.command += ' ';
                    }
                    outcome.request.command += argv[i];
                }
                optind = argc;
                break;
            case 'h':
                outcome.kind = SuKind::Help;
                return outcome;
            case 'l':
                outcome.request.login = true;
                break;
            case 'm':
            case 'p':
                outcome.request.keepenv = true;
                break;
            case 's':
                outcome.request.shell = optarg != nullptr ? optarg : "";
                break;
            case 'V':
                outcome.kind = SuKind::VersionCode;
                return outcome;
            case 'v':
                outcome.kind = SuKind::Version;
                return outcome;
            case 'z':
                outcome.request.context = optarg != nullptr ? optarg : "";
                break;
            case 'M':
                outcome.request.mount_master = true;
                break;
            default:
                outcome.kind = SuKind::Error;
                return outcome;
        }
    }

    if (optind < argc && std::strcmp(argv[optind], "-") == 0) {
        outcome.request.login = true;
        optind++;
    }
    outcome.first_positional = optind;
    return outcome;
}

}  // namespace reference
