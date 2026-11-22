// resetprop -- command line contract.
//
// Ported from the resetprop applet of Magisk v30.7
// (``native/src/core/resetprop/cli.rs``, ``ResetProp``/``resetprop_main``):
// the same switches, the same operation modes, the same mutual-exclusion checks
// and the same early-exit behaviour (help text goes to stderr and exits 0;
// usage errors print their reason, then the help text, and exit 1).
//
// This header is self-contained so the host contract tests compile the very same
// parser the device program runs.
//
#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace maplesu::payload::resetprop {

struct CliOptions {
    bool verbose = false;        // -v : verbose diagnostics (release builds stay quiet)
    bool wait_mode = false;      // -w : wait until a property changes
    bool persist = false;        // -p : include / always write persistent storage
    bool persist_only = false;   // -P : read persistent storage only
    bool context = false;        // -Z : print/read the SELinux context
    bool skip_svc = false;       // -n : bypass property_service
    bool has_file = false;       // -f/--file FILE : load NAME=VALUE lines
    std::string file;
    bool has_delete = false;     // -d/--delete NAME : delete a property
    std::string delete_key;
    std::vector<std::string> args;   // greedy positional arguments
};

enum class ParseKind {
    Run,      // command is valid
    Help,     // -h/--help : caller prints usage and exits 0
    Error,    // usage/validation error : caller prints message + usage and exits 1
};

struct ParseResult {
    ParseKind kind = ParseKind::Run;
    CliOptions options;
    std::string message;   // human-readable reason for ParseKind::Error
};

// The exact help text of the resetprop applet; ``program`` is argv[0].
inline std::string usage_text(const std::string& program) {
    return "resetprop - System Property Manipulation Tool\n"
           "\n"
           "Usage: " + program + " [flags] [arguments...]\n"
           "\n"
           "Read mode arguments:\n"
           "   (no arguments)    print all properties\n"
           "   NAME              get property of NAME\n"
           "\n"
           "Write mode arguments:\n"
           "   NAME VALUE        set property NAME as VALUE\n"
           "   -f,--file   FILE  load and set properties from FILE\n"
           "   -d,--delete NAME  delete property\n"
           "\n"
           "Wait mode arguments (toggled with -w):\n"
           "    NAME             wait until property NAME changes\n"
           "    NAME OLD_VALUE   if value of property NAME is not OLD_VALUE, get value\n"
           "                     or else wait until property NAME changes\n"
           "\n"
           "General flags:\n"
           "   -h,--help         show this message\n"
           "   -v,--verbose      print verbose output to stderr\n"
           "   -w                switch to wait mode\n"
           "\n"
           "Read mode flags:\n"
           "   -p      also read persistent properties from storage\n"
           "   -P      only read persistent properties from storage\n"
           "   -Z      get property context instead of value\n"
           "\n"
           "Write mode flags:\n"
           "   -n      set properties bypassing property_service\n"
           "   -p      always write persistent prop changes to storage\n";
}

namespace detail {

inline bool starts_with(const std::string& text, const char* prefix) {
    const size_t length = std::strlen(prefix);
    return text.size() >= length && text.compare(0, length, prefix) == 0;
}

// Long option names of the applet.  Every other switch is short-only, matching
// the Rust definition (``long = none`` for -w/-p/-P/-Z/-n and -v).
inline bool take_long_option(const std::string& arg, CliOptions& out, ParseResult& result) {
    if (arg == "--help") {
        result.kind = ParseKind::Help;
        return true;
    }
    if (arg == "--verbose") {          // accepted alias, never advertised
        out.verbose = true;
        return true;
    }
    std::string name = arg;
    std::string value;
    bool has_value = false;
    const size_t equals = arg.find('=');
    if (equals != std::string::npos) {
        name = arg.substr(0, equals);
        value = arg.substr(equals + 1);
        has_value = true;
    }
    if (name == "--file" || name == "--delete") {
        if (!has_value) {
            result.kind = ParseKind::Error;
            result.message = "No value provided for option '" + name + "'";
            return true;
        }
        if (name == "--file") {
            out.has_file = true;
            out.file = value;
        } else {
            out.has_delete = true;
            out.delete_key = value;
        }
        return true;
    }
    return false;
}

}  // namespace detail

// Parses argv[1..argc).  Faithful to the applet's argh definition with the
// validation resetprop_main performs after parsing.
inline ParseResult parse_cli(int argc, const char* const* argv) {
    ParseResult result;
    CliOptions& options = result.options;
    bool options_ended = false;
    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index] != nullptr ? argv[index] : "";
        if (options_ended || arg.empty() || arg == "-" || arg[0] != '-') {
            options.args.push_back(arg);
            continue;
        }
        if (arg == "--") {
            options_ended = true;
            continue;
        }
        if (detail::starts_with(arg, "--")) {
            if (!detail::take_long_option(arg, options, result)) {
                result.kind = ParseKind::Error;
                result.message = "Unrecognized argument: " + arg;
                return result;
            }
            if (result.kind != ParseKind::Run) return result;
            continue;
        }
        // Short switch cluster: -v -w -p -P -Z -n may be combined; -f/-d take
        // the rest of the cluster or the next argument as their value.
        for (size_t position = 1; position < arg.size(); ++position) {
            const char flag = arg[position];
            switch (flag) {
                case 'v': options.verbose = true; break;
                case 'w': options.wait_mode = true; break;
                case 'p': options.persist = true; break;
                case 'P': options.persist_only = true; break;
                case 'Z': options.context = true; break;
                case 'n': options.skip_svc = true; break;
                case 'h':
                    result.kind = ParseKind::Help;
                    return result;
                case 'f':
                case 'd': {
                    std::string value;
                    if (position + 1 < arg.size()) {
                        value = arg.substr(position + 1);
                        position = arg.size();
                    } else if (index + 1 < argc) {
                        value = argv[++index] != nullptr ? argv[index] : "";
                    } else {
                        result.kind = ParseKind::Error;
                        result.message = std::string("option '-") + flag +
                                         "' requires a value";
                        return result;
                    }
                    if (flag == 'f') {
                        options.has_file = true;
                        options.file = value;
                    } else {
                        options.has_delete = true;
                        options.delete_key = value;
                    }
                    break;
                }
                default:
                    result.kind = ParseKind::Error;
                    result.message = std::string("Unrecognized argument: -") + flag;
                    return result;
            }
        }
    }

    // Validation rules of resetprop_main, in the same order.
    if (options.wait_mode && options.args.empty()) {
        result.kind = ParseKind::Error;
        result.message = "Required positional argument NAME is missing";
        return result;
    }
    int special_modes = 0;
    if (options.wait_mode) ++special_modes;
    if (options.has_file) ++special_modes;
    if (options.has_delete) ++special_modes;
    if (special_modes > 1) {
        result.kind = ParseKind::Error;
        result.message = "Multiple operation mode detected!";
        return result;
    }
    if (options.args.size() > 2) {
        result.kind = ParseKind::Error;
        result.message = "Unrecognized argument: " + options.args[2];
        return result;
    }
    return result;
}

}  // namespace maplesu::payload::resetprop
