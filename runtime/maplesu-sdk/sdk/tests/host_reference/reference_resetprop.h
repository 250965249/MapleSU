// Reference model: the resetprop applet semantics.
//
// This is the operation logic of Magisk v30.7
// ``native/src/core/resetprop/cli.rs`` (``ResetProp::run`` and its helpers)
// transcribed into C++ that talks to the same ``PropertyBackend`` boundary the
// production port uses.  It exists so the host differential test can run both
// implementations on the same argument vector and the same simulated property
// state and compare the operation trace, the printed output and the resulting
// state -- rather than comparing against a hand-written expectation table.
//
#pragma once

#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "payload_support.h"
#include "resetprop/src/cli_contract.h"
#include "resetprop/src/prop_backend.h"

namespace reference_resetprop {

using maplesu::payload::resetprop::CliOptions;
using maplesu::payload::resetprop::PropForeachCallback;
using maplesu::payload::resetprop::PropInfo;
using maplesu::payload::resetprop::PropertyBackend;

inline bool starts_with(const std::string& text, const char* prefix) {
    const size_t length = std::strlen(prefix);
    return text.size() >= length && text.compare(0, length, prefix) == 0;
}

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

inline bool get_value(PropertyBackend& api, const std::string& key, std::string& value,
                      FILE* out) {
    (void)out;
    const PropInfo* info = api.find(key.c_str());
    if (info == nullptr) return false;
    std::string record_key;
    uint32_t serial = 0;
    return api.read(info, record_key, value, serial);
}

inline void print_all(const CliOptions& options, PropertyBackend& api, FILE* out) {
    std::map<std::string, std::string> values;
    struct Cookie {
        PropertyBackend* backend;
        std::map<std::string, std::string>* values;
    } cookie{&api, &values};
    api.for_each(
        [](const PropInfo* info, void* raw) {
            auto* state = static_cast<Cookie*>(raw);
            std::string key;
            std::string value;
            uint32_t serial = 0;
            if (state->backend->read(info, key, value, serial)) {
                (*state->values)[key] = value;
            }
        },
        &cookie);
    if (options.persist || options.persist_only) {
        std::vector<maplesu::payload::resetprop::PersistentRecord> records;
        if (api.persist_all(records)) {
            for (const auto& record : records) {
                if (record.has_name && record.has_value) {
                    values[record.name] = record.value;
                }
            }
        }
    }
    for (const auto& entry : values) {
        if (options.context) {
            const char* context = api.context(entry.first.c_str());
            std::fprintf(out, "[%s]: [%s]\n", entry.first.c_str(),
                         context != nullptr ? context : "");
        } else {
            std::fprintf(out, "[%s]: [%s]\n", entry.first.c_str(), entry.second.c_str());
        }
    }
}

inline void set_prop(const CliOptions& options, PropertyBackend& api,
                     const std::string& key, const std::string& value) {
    bool skip_svc = options.skip_svc;
    PropInfo* info = api.find_mutable(key.c_str());

    if (starts_with(key, "ro.")) {
        skip_svc = true;
        if (info != nullptr &&
            (api.is_long(info) || value.size() >= 92)) {
            api.remove(key.c_str(), false);
            info = nullptr;
        }
    }

    if (info != nullptr) {
        if (skip_svc) {
            api.update(info, value.c_str(), value.size());
        } else {
            api.set(key.c_str(), value.c_str());
        }
    } else {
        if (skip_svc) {
            api.add(key.c_str(), value.c_str(), value.size());
        } else {
            api.set(key.c_str(), value.c_str());
        }
    }

    if (skip_svc && options.persist && starts_with(key, "persist.")) {
        api.persist_set(key, value);
    }
}

inline bool delete_prop(const CliOptions& options, PropertyBackend& api,
                        const std::string& key) {
    bool removed = false;
    removed = api.remove(key.c_str(), true) || removed;
    if (options.persist && starts_with(key, "persist.")) {
        const bool persisted = api.persist_erase(key);
        removed = removed || persisted;
    }
    return removed;
}

inline void wait_prop(const CliOptions& options, PropertyBackend& api) {
    const std::string key = options.args[0];
    const bool compare = options.args.size() >= 2;
    const std::string expected = compare ? options.args[1] : std::string();

    const PropInfo* info = nullptr;
    while (info == nullptr) {
        info = api.find(key.c_str());
        if (info != nullptr) break;
        uint32_t serial = api.area_serial();
        uint32_t observed = serial;
        if (!api.wait_for_change(nullptr, serial, observed)) {
            return;   // the reference blocks here; a host model must not spin
        }
    }
    if (!compare) return;
    std::string current;
    uint32_t serial = 0;
    while (true) {
        std::string record_key;
        if (!api.read(info, record_key, current, serial)) return;
        if (current != expected) return;
        uint32_t observed = serial;
        if (!api.wait_for_change(info, serial, observed)) return;
    }
}

inline bool load_file(const CliOptions& options, PropertyBackend& api,
                      const std::string& path) {
    std::FILE* file = std::fopen(path.c_str(), "r");
    if (file == nullptr) return false;
    std::string text;
    while (maplesu::payload::read_line(file, text)) {
        // base/files.rs: trim -> skip '#' -> split once at '=' -> trim parts.
        while (!text.empty()) {
            const char first = text.front();
            if (first != ' ' && first != '\t' && first != '\n' && first != '\r' &&
                first != '\v' && first != '\f') break;
            text.erase(text.begin());
        }
        while (!text.empty()) {
            const char last = text.back();
            if (last != ' ' && last != '\t' && last != '\n' && last != '\r' &&
                last != '\v' && last != '\f') break;
            text.pop_back();
        }
        if (text.empty() || text.front() == '#') continue;
        const size_t separator = text.find('=');
        if (separator == std::string::npos) continue;
        std::string key = text.substr(0, separator);
        std::string value = text.substr(separator + 1);
        auto trim = [](std::string& part) {
            while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) {
                part.erase(part.begin());
            }
            while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) {
                part.pop_back();
            }
        };
        trim(key);
        trim(value);
        set_prop(options, api, key, value);
    }
    std::fclose(file);
    return true;
}

// Reference ``ResetProp::run``: returns the applet's success flag.
inline bool run(const CliOptions& options, PropertyBackend& api, FILE* out) {
    if (options.wait_mode) {
        wait_prop(options, api);
        return true;
    }
    if (options.has_file) return load_file(options, api, options.file);
    if (options.has_delete) return delete_prop(options, api, options.delete_key);

    switch (options.args.size()) {
        case 0:
            print_all(options, api, out);
            return true;
        case 1: {
            if (options.context) {
                const char* context = api.context(options.args[0].c_str());
                if (context == nullptr) return false;
                std::fprintf(out, "%s\n", context);
                return true;
            }
            std::string value;
            bool found = false;
            if (!options.persist_only) found = get_value(api, options.args[0], value, out);
            if (!found && (options.persist || options.persist_only) &&
                starts_with(options.args[0], "persist.")) {
                found = api.persist_get(options.args[0], value);
            }
            if (!found) return false;
            std::fprintf(out, "%s\n", value.c_str());
            return true;
        }
        case 2:
            set_prop(options, api, options.args[0], options.args[1]);
            return true;
        default:
            return false;
    }
}

}  // namespace reference_resetprop
