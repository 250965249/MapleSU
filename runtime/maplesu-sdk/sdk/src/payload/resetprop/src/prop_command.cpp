// resetprop -- property manipulation implementation.
//
#include "prop_command.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <sys/types.h>
#include <unistd.h>

#include "payload_support.h"

namespace maplesu::payload::resetprop {
namespace {

const char* kPersistPrefix = "persist.";
const char* kReadOnlyPrefix = "ro.";

}  // namespace

ResetProp::ResetProp(CliOptions options, PropertyBackend* backend)
    : options_(std::move(options)),
      backend_(backend != nullptr ? backend : &android_property_backend()) {}

bool ResetProp::get(const std::string& key, std::string& value) const {
    PropertyBackend& api = *backend_;
    if (options_.context) {
        const char* context = api.context(key.c_str());
        if (context == nullptr) return false;
        value = context;
        return true;
    }

    bool found = false;
    if (!options_.persist_only) {
        const PropInfo* info = api.find(key.c_str());
        if (info != nullptr) {
            std::string record_key;
            uint32_t serial = 0;
            found = api.read(info, record_key, value, serial);
        }
    }
    if (!found && (options_.persist || options_.persist_only) &&
        key.rfind(kPersistPrefix, 0) == 0) {
        found = api.persist_get(key, value);
    }
    return found;
}

void ResetProp::print_all() const {
    PropertyBackend& api = *backend_;
    std::map<std::string, std::string> values;
    // The area walk hands out records; the backend read supplies key + value.
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

    if (options_.persist || options_.persist_only) {
        std::vector<PersistentRecord> records;
        if (api.persist_all(records)) {
            for (const auto& record : records) {
                if (record.has_name && record.has_value) values[record.name] = record.value;
            }
        }
    }
    for (const auto& entry : values) {
        if (options_.context) {
            const char* context = api.context(entry.first.c_str());
            out_printf("[%s]: [%s]\n", entry.first.c_str(),
                       context != nullptr ? context : "");
        } else {
            out_printf("[%s]: [%s]\n", entry.first.c_str(), entry.second.c_str());
        }
    }
}

void ResetProp::set(const std::string& key, const std::string& value) const {
    PropertyBackend& api = *backend_;
    bool skip_service = options_.skip_svc;
    PropInfo* info = api.find_mutable(key.c_str());

    if (key.rfind(kReadOnlyPrefix, 0) == 0) {
        skip_service = true;
        if (info != nullptr &&
            (api.is_long(info) || value.size() >= kPropValueMax)) {
            // A long read-only property cannot be updated in place: drop the
            // record first (without pruning) and recreate it below.
            api.remove(key.c_str(), false);
            info = nullptr;
        }
    }

    if (info != nullptr) {
        if (skip_service) {
            api.update(info, value.c_str(), value.size());
        } else {
            api.set(key.c_str(), value.c_str());
        }
    } else {
        if (skip_service) {
            api.add(key.c_str(), value.c_str(), value.size());
        } else {
            api.set(key.c_str(), value.c_str());
        }
    }

    if (skip_service && options_.persist &&
        key.rfind(kPersistPrefix, 0) == 0) {
        api.persist_set(key, value);
    }
}

bool ResetProp::erase(const std::string& key) const {
    PropertyBackend& api = *backend_;
    bool removed = api.remove(key.c_str(), true);
    if (options_.persist && key.rfind(kPersistPrefix, 0) == 0) {
        // The reference folds both results with |=, so the persistent erase is
        // evaluated even when the area delete already succeeded.
        const bool persisted = api.persist_erase(key);
        removed = removed || persisted;
    }
    return removed;
}

void ResetProp::wait() const {
    PropertyBackend& api = *backend_;
    const std::string key = options_.args[0];
    const bool compare = options_.args.size() >= 2;
    const std::string expected = compare ? options_.args[1] : std::string();

    const PropInfo* info = nullptr;
    while (info == nullptr) {
        info = api.find(key.c_str());
        if (info != nullptr) break;
        uint32_t serial = api.area_serial();
        uint32_t observed = serial;
        if (!api.wait_for_change(nullptr, serial, observed)) {
            // Platform without the wait primitive: poll instead of spinning.
            ::usleep(10 * 1000);
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
        if (!api.wait_for_change(info, serial, observed)) {
            ::usleep(10 * 1000);
        }
    }
}

bool ResetProp::load_file(const std::string& path) const {
    FILE* file = ::fopen(path.c_str(), "r");
    if (file == nullptr) {
        err_printf("resetprop: %s\n", std::strerror(errno));
        return false;
    }
    bool ok = true;
    std::string line;
    while (read_line(file, line)) {
        const PropLine parsed = parse_prop_line(line);
        if (parsed.valid) set(parsed.key, parsed.value);
    }
    std::fclose(file);
    return ok;
}

bool ResetProp::run() {
    if (options_.wait_mode) {
        wait();
        return true;
    }
    if (options_.has_file) return load_file(options_.file);
    if (options_.has_delete) return erase(options_.delete_key);

    switch (options_.args.size()) {
        case 0:
            print_all();
            return true;
        case 1: {
            std::string value;
            if (!get(options_.args[0], value)) return false;
            out_printf("%s\n", value.c_str());
            return true;
        }
        case 2:
            set(options_.args[0], options_.args[1]);
            return true;
        default:
            return false;
    }
}

}  // namespace maplesu::payload::resetprop
