// cred implementation.
//
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/prctl.h>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_caps_private.h"
#include "maplesu_kernel_layout_private.h"

// a single tail call to
//   _ZN15default_modules11module_root16set_current_capsERKN13kernel_module9caps_infoE ).
// It is defined by another archive member, so declare it only.
namespace default_modules {
namespace module_root {

KModErr set_current_caps(const kernel_module::caps_info& new_caps);

}  // namespace module_root
}  // namespace default_modules

namespace kernel_module {

KModErr get_cred_uid_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr error = maplesu_resolve_btf_field("cred", "uid", 4, field, available);
    if (available) {
        if (is_ok(error)) offset = field.offset_bytes;
        return error;
    }
    error = maplesu_resolve_accessor_field("cred", "uid", 4, field);
    if (is_ok(error)) offset = field.offset_bytes;
    return error;
}

//
// Both BTF and the target getter resolve euid independently.
KModErr get_cred_euid_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr error = maplesu_resolve_btf_field("cred", "euid", 4, field, available);
    if (available) {
        if (is_ok(error)) offset = field.offset_bytes;
        return error;
    }
    error = maplesu_resolve_accessor_field("cred", "euid", 4, field);
    if (is_ok(error)) offset = field.offset_bytes;
    return error;
}

// Resolve this field independently from BTF or cap_capget's output data flow.
KModErr get_cred_cap_inheritable_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr error = maplesu_resolve_btf_field("cred", "cap_inheritable", 8, field, available);
    if (available) {
        if (is_ok(error)) offset = field.offset_bytes;
        return error;
    }
    error = maplesu_resolve_accessor_field("cred", "cap_inheritable", 8, field);
    if (is_ok(error)) offset = field.offset_bytes;
    return error;
}

//
// Match native module: only -1/EINVAL continues the search. Other results select this cap.
// Its AArch64 variable shift masks the count to six bits, including cap 63.
uint64_t get_cap_ability_max() {
    for (int32_t cap = 63; cap >= 0; --cap) {
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) >= 0 || errno != EINVAL) {
            const auto shift = static_cast<uint32_t>(cap + 1) & 63u;
            return (uint64_t(1) << shift) - 1;
        }
    }
    return 0;
}

//
int get_caps_cnt() {
    std::ifstream status_file("/proc/thread-self/status", std::ios::in);
    if (!status_file.is_open()) {
        return 0;
    }

    std::string line;
    int caps_cnt = 0;
    while (std::getline(status_file, line)) {
        if (line.rfind("CapInh:", 0) == 0 ||
            line.rfind("CapPrm:", 0) == 0 ||
            line.rfind("CapEff:", 0) == 0 ||
            line.rfind("CapBnd:", 0) == 0 ||
            line.rfind("CapAmb:", 0) == 0) {
            ++caps_cnt;
        }
    }
    return caps_cnt;
}

// Read one status snapshot and publish only complete capability sets.
// Ambient remains optional for kernels exposing the original four sets.
KModErr get_current_caps_snapshot(caps_info& out, bool& ambient_present) {
    memset(&out, 0, sizeof(out));
    ambient_present = false;

    FILE* status_file = fopen("/proc/thread-self/status", "r");
    if (status_file == nullptr) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    caps_info parsed{};
    unsigned matched = 0;
    bool invalid = false;
    char line[256];
    while (fgets(line, static_cast<int>(sizeof(line)), status_file) != nullptr) {
        char cap_key[32] = {0};
        char cap_value[65] = {0};
        char extra = 0;
        const int tokens = sscanf(line, "%31s %64s %c", cap_key, cap_value, &extra);
        uint64_t* target = nullptr;
        unsigned bit = 0;
        if (strcmp(cap_key, "CapInh:") == 0) {
            target = &parsed.inheritable; bit = 1;
        } else if (strcmp(cap_key, "CapPrm:") == 0) {
            target = &parsed.permitted; bit = 2;
        } else if (strcmp(cap_key, "CapEff:") == 0) {
            target = &parsed.effective; bit = 4;
        } else if (strcmp(cap_key, "CapBnd:") == 0) {
            target = &parsed.bounding; bit = 8;
        } else if (strcmp(cap_key, "CapAmb:") == 0) {
            target = &parsed.ambient; bit = 16;
        } else {
            if (strlen(line) == sizeof(line) - 1 && line[sizeof(line) - 2] != '\n') {
                int next;
                do { next = fgetc(status_file); } while (next != EOF && next != '\n');
            }
            continue;
        }
        const size_t length = strlen(cap_value);
        if (tokens != 2 || (matched & bit) != 0 || length == 0 || length > 16 ||
                strspn(cap_value, "0123456789abcdefABCDEF") != length ||
                (strlen(line) == sizeof(line) - 1 && line[sizeof(line) - 2] != '\n')) {
            invalid = true;
            break;
        }
        errno = 0;
        char* parse_end = nullptr;
        const unsigned long long value = strtoull(cap_value, &parse_end, 16);
        if (errno != 0 || *parse_end != '\0') {
            invalid = true;
            break;
        }
        *target = value;
        matched |= bit;
    }

    const bool read_error = ferror(status_file) != 0;
    fclose(status_file);
    if (read_error) return KModErr::ERR_MODULE_READ_FILE;
    if (invalid || (matched & 15) != 15) return KModErr::ERR_MODULE_GET_CAPS;
    out = parsed;
    ambient_present = (matched & 16) != 0;
    return KModErr::OK;
}

KModErr get_current_caps(caps_info& out) {
    bool ambient_present = false;
    return get_current_caps_snapshot(out, ambient_present);
}

//
// One tail call into the private module_root layer; the real work lives in
// that member (default_modules::module_root::set_current_caps).
KModErr set_current_caps(const caps_info& new_caps) {
    return default_modules::module_root::set_current_caps(new_caps);
}

}  // namespace kernel_module

// sizeof(caps_info) is ABI: get_current_caps() memsets exactly 40 bytes
static_assert(sizeof(kernel_module::caps_info) == 5 * sizeof(uint64_t),
              "caps_info is five 64-bit capability sets");
static_assert(offsetof(kernel_module::caps_info, permitted) == 8,
              "caps_info field order: inheritable, permitted, effective, bounding, ambient");
