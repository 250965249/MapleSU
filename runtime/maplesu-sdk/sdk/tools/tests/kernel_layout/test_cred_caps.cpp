// Exercise the real cred.cpp capability getters; only kernel I/O and prctl are seams.
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/prctl.h>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_caps_private.h"
#include "maplesu_kernel_layout_private.h"

namespace {
constexpr uint64_t kCap40Mask = (uint64_t{1} << 41) - 1;
unsigned reads = 0, lookups = 0, prctls = 0, accessor_calls = 0;
int last_cap = 40, forced_errno = 0;
bool btf_available = false;
KModErr btf_error = KModErr::OK;
uint32_t btf_offset = 48;
KModErr accessor_error = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
uint32_t accessor_offset = 56;
bool status_active = false, status_open_error = false, status_read_error = false;
std::string status_text;
FILE* status_stream = nullptr;
unsigned status_opens = 0, status_closes = 0;

}

extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" int __real_ferror(FILE*);
extern "C" int __real_fclose(FILE*);

extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
    if (!status_active || strcmp(path, "/proc/self/status") != 0)
        return __real_fopen(path, mode);
    ++status_opens;
    if (status_open_error) { errno = EACCES; return nullptr; }
    status_stream = tmpfile();
    if (status_stream) {
        fwrite(status_text.data(), 1, status_text.size(), status_stream);
        rewind(status_stream);
    }
    return status_stream;
}

extern "C" int __wrap_ferror(FILE* stream) {
    return stream == status_stream && status_read_error ? 1 : __real_ferror(stream);
}

extern "C" int __wrap_fclose(FILE* stream) {
    if (stream == status_stream) { ++status_closes; status_stream = nullptr; }
    return __real_fclose(stream);
}

extern "C" int __wrap_prctl(int option, ...) {
    ++prctls;
    va_list args;
    va_start(args, option);
    const int cap = va_arg(args, int);
    va_end(args);
    if (option != PR_CAPBSET_READ) return -1;
    if (forced_errno != 0) {
        errno = forced_errno;
        return -1;
    }
    if (cap > last_cap) {
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    return 1;
}

namespace kernel_module {
KModErr maplesu_resolve_btf_field(const char*, const char*, uint32_t,
        KernelFieldDescription& field, bool& available) {
    available = btf_available;
    field.offset_bytes = btf_offset;
    return btf_error;
}

KModErr maplesu_resolve_accessor_field(const char* owner, const char* member, uint32_t width,
        KernelFieldDescription& field) {
    ++accessor_calls;
    if (strcmp(owner, "cred") || strcmp(member, "cap_inheritable") || width != 8)
        return KModErr::ERR_MODULE_PARAM;
    // Even a provider that changes its output on error must not publish it
    // through the public getter.
    field.offset_bytes = accessor_offset;
    return accessor_error;
}

KModErr kallsyms_lookup_name(const char*, uint64_t&) {
    ++lookups;
    return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
}

KModErr read_kernel_mem(uint64_t, void*, uint32_t) {
    ++reads;
    return KModErr::ERR_MODULE_READ_FILE;
}
}

namespace {
int snapshot_cases() {
    const std::string four = "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\n";
    struct Case { std::string text; bool present; KModErr error; bool open_error = false; bool read_error = false; };
    const std::array<Case, 6> cases{{
        {four, false, KModErr::OK},
        {four + "CapAmb:\t0\n", true, KModErr::OK},
        {four + "CapAmb:\t1\nCapAmb:\t1\n", false, KModErr::ERR_MODULE_GET_CAPS},
        {four, false, KModErr::ERR_MODULE_OPEN_FILE, true},
        {four + "CapAmb:\t1\n", false, KModErr::ERR_MODULE_READ_FILE, false, true},
        {"", false, KModErr::ERR_MODULE_GET_CAPS},
    }};
    unsigned failures = 0;
    status_active = true;
    for (const auto& test : cases) {
        status_text = test.text;
        status_open_error = test.open_error;
        status_read_error = test.read_error;
        status_opens = status_closes = 0;
        kernel_module::caps_info output{1, 1, 1, 1, 1};
        bool present = true;
        const auto error = kernel_module::get_current_caps_snapshot(output, present);
        const kernel_module::caps_info zero{};
        const bool passed = error == test.error && present == test.present &&
            memcmp(&output, &zero, sizeof(output)) == 0 && status_opens == 1 &&
            status_closes == (test.open_error ? 0U : 1U);
        failures += !passed;
    }
    printf("{\"case\":\"snapshot\",\"cases\":%zu,\"failures\":%u,\"passed\":%s}\n",
        cases.size(), failures, failures ? "false" : "true");
    return failures ? 1 : 0;
}

int status_cases() {
    struct Case {
        const char* name;
        std::string text;
        KModErr error;
        bool ambient = true;
        bool open_error = false;
        bool read_error = false;
    };
    const std::array<std::string, 5> lines = {
        "CapInh:\t8000000000000001\n", "CapPrm:\t000001ffffffffff\n",
        "CapEff:\t0000000000000000\n", "CapBnd:\tFFFFFFFFFFFFFFFF\n",
        "CapAmb:\t0000000000000002\n"};
    std::string valid, four;
    for (unsigned i = 0; i < lines.size(); ++i) { valid += lines[i]; if (i < 4) four += lines[i]; }
    const KModErr bad = KModErr::ERR_MODULE_GET_CAPS;
    std::vector<Case> cases = {
        {"five-fields", valid, KModErr::OK},
        {"four-fields", four, KModErr::OK, false},
        {"reordered", lines[4] + lines[2] + lines[0] + lines[3] + lines[1], KModErr::OK},
        {"no-final-newline", valid.substr(0, valid.size() - 1), KModErr::OK},
        {"unrelated-fields", "Name:\ttest\nCapFuture:\tgarbage\n" + valid, KModErr::OK},
        {"empty", "", bad},
        {"unrelated-only", "Name:\ttest\n", bad},
        {"duplicate", valid + lines[0], bad},
        {"duplicate-ambient", valid + lines[4], bad},
        {"open-error", valid, KModErr::ERR_MODULE_OPEN_FILE, true, true},
        {"read-error", valid, KModErr::ERR_MODULE_READ_FILE, true, false, true},
        {"empty-read-error", "", KModErr::ERR_MODULE_READ_FILE, true, false, true},
    };
    for (unsigned missing = 0; missing < 4; ++missing) {
        std::string text;
        for (unsigned i = 0; i < lines.size(); ++i) if (i != missing) text += lines[i];
        cases.push_back({"missing-required", text, bad});
    }
    for (const char* value : {"", "-1", "+1", "0x1", "0000000000000001junk",
            "0000000000000001 extra", "10000000000000000", "gggg", "1 2"}) {
        cases.push_back({"invalid-value", "CapInh:\t" + std::string(value) + "\n" +
            lines[1] + lines[2] + lines[3] + lines[4], bad});
    }
    cases.push_back({"truncated-line", "CapInh:\t8000000000000001" +
        std::string(300, ' ') + "junk\n" + lines[1] + lines[2] + lines[3] + lines[4], bad});
    cases.push_back({"short-hex", "CapInh:\t1\n" + lines[1] + lines[2] + lines[3] + lines[4], KModErr::OK});
    cases.push_back({"all-zero", "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n", KModErr::OK});
    cases.push_back({"long-unrelated-line", "Groups:\t" + std::string(600, '1') + "\n" + valid, KModErr::OK});
    cases.push_back({"continuation-key", "Groups:\t" + std::string(247, '1') + valid, bad});
    cases.push_back({"invalid-ambient", four + "CapAmb:\t\n", bad});
    cases.push_back({"crlf-whitespace", " CapInh: 8000000000000001 \r\nCapPrm:\t000001ffffffffff\r\n"
        "CapEff: 0\r\nCapBnd: ffffffffffffffff\r\nCapAmb: 2\r\n", KModErr::OK});
    unsigned failed = 0, checks = 0;
    status_active = true;
    for (const auto& test : cases) {
        status_text = test.text;
        status_open_error = test.open_error;
        status_read_error = test.read_error;
        status_opens = status_closes = 0;
        kernel_module::caps_info output{~uint64_t{0}, ~uint64_t{0}, ~uint64_t{0}, ~uint64_t{0}, ~uint64_t{0}};
        kernel_module::caps_info expected{};
        if (test.error == KModErr::OK && std::string(test.name) != "all-zero") {
            expected = {std::string(test.name) == "short-hex" ? 1 : 0x8000000000000001ULL,
                kCap40Mask, 0, ~uint64_t{0}, test.ambient ? 2U : 0U};
        }
        const auto error = kernel_module::get_current_caps(output);
        const bool code_ok = error == test.error;
        const bool output_ok = memcmp(&output, &expected, sizeof(output)) == 0;
        const bool file_ok = status_opens == 1 && status_closes == (test.open_error ? 0U : 1U);
        checks += 3;
        failed += !code_ok; failed += !output_ok; failed += !file_ok;
        printf("STATUS case=%s error=%zd expected=%zd output_ok=%d file_ok=%d\n",
            test.name, to_num(error), to_num(test.error), output_ok, file_ok);
    }
    printf("{\"case\":\"status\",\"cases\":%zu,\"checks\":%u,\"failures\":%u,\"passed\":%s}\n",
        cases.size(), checks, failed, failed ? "false" : "true");
    return failed ? 1 : 0;
}
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string name = argv[1];
    if (name == "status") return status_cases();
    if (name == "snapshot") return snapshot_cases();
    if (name == "cap40" || name == "cap63" || name == "prctl-eperm") {
        if (name == "cap63") last_cap = 63;
        if (name == "prctl-eperm") forced_errno = EPERM;
        const uint64_t actual = kernel_module::get_cap_ability_max();
        // Original native module's AArch64 variable shift maps a shift of 64 to 0.
        const uint64_t expected = name == "cap40" ? kCap40Mask : 0;
        const bool passed = actual == expected && prctls == (name == "cap40" ? 24U : 1U);
        printf("{\"case\":\"%s\",\"passed\":%s,\"mask\":%llu,\"expected_mask\":%llu,\"prctls\":%u}\n",
            name.c_str(), passed ? "true" : "false",
            static_cast<unsigned long long>(actual),
            static_cast<unsigned long long>(expected), prctls);
        return passed ? 0 : 1;
    }

    uint32_t offset = 999;
    uint32_t expected_offset = offset;
    KModErr expected_error = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (name == "accessor-ok" || name == "accessor-zero" || name == "accessor-nonadjacent") {
        accessor_error = KModErr::OK;
        accessor_offset = expected_offset = name == "accessor-zero" ? 0 :
            name == "accessor-nonadjacent" ? 88 : 56;
        expected_error = KModErr::OK;
    } else if (name == "accessor-missing-zero") {
        offset = expected_offset = 0;
    } else if (name == "accessor-missing-nonzero") {
    } else if (name == "accessor-read-error") {
        accessor_error = expected_error = KModErr::ERR_MODULE_READ_FILE;
    } else if (name == "accessor-symbol-error") {
        accessor_error = expected_error = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    } else if (name == "btf-ok" || name == "btf-zero") {
        btf_available = true;
        btf_offset = expected_offset = name == "btf-zero" ? 0 : 48;
        expected_error = KModErr::OK;
    } else if (name == "btf-error") {
        btf_available = true;
        btf_error = expected_error = KModErr::ERR_MODULE_READ_FILE;
    } else {
        return 2;
    }
    const KModErr error = kernel_module::get_cred_cap_inheritable_offset(offset);
    const bool routing = accessor_calls == (btf_available ? 0U : 1U) && reads == 0 && lookups == 0 && prctls == 0;
    const bool passed = error == expected_error && offset == expected_offset && routing;
    printf("{\"case\":\"%s\",\"passed\":%s,\"error\":%zd,\"expected_error\":%zd,\"offset\":%u,\"expected_offset\":%u,\"reads\":%u,\"lookups\":%u,\"prctls\":%u}\n",
        name.c_str(), passed ? "true" : "false", to_num(error), to_num(expected_error),
        offset, expected_offset, reads, lookups, prctls);
    return passed ? 0 : 1;
}
