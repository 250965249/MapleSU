#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"
#include "kernel_layout.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <exception>
#include <fstream>
#include <iterator>
#include <linux/btf.h>
#include <thread>
#include "fixtures/android12-5.10.h"
#include "fixtures/seccomp-real.h"

namespace layout_test { std::atomic<unsigned> writes{0}; }
namespace kernel_module::export_symbol::linux_above_5_10_0 {
KModErr function_error = KModErr::OK;
}
using namespace kernel_module;
extern "C" KModErr maplesu_find_real_cred_offset(uint32_t* value);
namespace {
constexpr uint64_t BLOB = 0xffff000010000000ULL;
constexpr uint64_t VARIABLE = 0xffff000020000000ULL;
constexpr uint64_t BTF_A = 0xffff000030000000ULL;
constexpr uint64_t BTF_B = 0xffff000040000000ULL;
constexpr uint64_t STRINGS = 0xffff000050000000ULL;
constexpr uint64_t TYPE = 0xffff000060000000ULL;
std::vector<uint8_t> blob;
int open_error = 0;
bool file_error = false;
KModErr lookup_error = KModErr::OK;
uint64_t start = BLOB, stop = 0, btf_value = BTF_A, strings_value = STRINGS, type_value = TYPE;
uint64_t variable_value = BTF_A;
uint64_t variable_address = VARIABLE;
unsigned read_fail_at = 0;
bool execution_fail = false, strings_fail = false, first_string_nonzero = false;
bool btf_start_missing = false, btf_stop_missing = false;
std::atomic<unsigned> opens{0}, lookups{0}, reads{0}, executions{0}, legacy{0};
std::atomic<unsigned> get_btf_calls{0}, string_calls{0}, variable_reads{0};
std::vector<uint64_t> string_arguments;
std::vector<uint32_t> string_offsets;
uint64_t string_section_size = 256;
unsigned string_fail_at = 0;
unsigned string_errptr_at = 0;
bool string_max_nonnull = false, string_max_errptr = false, string_address_mismatch = false;
thread_local FILE* sysfs_file = nullptr;
unsigned checks = 0;
constexpr uint64_t TEXT = 0xffff000070000000ULL;
struct Function { uint64_t address; std::vector<uint8_t> bytes; };
std::map<std::string, Function> functions;
uint64_t size_override = 0, symbol_offset = 0;
bool symbol_size_missing = false, symbol_size_fail = false, text_read_fail = false;
unsigned text_reads = 0, text_outside = 0;
bool name_fixture = false;
uint32_t member_name_offset = 1;
std::vector<uint8_t> name_section;
unsigned name_reads = 0, name_outside = 0, name_fail_at = 0;
std::map<uint32_t, uint64_t> live_ids;
std::map<uint64_t, std::vector<uint8_t>> live_records;
uint64_t live_failed_read = 0, live_find_result = 1;
unsigned live_graph_reads = 0, live_graph_outside = 0, live_type_calls = 0;

void check(bool value) { ++checks; assert(value); }
void word(std::vector<uint8_t>& bytes, uint32_t value) {
    for (unsigned i = 0; i != 4; ++i) bytes.push_back(uint8_t(value >> (i * 8)));
}
struct Fixture {
    std::vector<uint8_t> types, strings{0};
    uint32_t str(const char* s) { auto at = uint32_t(strings.size()); do { strings.push_back(*s); } while (*s++); return at; }
    void type(const char* name, uint32_t kind, uint32_t size, uint32_t count = 0) {
        word(types, str(name)); word(types, kind << 24 | count); word(types, size);
    }
    void member(const char* name, uint32_t id, uint32_t offset) {
        word(types, str(name)); word(types, id); word(types, offset * 8);
    }
    std::vector<uint8_t> bytes() {
        std::vector<uint8_t> out;
        for (uint32_t value : {0x0001eb9fU, 24U, 0U, uint32_t(types.size()), uint32_t(types.size()), uint32_t(strings.size())}) word(out, value);
        out.insert(out.end(), types.begin(), types.end()); out.insert(out.end(), strings.begin(), strings.end());
        return out;
    }
};
Fixture fixture(const std::string& mode = "") {
    Fixture f;
    f.type("u32", 1, 4); word(f.types, 32); // 1
    f.type("u64", 1, 8); word(f.types, 64); // 2
    f.type("cred", 4, 8, 1); f.member("uid", 1, 0); // 3: unrelated duplicate
    f.type("cred", 4, 72, mode == "field-only" ? 1 : 3); // 4: actual pointee
    if (mode != "field-only") f.member("uid", mode == "width" ? 2 : 1, mode == "bounds" ? 72 : 32);
    f.member("euid", 1, 4);
    if (mode != "field-only") f.member("cap_inheritable", 2, 48);
    f.type("", 10, 4); // 5: const
    f.type("", 2, 5); // 6: pointer
    f.type("task_struct", 4, 96, mode == "field-only" ? 1 : 2); // 7
    f.member("cred", 6, 48);
    if (mode != "field-only") f.member("real_cred", 6, 16);
    if (mode == "ambiguous") {
        f.type("task_struct", 4, 112, 2); f.member("cred", 6, 56); f.member("real_cred", 6, 24);
    }
    return f;
}
Fixture seccomp_fixture(const std::string& mode) {
    Fixture f;
    f.type("u32", 1, 4); word(f.types, 32); // 1
    f.type("u64", 1, 8); word(f.types, 64); // 2
    f.type("cred", 4, 8, 1); f.member("uid", 1, 0); // 3
    f.type("", 10, 3); // 4: const cred
    f.type("", 2, 4); // 5: pointer to cred
    f.type("seccomp", 4, 16, mode == "seccomp-btf-missing" ? 0 : 1); // 6
    if (mode != "seccomp-btf-missing")
        f.member("mode", mode == "seccomp-btf-width" ? 2 : 1, mode == "seccomp-btf-zero" ? 0 : 4);
    f.type("task_struct", 4, 256, 2); // 7
    f.member("cred", 5, 48);
    f.member("seccomp", 6, mode == "seccomp-btf-zero" ? 0 : 128);
    return f;
}
void install_accessors(bool real = false) {
    open_error = ENOENT; lookup_error = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    if (real) {
        for (const auto& f : layout_test::real_accessors)
            functions[f.name] = {TEXT + f.offset, {f.bytes, f.bytes + f.size}};
        functions["overflowuid"] = {TEXT + layout_test::real_overflowuid, {}};
        functions["overflowgid"] = {TEXT + layout_test::real_overflowgid, {}};
        return;
    }
    for (unsigned index = 0; index != 4; ++index) {
        const char* names[] = {"__arm64_sys_getuid", "__arm64_sys_geteuid", "__arm64_sys_getgid", "__arm64_sys_getegid"};
        const unsigned offsets[] = {32, 4, 20, 12};
        std::vector<uint8_t> bytes;
        word(bytes, 0xd5384108); // mrs x8, sp_el0
        word(bytes, 0xf9400008 | (48 / 8 << 10) | (8 << 5)); // ldr x8, [x8, #48]
        word(bytes, 0xb9400000 | (offsets[index] / 4 << 10) | (8 << 5)); // ldr w0, [x8, #offset]
        word(bytes, 0xd65f03c0);
        functions[names[index]] = {TEXT + index * 0x1000, std::move(bytes)};
    }
}
void install_cap_accessor(const std::string& mode) {
    install_accessors();
    functions["__rcu_read_lock"] = {TEXT + 0x8000, {}};
    functions["__rcu_read_unlock"] = {TEXT + 0x9000, {}};
    std::vector<uint8_t> bytes;
    auto call = [&](uint64_t target) {
        const auto displacement = static_cast<int64_t>(target - (TEXT + 0x4000 + bytes.size()));
        word(bytes, 0x94000000U | (static_cast<uint32_t>(displacement / 4) & 0x03ffffffU));
    };
    // Synthetic cap_capget data flow; target task and three output pointers
    // remain distinct from current task / task.cred ID getter fixtures.
    for (unsigned i = 0; i != 4; ++i) word(bytes, 0xaa0003e0U | (i << 16) | (19 + i));
    call(TEXT + 0x8000);
    const unsigned real_cred = mode == "caps-zero" ? 0 : 16;
    word(bytes, 0xf9400008U | (real_cred / 8 << 10) | (19 << 5));
    const unsigned offsets[] = {64, mode == "caps-overlap" ? 64U : mode == "caps-nonadjacent" ? 104U : 48U, 80};
    for (unsigned i = 0; i != 3; ++i) {
        word(bytes, 0xf9400009U | (offsets[i] / 8 << 10) | (8 << 5));
        if (mode != "caps-missing-output" || i != 1)
            word(bytes, 0xf9000009U | ((20 + i) << 5));
    }
    if (mode != "caps-no-unlock") call(TEXT + 0x9000);
    word(bytes, 0x2a1f03e0U); // mov w0,wzr
    word(bytes, 0xd65f03c0U);
    if (mode == "caps-truncated") bytes.pop_back();
    if (mode == "caps-read-error") text_read_fail = true;
    functions["cap_capget"] = {TEXT + 0x4000, std::move(bytes)};
    if (mode == "caps-symbol-missing") functions.erase("cap_capget");
}
void expect_accessor_values(uint32_t uid = 32, uint32_t euid = 4, uint32_t cred = 48) {
    uint32_t observed_uid = 999, observed_euid = 999, observed_cred = 999;
    auto uid_error = get_cred_uid_offset(observed_uid);
    auto euid_error = get_cred_euid_offset(observed_euid);
    auto cred_error = get_task_struct_cred_offset(observed_cred);
    printf("OBSERVED uid=%u/%u euid=%u/%u cred=%u/%u candidate-writes=%u legacy=%u\n",
        observed_uid, uid, observed_euid, euid, observed_cred, cred, layout_test::writes.load(), legacy.load());
    fflush(stdout);
    check(is_ok(uid_error) && observed_uid == uid);
    check(is_ok(euid_error) && observed_euid == euid);
    check(is_ok(cred_error) && observed_cred == cred);
    check(layout_test::writes == 0); check(legacy == 0); check(text_outside == 0);
    KernelFieldDescription field;
    check(is_ok(maplesu_resolve_accessor_field("cred", "uid", 4, field)));
    check(field.offset_bytes == uid && field.width_bytes == 4 && field.owner_size_bytes == 0);
    check(!strcmp(field.source, "accessor") && !strcmp(field.reader, "target-text") && field.parser_version == 1);
}
void set_blob(std::vector<uint8_t> value) { blob = std::move(value); stop = start + blob.size(); }
void clean_readonly() { check(layout_test::writes == 0); check(legacy == 0); check(executions == 0); }
void get_five() {
    uint32_t value = 999;
    check(is_ok(get_task_struct_real_cred_offset(value)) && value == 16);
    check(is_ok(get_task_struct_cred_offset(value)) && value == 48);
    check(is_ok(get_cred_uid_offset(value)) && value == 32);
    check(is_ok(get_cred_euid_offset(value)) && value == 4);
    check(is_ok(get_cred_cap_inheritable_offset(value)) && value == 48);
    check(maplesu_find_real_cred_offset(nullptr) == KModErr::ERR_MODULE_PARAM);
    value = 999;
    check(is_ok(maplesu_find_real_cred_offset(&value)) && value == 16);
}
void expect_failed_uid() {
    uint32_t value = 999;
    check(is_failed(get_cred_uid_offset(value)) && value == 999);
    clean_readonly();
}
void retry_good() { set_blob(fixture().bytes()); get_five(); clean_readonly(); }
void setup_live() {
    open_error = ENOENT; lookup_error = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
}
KModErr live_size(uint32_t& value) { return btf_resolve_struct_size("fixture", value); }
void live_retry_after_failure() {
    uint32_t value = 999;
    check(is_failed(live_size(value)) && value == 0);
    btf_value = BTF_B; variable_value = BTF_B;
    strings_fail = false; execution_fail = false; strings_value = STRINGS;
    first_string_nonzero = false; type_value = TYPE;
    check(is_ok(live_size(value)) && value == 32);
    check(!string_arguments.empty() && string_arguments.back() == BTF_B);
}
void install_live_fixture(const Fixture& fixture, uint32_t root) {
    name_fixture = true;
    name_section = fixture.strings;
    string_section_size = name_section.size();
    live_find_result = root;
    size_t at = 0;
    uint32_t id = 1;
    while (at < fixture.types.size()) {
        uint32_t info = 0;
        memcpy(&info, fixture.types.data() + at + 4, sizeof(info));
        const uint32_t kind = info >> 24 & 31, count = info & 0xffff;
        const size_t extra = kind == 1 ? 4 : kind == 3 ? 12 : (kind == 4 || kind == 5) ? count * 12 : 0;
        const size_t end = at + sizeof(btf_type) + extra;
        check(end <= fixture.types.size());
        const uint64_t address = TYPE + uint64_t(id) * 0x100000;
        live_ids[id] = address;
        live_records[address] = {fixture.types.begin() + at, fixture.types.begin() + end};
        ++id; at = end;
    }
}
void test_live_field(const std::string& mode) {
    Fixture f;
    uint32_t integer_size = mode == "live-field-wide-owner" ? 8 : 4;
    f.type("integer", 1, integer_size);
    word(f.types, mode == "live-field-int-zero" ? 0 : mode == "live-field-int-invalid" ? (16U << 16 | 24) :
        mode == "live-field-int-offset" ? (8U << 16 | 16) : integer_size * 8);
    uint32_t member_id = 1, root_id = 2, owner = 32, offset = 12, count = 1;
    bool nested = false, named_nested = false, modern = false;
    std::string wanted = "field";
    KModErr expected = KModErr::OK;
    uint32_t expected_offset = 12;
    if (mode == "live-field-zero") offset = expected_offset = 0;
    else if (mode == "live-field-owner-end") offset = expected_offset = 28;
    else if (mode == "live-field-owner-overflow") { offset = 32; expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
    else if (mode == "live-field-wide-owner") { offset = 28; expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
    else if (mode == "live-field-int-offset") expected_offset = 13;
    else if (mode == "live-field-int-zero" || mode == "live-field-int-invalid") expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    else if (mode == "live-field-array" || mode == "live-field-array-overflow" || mode == "live-field-array-cycle") {
        f.type("", 3, 0); // 2
        word(f.types, mode == "live-field-array-cycle" ? 2 : 1); word(f.types, 1);
        word(f.types, mode == "live-field-array-overflow" ? UINT32_MAX : 3);
        member_id = 2; root_id = 3;
        if (mode == "live-field-array") offset = expected_offset = 20;
        else expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    } else if (mode == "live-field-modifier-long" || mode == "live-field-modifier-cycle") {
        const uint32_t modifiers = mode == "live-field-modifier-long" ? 40 : 1;
        for (uint32_t i = 0; i < modifiers; ++i) f.type("", 10, mode == "live-field-modifier-cycle" ? 2 : i + 1);
        member_id = 1 + modifiers; root_id = 2 + modifiers;
        if (mode == "live-field-modifier-cycle") expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    } else if (mode == "live-field-modern" || mode == "live-field-modern-bits" || mode == "live-field-modern-overflow") {
        modern = true;
        if (mode != "live-field-modern") expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    } else if (mode == "live-field-anonymous-empty") {
        f.type("", 4, 0); // Empty anonymous aggregate, type 2.
        root_id = 3; count = 2;
    } else if (mode == "live-field-anonymous" || mode == "live-field-union" || mode == "live-field-nested-owner" ||
               mode == "live-field-nested-read" || mode == "live-field-nested-duplicate" || mode == "live-field-path") {
        f.type("embedded", mode == "live-field-union" ? 5 : 4, 16, 1); f.member("field", 1, 4); // 2
        member_id = 2; root_id = 3; nested = true;
        offset = 8;
        if (mode == "live-field-nested-owner") { owner = 16; expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
        else if (mode == "live-field-nested-read") expected = KModErr::ERR_MODULE_READ_FILE;
        else if (mode == "live-field-nested-duplicate") { owner = 48; count = 2; expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
        else if (mode == "live-field-path") { named_nested = true; wanted = "outer.field"; }
    } else if (mode == "live-field-anonymous-cycle") {
        member_id = root_id; nested = true; offset = 0;
        expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    } else if (mode == "live-field-duplicate") { count = 2; expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
    else if (mode == "live-field-many") count = 5000;
    else if (mode == "live-field-missing") { wanted = "absent"; expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
    else if (mode == "live-field-missing-type") { member_id = 999; expected = KModErr::ERR_MODULE_NOT_KADDR; }
    else if (mode == "live-field-empty-owner") { owner = 0; expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
    else if (mode == "live-field-type-range" || mode == "live-field-members-range") expected = KModErr::ERR_MODULE_NOT_KADDR;
    else if (mode == "live-field-find-truncated") expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    const auto root_at = f.types.size();
    f.type("fixture", 4, owner, count);
    for (uint32_t i = 0; i < count; ++i) {
        if (mode == "live-field-anonymous-empty" && i == 0) {
            f.member("", 2, 0);
            continue;
        }
        const char* name = nested ? (named_nested ? "outer" : "") : mode == "live-field-many" && i + 1 < count ? "other" : "field";
        f.member(name, member_id, offset);
    }
    if (modern) {
        f.types[root_at + 7] |= 0x80;
        const uint32_t member_offset = (mode == "live-field-modern-bits" ? 3U : mode == "live-field-modern-overflow" ? 40U : 16U) << 24 | 96;
        memcpy(f.types.data() + root_at + sizeof(btf_type) + 8, &member_offset, sizeof(member_offset));
    }
    if (mode != "live-field-nested-read" && mode != "live-field-type-range" &&
        mode != "live-field-members-range" && mode != "live-field-find-truncated") {
        bool shared_ok = false;
        uint32_t shared_offset = 0;
        try {
            const auto layout = maplesu::module_policy::describe_kernel_layout(f.bytes(), {{"fixture", {wanted}}});
            const auto& field = layout.types.at(0).fields.at(0);
            shared_ok = !(field.bit_offset & 7) && field.bit_size && !(field.bit_size & 7);
            shared_offset = field.bit_offset / 8;
        } catch (const std::exception&) {}
        check(shared_ok == is_ok(expected));
        if (shared_ok) check(shared_offset == expected_offset);
    }
    install_live_fixture(f, root_id);
    if (mode == "live-field-nested-read") live_failed_read = live_ids.at(2) + sizeof(btf_type);
    if (mode == "live-field-type-range" || mode == "live-field-members-range") {
        const auto original = live_ids.at(root_id);
        const uint64_t edge = static_cast<uint64_t>(-4095LL) - (mode == "live-field-type-range" ? 8 : 16);
        live_records[edge] = std::move(live_records.at(original)); live_records.erase(original);
        live_ids[root_id] = edge;
    }
    if (mode == "live-field-find-truncated") live_find_result += uint64_t(1) << 32;
    uint32_t value = 999;
    const auto error = btf_resolve_member_offset("fixture", wanted.c_str(), value);
    printf("LIVE-FIELD error=%lld expected=%lld offset=%u expected-offset=%u graph-reads=%u type-calls=%u outside=%u\n",
        static_cast<long long>(error), static_cast<long long>(expected), value, expected_offset,
        live_graph_reads, live_type_calls, live_graph_outside);
    check(error == expected); check(value == (is_ok(expected) ? expected_offset : 0));
    check(live_graph_outside == 0); check(name_outside == 0);
    if (mode == "live-field-type-range" || mode == "live-field-find-truncated") check(live_graph_reads == 0);
    if (mode == "live-field-modifier-cycle" || mode == "live-field-array-cycle" || mode == "live-field-anonymous-cycle")
        check(live_type_calls < 10);
}
}
extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" size_t __real_fread(void*, size_t, size_t, FILE*);
extern "C" int __real_ferror(FILE*);
extern "C" FILE* __wrap_fopen(const char* name, const char* mode) {
    if (strcmp(name, "/sys/kernel/btf/vmlinux")) return __real_fopen(name, mode);
    ++opens;
    if (open_error) { errno = open_error; return nullptr; }
    sysfs_file = fmemopen(blob.data(), blob.size(), mode);
    return sysfs_file;
}
extern "C" size_t __wrap_fread(void* data, size_t size, size_t count, FILE* input) {
    if (input == sysfs_file && file_error) return 0;
    return __real_fread(data, size, count, input);
}
extern "C" int __wrap_ferror(FILE* input) {
    return input == sysfs_file && file_error ? 1 : __real_ferror(input);
}
namespace kernel_module {
KModErr get_seccomp_offset(uint32_t&) { ++legacy; return KModErr::ERR_MODULE_INTERNAL_APPEND; }
KModErr kallsyms_lookup_name(const char* name, uint64_t& value) {
    ++lookups;
    auto function = functions.find(name);
    if (function != functions.end()) { value = function->second.address; return KModErr::OK; }
    if (!strcmp(name, "btf_vmlinux")) { value = variable_address; return KModErr::OK; }
    if ((!strcmp(name, "__start_BTF") && btf_start_missing) || (!strcmp(name, "__stop_BTF") && btf_stop_missing))
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    if (is_failed(lookup_error)) return lookup_error;
    if (!strcmp(name, "__start_BTF")) value = start;
    else if (!strcmp(name, "__stop_BTF")) value = stop;
    else return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    return KModErr::OK;
}
KModErr read_kernel_mem(uint64_t address, void* data, uint32_t count) {
    unsigned call = ++reads;
    if (read_fail_at == call) return KModErr::ERR_MODULE_READ_FILE;
    if (!live_records.empty()) {
        for (const auto& [base, bytes] : live_records) {
            if (address < base || address - base > bytes.size()) continue;
            ++live_graph_reads;
            if (address == live_failed_read) return KModErr::ERR_MODULE_READ_FILE;
            const auto offset = static_cast<size_t>(address - base);
            if (count > bytes.size() - offset) { ++live_graph_outside; return KModErr::ERR_MODULE_READ_FILE; }
            memcpy(data, bytes.data() + offset, count);
            return KModErr::OK;
        }
    }
    if (address == TYPE + 0x1000 && count == sizeof(btf_type)) {
        btf_type type{}; type.info = 1U << 24; type.size = 4;
        memcpy(data, &type, sizeof(type)); return KModErr::OK;
    }
    if (address == TYPE + 0x1000 + sizeof(btf_type) && count == 4) {
        uint32_t encoding = 32; memcpy(data, &encoding, 4); return KModErr::OK;
    }
    if (name_fixture && address == strings_value && count == 1) {
        *static_cast<char*>(data) = 0;
        return KModErr::OK;
    }
    if (name_fixture && address != TYPE && address != TYPE + sizeof(btf_type)) {
        if (address < strings_value || address - strings_value > name_section.size() ||
            count > name_section.size() - static_cast<size_t>(address - strings_value)) {
            ++name_outside;
            return KModErr::ERR_MODULE_READ_FILE;
        }
        ++name_reads;
        if (name_reads == name_fail_at) return KModErr::ERR_MODULE_READ_FILE;
        memcpy(data, name_section.data() + static_cast<size_t>(address - strings_value), count);
        return KModErr::OK;
    }
    for (const auto& pair : functions) {
        const auto& f = pair.second;
        if (address >= f.address && address - f.address < 0x1000) {
            ++text_reads;
            if (text_read_fail) return KModErr::ERR_MODULE_READ_FILE;
            if (address - f.address > f.bytes.size() || count > f.bytes.size() - (address - f.address)) {
                ++text_outside; return KModErr::ERR_MODULE_READ_FILE;
            }
            memcpy(data, f.bytes.data() + (address - f.address), count); return KModErr::OK;
        }
    }
    if (address >= BLOB && address - BLOB <= blob.size() && count <= blob.size() - size_t(address - BLOB)) {
        memcpy(data, blob.data() + size_t(address - BLOB), count); return KModErr::OK;
    }
    if (address == VARIABLE && count == 8) { ++variable_reads; memcpy(data, &variable_value, 8); return KModErr::OK; }
    if (address == STRINGS && count == 1) { *static_cast<char*>(data) = first_string_nonzero ? 'x' : 0; return KModErr::OK; }
    if (address >= STRINGS && address < STRINGS + 256 && count <= 256 - (address - STRINGS)) {
        char strings[256] = "\0field"; memcpy(data, strings + (address - STRINGS), count); return KModErr::OK;
    }
    if (address == TYPE && count == sizeof(btf_type)) {
        btf_type type{}; type.info = 4U << 24 | 1; type.size = 32; memcpy(data, &type, sizeof(type)); return KModErr::OK;
    }
    if (address == TYPE + sizeof(btf_type) && count == sizeof(btf_member)) {
        btf_member member{member_name_offset, 2, 96}; memcpy(data, &member, sizeof(member)); return KModErr::OK;
    }
    return KModErr::ERR_MODULE_READ_FILE;
}
KModErr execute_kernel_asm_func(const std::vector<uint8_t>& bytes, uint64_t& value) {
    ++executions;
    uint64_t argument = 0; memcpy(&argument, bytes.data() + 1, 8);
    switch (bytes[0]) {
        case layout_test::symbol_size:
            if (symbol_size_missing) return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
            if (symbol_size_fail) return KModErr::ERR_MODULE_READ_FILE;
            for (const auto& pair : functions) if (pair.second.address == argument) {
                value = symbol_offset ? 0 : size_override ? size_override : pair.second.bytes.size();
                return KModErr::OK;
            }
            return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
        case layout_test::get_btf:
            ++get_btf_calls;
            if (execution_fail) return KModErr::ERR_MODULE_READ_FILE;
            value = btf_value; break;
        case layout_test::get_strings: {
            ++string_calls; string_arguments.push_back(argument);
            if (strings_fail) return KModErr::ERR_MODULE_READ_FILE;
            if (string_calls == string_fail_at) return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
            uint32_t offset = 0;
            if (bytes.size() >= 13) memcpy(&offset, bytes.data() + 9, sizeof(offset));
            string_offsets.push_back(offset);
            if (string_calls == string_errptr_at || (offset == UINT32_MAX && string_max_errptr)) value = uint64_t(-22LL);
            else if (offset == UINT32_MAX && string_max_nonnull) value = strings_value + offset;
            else if (offset >= string_section_size) value = 0;
            else value = strings_value + offset + (offset && string_address_mismatch ? 1 : 0);
            break;
        }
        case layout_test::find_type: value = live_find_result; break;
        case layout_test::type_by_id:
            ++live_type_calls;
            if (!live_ids.empty()) value = live_ids.count(static_cast<uint32_t>(argument)) ? live_ids.at(static_cast<uint32_t>(argument)) : 0;
            else value = argument == 2 ? TYPE + 0x1000 : type_value;
            break;
        default: return KModErr::ERR_MODULE_PARAM;
    }
    return KModErr::OK;
}
}

#ifdef MAPLESU_LAYOUT_RED_BASELINE
int main(int argc, char** argv) {
    assert(argc == 2); const std::string mode = argv[1];
    set_blob(fixture().bytes()); uint32_t value = 999;
    if (mode == "sysfs-task-cred") {
        KModErr result = get_task_struct_cred_offset(value);
        printf("OBSERVED result=%lld task.cred=%u expected=48 legacy=%u\n", static_cast<long long>(result), value, legacy.load());
        fflush(stdout); check(is_ok(result) && value == 48 && legacy == 0);
    } else if (mode == "sysfs-uid") {
        KModErr result = get_cred_uid_offset(value);
        printf("OBSERVED result=%lld cred.uid=%u expected=32 candidate-writes=%u\n", static_cast<long long>(result), value, layout_test::writes.load());
        fflush(stdout); check(is_ok(result) && value == 32 && layout_test::writes == 0);
    } else if (mode == "live-function-missing") {
        setup_live(); export_symbol::linux_above_5_10_0::function_error = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
        KModErr result = live_size(value);
        printf("OBSERVED result=%lld size=%u expected=32 variable-reads=%u\n", static_cast<long long>(result), value, variable_reads.load());
        fflush(stdout); check(is_ok(result) && value == 32 && variable_reads == 1);
    } else if (mode == "live-strings-failure") {
        setup_live(); strings_fail = true;
        check(is_failed(live_size(value))); strings_fail = false; btf_value = BTF_B;
        KModErr result = live_size(value);
        printf("OBSERVED result=%lld size=%u get-btf-calls=%u string-calls=%u\n", static_cast<long long>(result), value, get_btf_calls.load(), string_calls.load());
        fflush(stdout); check(is_ok(result) && value == 32 && get_btf_calls == 2 && string_arguments.back() == BTF_B);
    } else assert(false);
}
#else
int main(int argc, char** argv) {
    assert(argc == 2 || argc == 3);
    const std::string mode = argv[1];
    set_blob(fixture().bytes());
    if (mode.rfind("caps-", 0) == 0) {
        install_cap_accessor(mode);
        const bool success = mode == "caps-ok" || mode == "caps-zero" || mode == "caps-nonadjacent";
        uint32_t inherited = 999, real_cred = 999;
        const auto cap_error = get_cred_cap_inheritable_offset(inherited);
        const auto task_error = get_task_struct_real_cred_offset(real_cred);
        check(success ? is_ok(cap_error) && inherited == (mode == "caps-nonadjacent" ? 104U : 48U) :
                        is_failed(cap_error) && inherited == 999);
        check(success ? is_ok(task_error) && real_cred == (mode == "caps-zero" ? 0U : 16U) :
                        is_failed(task_error) && real_cred == 999);
        if (!success) {
            text_read_fail = false;
            install_cap_accessor("caps-ok");
            check(is_ok(get_cred_cap_inheritable_offset(inherited)) && inherited == 48);
            check(is_ok(get_task_struct_real_cred_offset(real_cred)) && real_cred == 16);
        }
        uint32_t compatible = 999;
        check(is_ok(maplesu_find_real_cred_offset(&compatible)) && compatible == real_cred);
        uint32_t subjective = 999;
        check(is_ok(get_task_struct_cred_offset(subjective)) && subjective == 48);
        for (const auto& member : {std::make_pair("cap_effective", 64U), std::make_pair("cap_permitted", 80U)}) {
            KernelFieldDescription field;
            check(is_ok(maplesu_resolve_accessor_field("cred", member.first, 8, field)));
            check(field.offset_bytes == member.second && field.width_bytes == 8 && !field.owner_size_bytes);
            check(field.parser_version == 2 && !strcmp(field.source, "accessor") && !strcmp(field.reader, "target-text"));
        }
        check(legacy == 0); check(layout_test::writes == 0); check(text_outside == 0);
    } else if (mode.rfind("seccomp-", 0) == 0) {
        const bool btf = mode.rfind("seccomp-btf-", 0) == 0;
        bool success = true;
        uint32_t expected = 128;
        if (btf) {
            set_blob(seccomp_fixture(mode).bytes());
            expected = mode == "seccomp-btf-zero" ? 0 : 132;
            success = mode != "seccomp-btf-width" && mode != "seccomp-btf-damaged" && mode != "seccomp-btf-missing";
            if (mode == "seccomp-btf-damaged") blob[0] ^= 0xff;
        } else {
            open_error = ENOENT; lookup_error = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
            std::vector<uint8_t> bytes;
            if (mode == "seccomp-accessor-real-510" || mode == "seccomp-accessor-real-66") {
                const auto& f = layout_test::real_seccomp[mode == "seccomp-accessor-real-510" ? 0 : 1];
                bytes.assign(f.bytes, f.bytes + f.size); expected = f.offset;
            } else {
                word(bytes, 0xd5384108U); // mrs x8, sp_el0
                expected = mode == "seccomp-accessor-zero" ? 0 : 128;
                if (mode == "seccomp-accessor-indirect") {
                    word(bytes, 0xf9401908U); word(bytes, 0xb9401100U); success = false;
                } else {
                    const uint32_t load = mode == "seccomp-accessor-wide" ? 0xf9408100U :
                        mode == "seccomp-accessor-ldr" ? 0xb9408100U : 0xb9800100U | (expected / 4 << 10);
                    word(bytes, mode == "seccomp-accessor-mov-w" ? load | 9U : load);
                    if (mode == "seccomp-accessor-mov-w") word(bytes, 0x2a0903e0U); // mov w0,w9
                    if (mode == "seccomp-accessor-wide") success = false;
                }
                if (mode == "seccomp-accessor-unknown-return") { word(bytes, 0x2a0903e0U); success = false; }
                word(bytes, 0xd65f03c0U);
                if (mode == "seccomp-accessor-truncated") { bytes.pop_back(); success = false; }
            }
            functions["prctl_get_seccomp"] = {TEXT, std::move(bytes)};
            if (mode == "seccomp-accessor-conflict") {
                std::vector<uint8_t> other;
                for (uint32_t instruction : {0xd5384108U, 0xb980c100U, 0xd65f03c0U}) word(other, instruction);
                functions["seccomp_mode"] = {TEXT + 0x1000, std::move(other)}; success = false;
            } else if (mode == "seccomp-accessor-missing") { functions.clear(); success = false; }
            else if (mode == "seccomp-accessor-read-error") { text_read_fail = true; success = false; }
            else if (mode == "seccomp-accessor-size-error") { symbol_size_missing = true; success = false; }
        }
        uint32_t value = 0xa5a5a5a5U;
        const auto error = get_task_struct_seccomp_offset(value);
        printf("SECCOMP case=%s result=%lld value=%u expected=%u success=%u legacy=%u writes=%u outside=%u\n",
            mode.c_str(), static_cast<long long>(error), value, expected, success, legacy.load(), layout_test::writes.load(), text_outside);
        fflush(stdout);
        check(success ? is_ok(error) && value == expected : is_failed(error) && value == 0xa5a5a5a5U);
        check(legacy == 0); check(layout_test::writes == 0); check(text_outside == 0);
        if (btf) { check(text_reads == 0); check(executions == 0); }
        if (success) {
            uint32_t again = 999;
            check(is_ok(get_task_struct_seccomp_offset(again)) && again == expected);
            KernelFieldDescription field;
            bool available = false;
            const auto described = btf ? maplesu_resolve_btf_field("task_struct", "seccomp.mode", 4, field, available) :
                maplesu_resolve_accessor_field("task_struct", "seccomp.mode", 4, field);
            check(is_ok(described) && field.offset_bytes == expected && field.width_bytes == 4);
            check(field.owner_size_bytes == (btf ? 256U : 0U));
            check(!strcmp(field.source, btf ? "btf" : "accessor"));
        }
    } else if (mode.rfind("accessor-", 0) == 0) {
        install_accessors(mode == "accessor-real");
        auto& uid = functions.at("__arm64_sys_getuid").bytes;
        const bool overflow_case = mode.rfind("accessor-overflow-", 0) == 0;
        if (overflow_case) {
            uid.clear();
            const unsigned displacement = 0x8000 - 12 + (mode == "accessor-overflow-address" ? 4 : 0);
            const uint32_t adr = 0x10000009U | ((displacement & 3) << 29) | ((displacement >> 2) << 5);
            for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0xb9402108U, adr,
                mode == "accessor-overflow-width" ? 0xf9400129U : 0xb9400129U,
                mode == "accessor-overflow-flags" ? 0x310004ffU : 0x3100051fU}) word(uid, insn);
            if (mode == "accessor-overflow-interrupted" || mode == "accessor-overflow-preserve-hint") word(uid, 0xd503201fU);
            else if (mode == "accessor-overflow-preserve-mov") word(uid, 0x2a0803eaU); // mov w10,w8
            else if (mode == "accessor-overflow-preserve-ldr") {
                for (uint32_t insn : {0xd538410aU, 0xf940194aU, 0xb940054bU}) word(uid, insn);
            } else if (mode == "accessor-overflow-preserve-branch") {
                word(uid, 0x3400004aU); word(uid, 0xd503201fU); // cbz w10,csel; nop
            } else if (mode == "accessor-overflow-clobber-adds") word(uid, 0x3100042aU);
            else if (mode == "accessor-overflow-clobber-ands") word(uid, 0x6a02002aU);
            word(uid, mode == "accessor-overflow-ne" ? 0x1a891100U :
                mode == "accessor-overflow-condition" ? 0x1a881120U : 0x1a880120U);
            word(uid, 0xd65f03c0U);
            functions[mode == "accessor-overflow-family" ? "overflowgid" : "overflowuid"] = {TEXT + 0x8000, {}};
        }
        if (mode == "accessor-overflow-eq" || mode == "accessor-overflow-ne" ||
            mode == "accessor-overflow-interrupted" || mode.rfind("accessor-overflow-preserve-", 0) == 0) expect_accessor_values();
        else if (mode == "accessor-nonadjacent") expect_accessor_values();
        else if (mode == "accessor-real") expect_accessor_values(4, 20, 1920);
        else if (mode == "accessor-concurrent") {
            std::atomic<unsigned> failures{0}; std::vector<std::thread> threads;
            for (unsigned i = 0; i != 16; ++i) threads.emplace_back([&] {
                for (unsigned n = 0; n != 20; ++n) {
                    uint32_t value = 999;
                    if (is_failed(get_cred_uid_offset(value)) || value != 32) ++failures;
                    if (is_failed(get_cred_euid_offset(value)) || value != 4) ++failures;
                    if (is_failed(get_task_struct_cred_offset(value)) || value != 48) ++failures;
                }
            });
            for (auto& t : threads) t.join();
            check(failures == 0); check(layout_test::writes == 0); check(legacy == 0);
            check(text_reads == 4 && text_outside == 0);
        } else if (mode == "accessor-converter" || mode == "accessor-tail-converter") {
            uid.clear();
            for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0xb9402101U}) word(uid, insn);
            functions["from_kuid_munged"] = {TEXT + 0x4000, {}};
            word(uid, (mode == "accessor-converter" ? 0x94000000U : 0x14000000U) | ((0x4000 - 12) / 4));
            word(uid, 0xd65f03c0U);
            expect_accessor_values();
        } else if (mode == "accessor-thunk") {
            functions["uid_body"] = {TEXT + 0x4000, uid};
            uid.clear(); word(uid, 0xd503245fU); word(uid, 0x14000000U | ((0x4000 - 4) / 4));
            expect_accessor_values();
        } else if (mode == "accessor-add-mov") {
            uid.clear();
            for (uint32_t insn : {0xd5384108U, 0x91008108U, 0xf9400909U, 0x91004129U, 0xb940112aU, 0x2a0a03e0U, 0xd65f03c0U}) word(uid, insn);
            expect_accessor_values();
        } else if (mode == "accessor-branch") {
            uid.clear();
            for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0x34000060U, 0xb9402100U, 0x14000002U, 0xb9402100U, 0xd65f03c0U}) word(uid, insn);
            expect_accessor_values();
        } else {
            if (overflow_case) {
                // The inline projection above deliberately changes one proof condition.
            } else if (mode == "accessor-csel-unknown" || mode == "accessor-csel-wrong-flags") {
                uid.clear();
                for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0xb9402108U, 0x2a0103e9U,
                    mode == "accessor-csel-unknown" ? 0x3100051fU : 0x310004ffU, 0x1a880120U, 0xd65f03c0U}) word(uid, insn);
            } else if (mode == "accessor-wrong-converter") {
                uid.clear();
                for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0xb9402101U, 0x94000000U | ((0x4000 - 12) / 4), 0xd65f03c0U}) word(uid, insn);
                functions["from_kgid_munged"] = {TEXT + 0x4000, {}};
            } else if (mode == "accessor-partial-btf-start" || mode == "accessor-partial-btf-stop") {
                lookup_error = KModErr::OK;
                btf_start_missing = mode == "accessor-partial-btf-start";
                btf_stop_missing = mode == "accessor-partial-btf-stop";
            } else if (mode == "accessor-ambiguous") {
                uid.clear();
                for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0x34000060U, 0xb9402100U, 0x14000002U, 0xb9402500U, 0xd65f03c0U}) word(uid, insn);
            } else if (mode == "accessor-task-conflict") {
                auto& euid = functions.at("__arm64_sys_geteuid").bytes;
                euid[5] ^= 4; // task.cred displacement differs from the other getters.
            } else if (mode == "accessor-unknown-return") {
                uid.clear(); for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0xb9402100U, 0x2a0103e0U, 0xd65f03c0U}) word(uid, insn);
            } else if (mode == "accessor-branch-outside") {
                uid.clear(); word(uid, 0x34002000U); word(uid, 0xd65f03c0U);
            } else if (mode == "accessor-thunk-cycle") {
                uid.clear(); word(uid, 0x14000000U | (0x4000 / 4));
                std::vector<uint8_t> back; word(back, 0x14000000U | ((0U - 0x4000 / 4) & 0x03ffffffU));
                functions["uid_body"] = {TEXT + 0x4000, back};
            } else if (mode == "accessor-truncated") uid.pop_back();
            else if (mode == "accessor-width") { uid.clear(); for (uint32_t insn : {0xd5384108U, 0xf9401908U, 0xf9401100U, 0xd65f03c0U}) word(uid, insn); }
            else if (mode == "accessor-symbol-missing") functions.clear();
            else if (mode == "accessor-size-missing") symbol_size_missing = true;
            else if (mode == "accessor-execute-error") symbol_size_fail = true;
            else if (mode == "accessor-size-offset") symbol_offset = 4;
            else if (mode == "accessor-size-overflow") size_override = UINT64_MAX;
            else if (mode == "accessor-read-error") text_read_fail = true;
            else if (mode == "accessor-bad-btf") { open_error = 0; blob[0] ^= 0xff; }
            else assert(false);
            uint32_t value = 999;
            check(is_failed(get_cred_uid_offset(value)) && value == 999);
            check(layout_test::writes == 0); check(legacy == 0); check(text_outside == 0);
            if (mode == "accessor-bad-btf" || mode == "accessor-partial-btf-start" || mode == "accessor-partial-btf-stop")
                check(text_reads == 0 && executions == 0);
        }
    } else if (mode == "real") {
        assert(argc == 3);
        std::ifstream input(argv[2], std::ios::binary);
        check(input.good());
        set_blob(std::vector<uint8_t>(std::istreambuf_iterator<char>(input), {}));
        auto expected = maplesu::module_policy::describe_task_credential_layout(blob,
            {"real_cred", "cred"}, {"uid", "euid", "cap_inheritable"});
        const std::vector<KModErr(*)(uint32_t&)> getters{
            get_task_struct_real_cred_offset, get_task_struct_cred_offset, get_cred_uid_offset,
            get_cred_euid_offset, get_cred_cap_inheritable_offset};
        unsigned index = 0;
        for (const auto& type : expected.types) for (const auto& field : type.fields) {
            uint32_t offset = 999;
            check(is_ok(getters.at(index++)(offset)) && offset == field.bit_offset / 8);
            KernelFieldDescription description; bool available = false;
            check(is_ok(maplesu_resolve_btf_field(type.name.c_str(), field.name.c_str(),
                field.bit_size / 8, description, available)) && available);
            check(description.owner_size_bytes == type.size && description.width_bytes == field.bit_size / 8);
            printf("FIELD %s.%s offset=%u width=%u owner=%u source=%s reader=%s parser=%u\n",
                type.name.c_str(), field.name.c_str(), offset, description.width_bytes,
                description.owner_size_bytes, description.source, description.reader, description.parser_version);
        }
        check(index == 5); check(opens == 1); check(lookups == 0); check(reads == 0); clean_readonly();
    } else if (mode == "sysfs") {
        get_five(); clean_readonly(); check(opens == 1); check(lookups == 0); check(reads == 0);
        KernelFieldDescription field; bool available = false;
        check(is_ok(maplesu_resolve_btf_field("cred", "uid", 4, field, available)) && available);
        check(field.offset_bytes == 32 && field.width_bytes == 4 && field.owner_size_bytes == 72);
        check(!strcmp(field.source, "btf") && !strcmp(field.reader, "sysfs") && field.parser_version == 1);
        check(is_failed(maplesu_resolve_btf_field("cred", "uid", 8, field, available)));
        uint32_t value = 0;
        check(is_ok(btf_resolve_member_offset("struct task_struct", "cred", value)) && value == 48);
        check(is_ok(btf_resolve_struct_size("cred", value)) && value == 72);
    } else if (mode == "kernel-symbols") {
        auto f = fixture(); f.strings.resize(150000); set_blob(f.bytes()); open_error = EACCES;
        get_five(); clean_readonly(); check(opens == 1); check(lookups == 2); check(reads == 3);
        KernelFieldDescription field; bool available = false;
        check(is_ok(maplesu_resolve_btf_field("cred", "uid", 4, field, available)) && available);
        check(!strcmp(field.reader, "kernel-symbols"));
    } else if (mode == "field-only") {
        set_blob(fixture(mode).bytes()); uint32_t value = 999;
        check(is_ok(get_cred_euid_offset(value)) && value == 4);
        check(is_ok(get_task_struct_cred_offset(value)) && value == 48);
        check(is_failed(get_task_struct_real_cred_offset(value)) && value == 48);
        clean_readonly();
    } else if (mode == "invalid" || mode == "truncated" || mode == "width" || mode == "bounds" || mode == "ambiguous") {
        set_blob(fixture(mode).bytes());
        if (mode == "invalid") blob[0] ^= 0xff;
        if (mode == "truncated") blob.resize(blob.size() - 1);
        expect_failed_uid(); check(lookups == 0); check(opens == 1); retry_good(); check(opens == 2);
    } else if (mode == "read-error") {
        file_error = true; expect_failed_uid(); check(lookups == 0);
        file_error = false; retry_good(); check(opens == 2);
    } else if (mode == "symbol-missing") {
        open_error = EACCES; lookup_error = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
        KernelFieldDescription field; field.offset_bytes = 777; bool available = true;
        check(is_failed(maplesu_resolve_btf_field("cred", "uid", 4, field, available)) && !available && field.offset_bytes == 777);
        uint32_t value = 0xa5a5a5a5U;
        const auto real_cred_error = get_task_struct_real_cred_offset(value);
        printf("OBSERVED missing-symbol real_cred result=%lld value=%u legacy=%u\n",
               static_cast<long long>(real_cred_error), value, legacy.load());
        fflush(stdout);
        // No BTF/accessor evidence means no offset; the retired positional
        // snapshot must not turn a missing symbol into a guessed credential.
        check(is_failed(real_cred_error) && value == 0xa5a5a5a5U);
        check(is_failed(get_task_struct_cred_offset(value)) && value == 0xa5a5a5a5U);
        check(is_failed(maplesu_find_real_cred_offset(&value)) && value == 0xa5a5a5a5U);
        check(legacy == 0); check(layout_test::writes == 0);
        // Failure must not poison a subsequent lookup when BTF becomes readable.
        open_error = 0; lookup_error = KModErr::OK; retry_good();
    } else if (mode == "symbol-error" || mode == "reverse-range" || mode == "large-range" || mode == "errptr-range" || mode == "kernel-read-failure") {
        open_error = EPERM;
        if (mode == "symbol-error") lookup_error = KModErr::ERR_MODULE_READ_FILE;
        if (mode == "reverse-range") stop = start - 1;
        if (mode == "large-range") stop = start + 64ULL * 1024 * 1024 + 1;
        if (mode == "errptr-range") stop = uint64_t(-22LL);
        if (mode == "kernel-read-failure") {
            auto f = fixture(); f.strings.resize(150000); set_blob(f.bytes()); read_fail_at = 2;
        }
        expect_failed_uid(); lookup_error = KModErr::OK; read_fail_at = 0; retry_good();
    } else if (mode == "concurrent") {
        std::atomic<unsigned> failures{0}; std::vector<std::thread> threads;
        for (unsigned i = 0; i != 32; ++i) threads.emplace_back([&] {
            for (unsigned n = 0; n != 20; ++n) {
                uint32_t value = 0;
                if (is_failed(get_task_struct_real_cred_offset(value)) || value != 16) ++failures;
                if (is_failed(get_task_struct_cred_offset(value)) || value != 48) ++failures;
                if (is_failed(get_cred_uid_offset(value)) || value != 32) ++failures;
                if (is_failed(get_cred_euid_offset(value)) || value != 4) ++failures;
                if (is_failed(get_cred_cap_inheritable_offset(value)) || value != 48) ++failures;
            }
        });
        for (auto& thread : threads) thread.join();
        check(failures == 0); check(opens == 1); clean_readonly();
    } else if (mode.rfind("live-", 0) == 0) {
        setup_live(); uint32_t value = 999;
        if (mode.rfind("live-field-", 0) == 0) {
            test_live_field(mode);
        } else if (mode.rfind("live-name-", 0) == 0) {
            name_fixture = true;
            name_section.resize(256, 0);
            memcpy(name_section.data() + 1, "field", 6);
            std::string requested_name = "field";
            const std::string long_name(400, 'x');
            if (mode == "live-name-offset-wrap" || mode == "live-name-offset-errptr" ||
                mode == "live-name-edge-terminated" || mode == "live-name-edge-unterminated") {
                strings_value = static_cast<uint64_t>(-4095LL) - 17;
                name_section.resize(17);
            }
            if (mode == "live-name-offset-wrap") member_name_offset = 8192;
            else if (mode == "live-name-offset-errptr") member_name_offset = 17;
            else if (mode == "live-name-edge-unterminated")
                std::fill(name_section.begin() + 1, name_section.end(), 'x');
            else if (mode == "live-name-read-error-retry") {
                std::fill(name_section.begin() + 1, name_section.end(), 'x');
                name_fail_at = 2;
            } else if (mode == "live-name-long" || mode == "live-name-long-prefix") {
                name_section.resize(512, 0);
                memcpy(name_section.data() + 1, long_name.c_str(), long_name.size() + 1);
                requested_name = mode == "live-name-long" ? long_name : long_name.substr(0, 256);
            } else if (mode == "live-name-tail-terminated") {
                name_section.resize(7);
            } else if (mode == "live-name-tail-unterminated") {
                name_section.resize(17);
                std::fill(name_section.begin() + 1, name_section.end(), 'x');
                requested_name.assign(16, 'x');
            }
            string_section_size = name_section.size();
            if (mode == "live-name-size-u32-max") string_section_size = UINT32_MAX;
            else if (mode == "live-name-one-byte-empty") string_section_size = 1;
            else if (mode == "live-name-zero-size") string_section_size = 0;
            else if (mode == "live-name-boundary-nonnull") string_max_nonnull = true;
            else if (mode == "live-name-boundary-errptr") string_max_errptr = true;
            else if (mode == "live-name-boundary-mismatch") string_address_mismatch = true;
            else if (mode == "live-name-boundary-error") string_fail_at = 2;
            else if (mode == "live-name-boundary-mid-error") string_fail_at = 3;
            else if (mode == "live-name-boundary-mid-errptr") string_errptr_at = 3;
            else if (mode == "live-name-boundary-wrap") {
                strings_value = static_cast<uint64_t>(-4095LL) - 17;
                string_section_size = 8192;
            }
            const bool success = mode == "live-name-edge-terminated" || mode == "live-name-long" ||
                mode == "live-name-tail-terminated" || mode == "live-name-size-u32-max";
            const bool init_failure = mode == "live-name-zero-size" ||
                mode.rfind("live-name-boundary-", 0) == 0;
            KModErr expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            if (success) expected = KModErr::OK;
            else if (mode == "live-name-read-error-retry") expected = KModErr::ERR_MODULE_READ_FILE;
            else if (mode == "live-name-boundary-error" || mode == "live-name-boundary-mid-error")
                expected = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
            else if (init_failure && mode != "live-name-boundary-nonnull") expected = KModErr::ERR_MODULE_NOT_KADDR;
            const auto error = btf_resolve_member_offset("fixture", requested_name.c_str(), value);
            const unsigned first_init_queries = string_calls;
            check(error == expected);
            check(value == (success ? 12U : 0U));
            check(name_outside == 0);
            if (success || mode == "live-name-long-prefix") {
                const unsigned queries = string_calls;
                check(queries > 1 && queries <= 34);
                check(string_offsets[0] == 0 && string_offsets[1] == UINT32_MAX);
                const char* full_name = mode == "live-name-long-prefix" ? long_name.c_str() : requested_name.c_str();
                check(is_ok(btf_resolve_member_offset("fixture", full_name, value)) && value == 12);
                check(string_calls == queries); check(get_btf_calls == 1);
            } else if (mode == "live-name-one-byte-empty") {
                const unsigned queries = string_calls;
                check(is_ok(live_size(value)) && value == 32);
                check(string_calls == queries); check(name_reads == 0);
            } else {
                member_name_offset = 1;
                name_fail_at = 0;
                string_fail_at = 0;
                string_errptr_at = 0;
                string_max_nonnull = false;
                string_max_errptr = false;
                string_address_mismatch = false;
                if (init_failure) {
                    btf_value = BTF_B;
                    strings_value = STRINGS;
                    string_section_size = name_section.size();
                }
                std::fill(name_section.begin(), name_section.end(), 0);
                memcpy(name_section.data() + 1, "field", 6);
                check(is_ok(btf_resolve_member_offset("fixture", "field", value)) && value == 12);
                check(name_outside == 0);
                if (init_failure) {
                    check(get_btf_calls == 2);
                    check(string_arguments.back() == BTF_B);
                    check(string_calls - first_init_queries <= 34);
                }
            }
            printf("NAME-BOUNDARY first-init-queries=%u total-queries=%u string-length=%llu\n",
                first_init_queries, string_calls.load(), static_cast<unsigned long long>(string_section_size));
        } else if (mode == "live-function-missing") {
            export_symbol::linux_above_5_10_0::function_error = KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
            check(is_ok(live_size(value)) && value == 32); check(variable_reads == 1); check(get_btf_calls == 0);
            check(is_ok(btf_resolve_member_offset("fixture", "field", value)) && value == 12);
        } else if (mode == "live-execute-failure") {
            execution_fail = true;
            check(is_ok(live_size(value)) && value == 32); check(variable_reads == 1); check(get_btf_calls == 1);
        } else if (mode == "live-errptr") {
            btf_value = uint64_t(-22LL);
            check(is_ok(live_size(value)) && value == 32); check(variable_reads == 1);
        } else if (mode == "live-variable-null" || mode == "live-variable-address-errptr") {
            btf_value = uint64_t(-22LL); variable_address = mode == "live-variable-null" ? 0 : uint64_t(-22LL);
            check(is_failed(live_size(value)) && value == 0); check(reads == 0);
            variable_address = VARIABLE; btf_value = BTF_B; variable_value = BTF_B;
            check(is_ok(live_size(value)) && value == 32);
        } else if (mode == "live-variable-errptr") {
            btf_value = uint64_t(-22LL); variable_value = uint64_t(-22LL); live_retry_after_failure(); check(variable_reads == 1);
        } else if (mode == "live-strings-failure") {
            strings_fail = true; live_retry_after_failure(); check(get_btf_calls == 2);
        } else if (mode == "live-strings-errptr") {
            strings_value = uint64_t(-22LL); live_retry_after_failure(); check(get_btf_calls == 2);
        } else if (mode == "live-nonempty-strings") {
            first_string_nonzero = true; live_retry_after_failure(); check(get_btf_calls == 2);
        } else if (mode == "live-type-errptr") {
            type_value = uint64_t(-22LL);
            check(is_failed(live_size(value)) && value == 0); type_value = TYPE;
            check(is_ok(live_size(value)) && value == 32); check(get_btf_calls == 1);
        } else assert(false);
        check(layout_test::writes == 0); check(legacy == 0);
    } else assert(false);
    printf("PASS %s: %u checks; opens=%u symbols=%u reads=%u exec=%u candidate-writes=%u legacy-snapshot=%u\n",
           mode.c_str(), checks, opens.load(), lookups.load(), reads.load(), executions.load(), layout_test::writes.load(), legacy.load());
}
#endif
