#ifndef SOURCE_UNDER_TEST
#define SOURCE_UNDER_TEST "../ultra/modules/module_control.cpp"
#endif
#include SOURCE_UNDER_TEST
#include <cstdio>
#include <filesystem>
#include <sys/mman.h>

namespace fs = std::filesystem;
static std::string fixture;
static std::vector<maplesu::sdk::module_record> records;
static unsigned cases, failures;
static constexpr const char* key = "0123456789abcdef0123456789abcdef";
extern "C" void maplesu_system_directory(std::string* out) { *out = fixture; }
extern "C" void maplesu_installed_helper_path(std::string* out) { *out = fixture + "/helper"; }
namespace default_modules::module_root { KModErr set_current_root(bool) { return KModErr::OK; } }
namespace maplesu::sdk {
KModErr get_root(const char*) { return KModErr::OK; }
MapleSUEnvState get_maplesu::sdkironment_state(const char*) { return MapleSUEnvState::Running; }
KModErr unsafe_get_all_modules(std::vector<module_record>& out) { out = records; return KModErr::OK; }
}
static void check(bool passed, const char* label, size_t length = 0) {
    ++cases;
    if (!passed) { ++failures; std::printf("FAIL %s length=%zu\n", label, length); }
}
static maplesu::sdk::module_record record(const std::string& id) {
    maplesu::sdk::module_record row{};
    memcpy(row.desc.id32, id.data(), id.size());
    row.state = maplesu::sdk::ModuleRunState::Running;
    return row;
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    char directory[] = "/tmp/maplesu-control-id-XXXXXX";
    const auto created = mkdtemp(directory);
    if (!created) return 2;
    fixture = created;
    fs::create_directories(fixture + "/modules");
    fs::copy_file(argv[1], fixture + "/helper");
    const std::vector<std::string> valid = {"a", "p0_probe", "com.module.test", std::string(32, 'z'),
        std::string(33, 'x'), std::string(255, 'x'), std::string(1023, 'x'), u8"模块", u8"module😀",
        "module with space", "module:colon", "module\\backslash"};
    for (const auto& id : valid) {
        check(id_valid(id.c_str()), "admission", id.size());
        records.clear();
        maplesu::ModuleControlState out;
        check(maplesu::get_module_control(key, id.c_str(), out) == maplesu::MODULE_CONTROL_NOT_FOUND,
              "valid missing record", id.size());
        if (id.size() > 255) continue;  // The real filesystem has a separate NAME_MAX limit.
        fs::create_directories(fixture + "/modules/" + id);
        records = {record(id)};
        check(maplesu::get_module_control(key, id.c_str(), out) == 0 && out.enabled,
              "exact record read", id.size());
        check(maplesu::set_module_enabled(key, id.c_str(), false, out) == 0 && !out.enabled && out.needsReboot,
              "persist and readback", id.size());
        const auto replies = maplesu::get_module_controls(key, records);
        check(replies.size() == 1 && replies[0].error == 0 && !replies[0].state.enabled,
              "list record read", id.size());
        records.push_back(records.front());
        check(maplesu::get_module_control(key, id.c_str(), out) == maplesu::MODULE_CONTROL_IO,
              "duplicate full identity", id.size());
    }
    for (const auto& id : std::vector<std::string>{"", ".", "..", "a/b", "../bad", std::string(1024, 'x')}) {
        check(!id_valid(id.c_str()), "invalid admission", id.size());
        maplesu::ModuleControlState out;
        check(maplesu::get_module_control(key, id.c_str(), out) == maplesu::MODULE_CONTROL_INVALID_ID,
              "invalid public read", id.size());
    }
    check(!id_valid(nullptr), "null id");
    const size_t page = sysconf(_SC_PAGESIZE);
    void* guarded = mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guarded == MAP_FAILED || mprotect(static_cast<char*>(guarded) + page, page, PROT_NONE)) return 2;
    char* unterminated = static_cast<char*>(guarded) + page - 1024;
    memset(unterminated, 'x', 1024);
    check(!id_valid(unterminated), "bounded nonterminated descriptor");
    maplesu::sdk::module_record malformed{};
    memcpy(malformed.desc.id32, unterminated, 1024);
    const std::string short_id(32, 'z'), long_id(33, 'z');
    fs::create_directories(fixture + "/modules/" + short_id);
    fs::create_directories(fixture + "/modules/" + long_id);
    records = {malformed, record(long_id), record(short_id)};
    maplesu::ModuleControlState out;
    check(maplesu::get_module_control(key, short_id.c_str(), out) == 0,
          "same 32 byte prefix matches short exact record");
    check(maplesu::get_module_control(key, long_id.c_str(), out) == 0,
          "same 32 byte prefix matches long exact record");
    records = {malformed};
    check(maplesu::get_module_control(key, short_id.c_str(), out) == maplesu::MODULE_CONTROL_NOT_FOUND,
          "unterminated record is not a prefix match");
    munmap(guarded, page * 2);
    fs::remove_all(fixture);
    std::printf("CONTROL_ID_CASES %u FAILURES %u\n", cases, failures);
    return failures != 0;
}
