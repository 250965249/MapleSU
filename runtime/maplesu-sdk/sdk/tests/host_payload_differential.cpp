// Host differential tests: production payload code vs the reference behaviour.
//
// The payload programs are AArch64 Android executables and cannot be executed on
// the build host, but the parts of their behaviour that define the contract are
// host-runnable.  For each of those parts this harness runs the production port
// and the reference implementation side by side on the same input and compares
// the observable results:
//
//   su            production CLI parser  vs  the open-edition su client parser
//                 (tests/host_reference/reference_su.h is that source, verbatim)
//   resetprop     production command logic  vs  the resetprop applet logic from
//                 Magisk v30.7 cli.rs (tests/host_reference/reference_resetprop.h),
//                 both driven through the same simulated property backend, comparing
//                 the full platform-operation trace, stdout and resulting state
//
// Everything that needs a real device (kernel root handshake, exec, Android
// property area, /data/property publication, module ELF hosting) is reported as
// not-run with the reason.  Results are also written as JSON for PAYLOADS.md.
//
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include "payload_support.h"
#include "reference_resetprop.h"
#include "reference_su.h"
#include "resetprop/src/cli_contract.h"
#include "resetprop/src/persist_proto.h"
#include "resetprop/src/prop_backend.h"
#include "resetprop/src/prop_command.h"
#include "su/src/cli_contract.h"

namespace {

int g_checks = 0;
int g_failures = 0;
std::vector<std::string> g_rows;

void check(bool condition, const std::string& label) {
    ++g_checks;
    g_rows.push_back((condition ? "PASS " : "DIFF ") + label);
    std::printf("[check] %s %s\n", condition ? "PASS" : "DIFF", label.c_str());
    if (!condition) {
        ++g_failures;
        std::printf("FAIL %s\n", label.c_str());
    }
}

// ---------------------------------------------------------------------------
// stdout capture (the payload programs print their results on stdout)
// ---------------------------------------------------------------------------
#if defined(_WIN32)
#define maplesu_dup _dup
#define maplesu_dup2 _dup2
#define maplesu_close _close
#define maplesu_fileno _fileno
#else
#define maplesu_dup dup
#define maplesu_dup2 dup2
#define maplesu_close close
#define maplesu_fileno fileno
#endif

std::string capture_stdout(const std::function<void()>& body) {
    std::fflush(stdout);
    const int saved = maplesu_dup(1);
    std::FILE* temporary = std::tmpfile();
    if (temporary == nullptr) {
        body();
        return {};
    }
    maplesu_dup2(maplesu_fileno(temporary), 1);
    body();
    std::fflush(stdout);
    maplesu_dup2(saved, 1);
    maplesu_close(saved);
    std::string output;
    std::fseek(temporary, 0, SEEK_SET);
    char buffer[512];
    while (true) {
        const size_t read = std::fread(buffer, 1, sizeof(buffer), temporary);
        if (read == 0) break;
        output.append(buffer, read);
    }
    std::fclose(temporary);
    return output;
}

// ---------------------------------------------------------------------------
// simulated property platform used by both resetprop implementations
// ---------------------------------------------------------------------------
class FakePropertyBackend final : public maplesu::payload::resetprop::PropertyBackend {
public:
    struct Entry {
        std::string value;
        uint32_t serial = 1;
        bool is_long = false;
        maplesu::payload::resetprop::PropInfo info{};
        std::string context = "u:object_r:build_prop:s0";
    };

    mutable std::vector<std::string> trace;

    void seed(const std::string& key, const std::string& value, bool is_long = false) {
        Entry& entry = entries_[key];
        entry.value = value;
        entry.is_long = is_long;
        entry.info.opaque = next_opaque_++;
        entry.info.serial = entry.serial;
        by_opaque_[entry.info.opaque] = &entry;
    }

    void seed_persistent(const std::string& key, const std::string& value) {
        persistent_[key] = value;
    }

    std::string state_dump() const {
        std::string dump = "props:";
        for (const auto& item : entries_) {
            dump += "[" + item.first + "=" + item.second.value +
                    (item.second.is_long ? "(long)" : "") + "]";
        }
        dump += " persist:";
        for (const auto& item : persistent_) dump += "[" + item.first + "=" + item.second + "]";
        return dump;
    }

    std::string trace_dump() const {
        std::string dump;
        for (const auto& step : trace) dump += step + ";";
        return dump;
    }

    // PropertyBackend
    const maplesu::payload::resetprop::PropInfo* find(const char* key) const override {
        trace.emplace_back(std::string("find:") + key);
        const auto found = entries_.find(key);
        if (found == entries_.end()) return nullptr;
        return &found->second.info;
    }
    maplesu::payload::resetprop::PropInfo* find_mutable(const char* key) override {
        trace.emplace_back(std::string("find_mutable:") + key);
        const auto found = entries_.find(key);
        if (found == entries_.end()) return nullptr;
        return &found->second.info;
    }
    bool read(const maplesu::payload::resetprop::PropInfo* info, std::string& key,
              std::string& value, uint32_t& serial) const override {
        trace.emplace_back("read:" + opaque_key(info));
        const Entry* entry = lookup(info);
        if (entry == nullptr) return false;
        key = opaque_key(info);
        value = entry->value;
        serial = entry->serial;
        return true;
    }
    bool is_long(const maplesu::payload::resetprop::PropInfo* info) const override {
        trace.emplace_back("is_long:" + opaque_key(info));
        const Entry* entry = lookup(info);
        return entry != nullptr && entry->is_long;
    }
    void for_each(maplesu::payload::resetprop::PropForeachCallback callback,
                  void* cookie) const override {
        trace.emplace_back("for_each");
        for (const auto& item : entries_) callback(&item.second.info, cookie);
    }
    bool set(const char* key, const char* value) override {
        trace.emplace_back(std::string("set:") + key + "=" + value);
        Entry& entry = entries_[key];
        if (entry.info.opaque == 0) {
            entry.info.opaque = next_opaque_++;
            by_opaque_[entry.info.opaque] = &entry;
        }
        entry.value = value;
        entry.serial++;
        entry.info.serial = entry.serial;
        return true;
    }
    bool update(maplesu::payload::resetprop::PropInfo* info, const char* value,
                size_t length) override {
        trace.emplace_back("update:" + opaque_key(info) + "=" +
                           std::string(value, length));
        Entry* entry = lookup(info);
        if (entry == nullptr) return false;
        entry->value.assign(value, length);
        entry->serial++;
        entry->info.serial = entry->serial;
        return true;
    }
    bool add(const char* key, const char* value, size_t length) override {
        trace.emplace_back(std::string("add:") + key + "=" + std::string(value, length));
        Entry& entry = entries_[key];
        if (entry.info.opaque == 0) {
            entry.info.opaque = next_opaque_++;
            by_opaque_[entry.info.opaque] = &entry;
        }
        entry.value.assign(value, length);
        entry.serial++;
        entry.info.serial = entry.serial;
        return true;
    }
    bool remove(const char* key, bool prune) override {
        trace.emplace_back(std::string("remove:") + key + (prune ? ":prune" : ":keep"));
        const auto found = entries_.find(key);
        if (found == entries_.end()) return false;
        by_opaque_.erase(found->second.info.opaque);
        entries_.erase(found);
        return true;
    }
    const char* context(const char* key) const override {
        trace.emplace_back(std::string("context:") + key);
        const auto found = entries_.find(key);
        return found == entries_.end() ? nullptr : found->second.context.c_str();
    }
    uint32_t area_serial() const override {
        trace.emplace_back("area_serial");
        return 1;
    }
    bool wait_for_change(const maplesu::payload::resetprop::PropInfo* info,
                         uint32_t old_serial, uint32_t& new_serial) const override {
        trace.emplace_back("wait:" + opaque_key(info));
        new_serial = old_serial;
        return false;   // host model never blocks
    }
    bool persist_get(const std::string& key, std::string& value) override {
        trace.emplace_back("persist_get:" + key);
        const auto found = persistent_.find(key);
        if (found == persistent_.end()) return false;
        value = found->second;
        return true;
    }
    bool persist_set(const std::string& key, const std::string& value) override {
        trace.emplace_back("persist_set:" + key + "=" + value);
        persistent_[key] = value;
        return true;
    }
    bool persist_erase(const std::string& key) override {
        trace.emplace_back("persist_erase:" + key);
        return persistent_.erase(key) != 0;
    }
    bool persist_all(
        std::vector<maplesu::payload::resetprop::PersistentRecord>& records) override {
        trace.emplace_back("persist_all");
        for (const auto& item : persistent_) {
            maplesu::payload::resetprop::PersistentRecord record;
            record.has_name = true;
            record.has_value = true;
            record.name = item.first;
            record.value = item.second;
            records.push_back(record);
        }
        return true;
    }

private:
    std::string opaque_key(const maplesu::payload::resetprop::PropInfo* info) const {
        if (info == nullptr) return "<wait-all>";
        const auto found = by_opaque_.find(info->opaque);
        if (found == by_opaque_.end()) return "<unknown>";
        for (const auto& item : entries_) {
            if (&item.second == found->second) return item.first;
        }
        return "<unknown>";
    }
    Entry* lookup(const maplesu::payload::resetprop::PropInfo* info) {
        if (info == nullptr) return nullptr;
        const auto found = by_opaque_.find(info->opaque);
        return found == by_opaque_.end() ? nullptr : found->second;
    }
    const Entry* lookup(const maplesu::payload::resetprop::PropInfo* info) const {
        return const_cast<FakePropertyBackend*>(this)->lookup(info);
    }

    std::map<std::string, Entry> entries_;
    std::map<uint32_t, Entry*> by_opaque_;
    std::map<std::string, std::string> persistent_;
    uint32_t next_opaque_ = 100;
};

FakePropertyBackend make_seeded_backend() {
    FakePropertyBackend backend;
    backend.seed("ro.build.type", "userdebug");
    backend.seed("ro.long", std::string(100, 'x'), /*is_long=*/true);
    backend.seed("persist.sys.test", "1");
    backend.seed("persist.sys.other", "2");
    backend.seed("vendor.debug", "off");
    backend.seed_persistent("persist.sys.test", "1");
    backend.seed_persistent("persist.sys.other", "2");
    backend.seed_persistent("persist.extra", "3");
    return backend;
}

// ---------------------------------------------------------------------------
// su: production parser vs reference parser
// ---------------------------------------------------------------------------
void run_su_differential() {
    std::printf("[section] su differential\n");
    const std::vector<std::vector<std::string>> cases = {
        {"su"},
        {"su", "-h"},
        {"su", "--help"},
        {"su", "-v"},
        {"su", "--version"},
        {"su", "-V"},
        {"su", "-l"},
        {"su", "-p"},
        {"su", "-m"},
        {"su", "--preserve-environment"},
        {"su", "-s", "/system/bin/bash"},
        {"su", "--shell", "/x/sh"},
        {"su", "-mm"},
        {"su", "-M"},
        {"su", "--mount-master"},
        {"su", "-cn"},
        {"su", "-z", "u:r:su:s0"},
        {"su", "-", "2000"},
        {"su", "2000", "id"},
        {"su", "-c", "id -u"},
        {"su", "-c", "id", "-u"},
        {"su", "--bogus"},
        {"su", "-l", "-c", "whoami"},
        {"su", "-mp", "0"},
        {"su", "-l", "-", "0"},
        {"su", "shell"},
        {"su", "-s", "/x/sh", "2000", "-c", "id"},
    };

    for (const auto& words : cases) {
        // Fresh mutable buffers for each implementation: both rewrite -cn/-mm.
        auto build_argv = [](const std::vector<std::string>& input) {
            std::vector<std::string> copy = input;
            std::vector<char*> argv;
            for (auto& word : copy) argv.push_back(word.data());
            return std::make_pair(std::move(copy), std::move(argv));
        };

        auto ours_words = build_argv(words);
        const auto ours = maplesu::payload::su::parse_su_args(
            static_cast<int>(ours_words.second.size()), ours_words.second.data());

        auto reference_words = build_argv(words);
        const auto reference = reference::parse(
            static_cast<int>(reference_words.second.size()), reference_words.second.data());

        // Map the reference's exit-kind to our parse result kind.
        const bool ours_help = ours.kind == maplesu::payload::su::SuParseKind::Help;
        const bool ours_version = ours.kind == maplesu::payload::su::SuParseKind::Version;
        const bool ours_code = ours.kind == maplesu::payload::su::SuParseKind::VersionCode;
        const bool ours_error = ours.failed;
        const bool ref_help = reference.kind == reference::SuKind::Help;
        const bool ref_version = reference.kind == reference::SuKind::Version;
        const bool ref_code = reference.kind == reference::SuKind::VersionCode;
        const bool ref_error = reference.kind == reference::SuKind::Error;

        std::string label;
        for (size_t index = 1; index < words.size(); ++index) {
            label += " " + words[index];
        }
        if (label.empty()) label = " (bare)";

        const bool same_mode = ours_help == ref_help && ours_version == ref_version &&
                               ours_code == ref_code && ours_error == ref_error &&
                               !(ours_error && ref_error ? false : false);
        const bool same_fields =
            ours.request.login == reference.request.login &&
            ours.request.keepenv == reference.request.keepenv &&
            ours.request.mount_master == reference.request.mount_master &&
            std::strcmp(ours.request.shell, reference.request.shell.c_str()) == 0 &&
            std::strcmp(ours.request.command, reference.request.command.c_str()) == 0 &&
            std::strcmp(ours.request.context, reference.request.context.c_str()) == 0 &&
            ours.first_positional == reference.first_positional;
        check(same_mode, "su mode" + label);
        check(same_fields, "su request fields" + label);

    }

    // The usage text itself must be identical to the reference client's.
    std::string ours_usage;
    {
        const std::string program = "su";
        (void)program;
        std::FILE* temporary = std::tmpfile();
        if (temporary != nullptr) {
            // print_usage takes a FILE*; capture the text once.
            std::fflush(stdout);
            maplesu::payload::su::print_usage(temporary);
            std::fseek(temporary, 0, SEEK_SET);
            char buffer[512];
            while (true) {
                const size_t read = std::fread(buffer, 1, sizeof(buffer), temporary);
                if (read == 0) break;
                ours_usage.append(buffer, read);
            }
            std::fclose(temporary);
        }
    }
    check(ours_usage == reference::usage_text(), "su usage text identical to reference");
    check(std::string(maplesu::payload::su::kRootVersion) ==
              std::string(reference::kRootVersion),
          "su version string identical to reference");
    check(maplesu::payload::su::kRootVerCode == reference::kRootVerCode,
          "su version code identical to reference");
}

// ---------------------------------------------------------------------------
// resetprop: production command logic vs reference applet logic
// ---------------------------------------------------------------------------
struct ResetpropCase {
    std::string name;
    std::vector<std::string> argv;
};

void run_resetprop_differential() {
    std::printf("[section] resetprop differential\n");

    // A property file shared by the -f cases; both implementations read it.
    const std::filesystem::path property_file =
        std::filesystem::temp_directory_path() / "maplesu-payload-props.txt";
    {
        std::FILE* file = std::fopen(property_file.string().c_str(), "wb");
        if (file != nullptr) {
            std::fputs("  new.prop = hello world  \n", file);
            std::fputs("# comment line\n", file);
            std::fputs("persist.sys.other=9\n", file);
            std::fputs("broken line without separator\n", file);
            std::fputs("vendor.debug = on = extra\n", file);
            std::fclose(file);
        }
    }

    const std::vector<ResetpropCase> cases = {
        {"print-all", {"resetprop"}},
        {"print-all-p", {"resetprop", "-p"}},
        {"print-all-P", {"resetprop", "-P"}},
        {"print-all-Z", {"resetprop", "-Z"}},
        {"get", {"resetprop", "ro.build.type"}},
        {"get-persist", {"resetprop", "persist.sys.test"}},
        {"get-persist-p", {"resetprop", "-p", "persist.sys.test"}},
        {"get-persist-P", {"resetprop", "-P", "persist.sys.test"}},
        {"get-missing", {"resetprop", "does.not.exist"}},
        {"get-context", {"resetprop", "-Z", "ro.build.type"}},
        {"set-service", {"resetprop", "vendor.debug", "on"}},
        {"set-service-new", {"resetprop", "new.property", "value"}},
        {"set-bypass", {"resetprop", "-n", "vendor.debug", "on"}},
        {"set-bypass-new", {"resetprop", "-n", "new.property", "value"}},
        {"set-ro", {"resetprop", "ro.build.type", "eng"}},
        {"set-ro-long", {"resetprop", "-n", "ro.long", std::string(120, 'y')}},
        {"set-persist-bypass", {"resetprop", "-n", "-p", "persist.sys.test", "7"}},
        {"set-persist-service", {"resetprop", "-p", "persist.sys.test", "7"}},
        {"delete", {"resetprop", "-d", "vendor.debug"}},
        {"delete-persist", {"resetprop", "-p", "-d", "persist.sys.test"}},
        {"delete-missing", {"resetprop", "-d", "does.not.exist"}},
        {"wait-exists", {"resetprop", "-w", "ro.build.type"}},
        {"wait-value-differs", {"resetprop", "-w", "ro.build.type", "USERDEBUG"}},
        {"load-file", {"resetprop", "-f", property_file.string()}},
        {"load-file-bypass", {"resetprop", "-n", "-f", property_file.string()}},
    };

    for (const auto& test : cases) {
        std::vector<std::string> words = test.argv;
        // argv[0] for both programs is the program name; the file path is a
        // normal positional for -f.
        std::vector<char*> raw_argv;
        raw_argv.reserve(words.size());
        for (auto& word : words) raw_argv.push_back(word.data());

        const auto parsed = maplesu::payload::resetprop::parse_cli(
            static_cast<int>(raw_argv.size()), raw_argv.data());
        if (parsed.kind != maplesu::payload::resetprop::ParseKind::Run) {
            check(false, "resetprop case rejected by our parser: " + test.name);
            continue;
        }

        // Production implementation.
        FakePropertyBackend ours_backend = make_seeded_backend();
        bool ours_ok = false;
        std::string ours_output;
        {
            maplesu::payload::resetprop::ResetProp command(parsed.options, &ours_backend);
            ours_output = capture_stdout([&]() { ours_ok = command.run(); });
        }

        // Reference implementation on an identically seeded backend.
        FakePropertyBackend reference_backend = make_seeded_backend();
        bool reference_ok = false;
        std::string reference_output;
        {
            std::FILE* sink = std::tmpfile();
            reference_ok = reference_resetprop::run(parsed.options, reference_backend,
                                                    sink != nullptr ? sink : stdout);
            if (sink != nullptr) {
                std::fseek(sink, 0, SEEK_SET);
                char buffer[512];
                while (true) {
                    const size_t read = std::fread(buffer, 1, sizeof(buffer), sink);
                    if (read == 0) break;
                    reference_output.append(buffer, read);
                }
                std::fclose(sink);
            }
        }

        check(ours_ok == reference_ok, "resetprop exit status: " + test.name);
        check(ours_output == reference_output,
              "resetprop stdout: " + test.name);
        check(ours_backend.trace == reference_backend.trace,
              "resetprop operation trace: " + test.name);
        check(ours_backend.state_dump() == reference_backend.state_dump(),
              "resetprop resulting state: " + test.name);
    }

    // The usage text must be identical to the reference applet's text.
    const std::string ours_usage =
        maplesu::payload::resetprop::usage_text("resetprop");
    check(ours_usage == reference_resetprop::usage_text("resetprop"),
          "resetprop usage text identical to reference");

    std::error_code ignored;
    std::filesystem::remove(property_file, ignored);
}

}  // namespace

// The production command layer defaults to the Android platform backend; the host
// differential run always injects an explicit backend, so this definition exists
// only to satisfy the link and is never observed by a test case.
namespace maplesu::payload::resetprop {
PropertyBackend& android_property_backend() {
    static FakePropertyBackend host_stub;
    return host_stub;
}
}  // namespace maplesu::payload::resetprop

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    run_su_differential();
    run_resetprop_differential();
    std::printf("\n%d check(s), %d failure(s)\n", g_checks, g_failures);
    struct NotRun {
        const char* item;
        const char* reason;
    };
    static const NotRun kNotRun[] = {
        {"su root handshake + exec",
         "needs the kernel module root hook and a real login shell; the process "
         "identity and exec contract are documented instead"},
        {"resetprop Android property area",
         "needs a device property area (/dev/__properties__ + property_service)"},
        {"resetprop /data/property publication",
         "needs an Android /data/property directory and its SELinux labels"},
        {"resetprop interactive wait blocking",
         "the reference blocks on the platform wait primitive; a host model cannot "
         "reproduce blocking without the real property area"},
        {"webui_loader module hosting / launch URL",
         "needs the kernel-module kit to create the session, a module ELF and the "
         "Android activity starter"},
        {"webui_loader parent watchdog",
         "needs POSIX getppid/kill polling; the Windows host has no equivalent"},
    };
    std::printf("\nnot-run items:\n");
    for (const auto& item : kNotRun) {
        std::printf("  - %s: %s\n", item.item, item.reason);
    }
    return g_failures == 0 ? 0 : 1;
}
