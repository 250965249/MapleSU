#include "module_runtime.h"
#include "module_state_private.h"
#include "maplesu_module_install_callback_private.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/wait.h>

extern "C" int maplesu_skip_disabled(const char*);
namespace maplesu::sdk {
KModErr unsafe_get_all_modules(std::vector<module_record>&);
KModErr parse_module_meta_from_elf_bytes(const std::vector<uint8_t>&, module_desc&);
}

#ifndef MAPLESU_MODULE_DATA_ROOT
#define MAPLESU_MODULE_DATA_ROOT "/data"
#endif

namespace maplesu::module_runtime {
namespace {
using List = module_state::List;
bool contains(const std::vector<std::string>& ids, const std::string& id) {
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}
void remember(KModErr error, KModErr& first) {
    if (is_ok(first) && is_failed(error)) first = error;
}
bool transfer(int fd, void* buffer, size_t length, bool writing) {
    auto* bytes = static_cast<unsigned char*>(buffer);
    while (length) {
        ssize_t count = writing ? write(fd, bytes, length) : read(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        bytes += count;
        length -= static_cast<size_t>(count);
    }
    return true;
}
void setup(const std::string& directory, const char* id) {
    if (setsid() < 0) setpgid(0, 0);
    signal(SIGPIPE, SIG_IGN);
    const int ns = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (ns >= 0) {
        const int joined = setns(ns, CLONE_NEWNS);
        close(ns);
        if (joined == 0) unshare(CLONE_NEWNS);
    }
    (void)cg_v2::migrate_self_to_root();
    (void)cg_v1::migrate_self_threads_v1();
    (void)selinux_procattr::setcon("u:r:shell:s0");
    (void)selinux_procattr::setexeccon("u:r:shell:s0");
    prctl(PR_SET_NAME, id, 0, 0, 0);
    std::string component = directory;
    while (component.size() > 1 && component.back() == '/') component.pop_back();
    const char* old = getenv("PATH");
    std::string path = old ? old : "";
    bool found = false;
    for (size_t at = 0; at <= path.size();) {
        size_t end = path.find(':', at);
        if (end == std::string::npos) end = path.size();
        if (path.substr(at, end - at) == component) { found = true; break; }
        at = end + 1;
    }
    if (!found) setenv("PATH", (component + (path.empty() ? "" : ":" + path)).c_str(), 1);
}
Result validate(const maplesu::sdk::module_desc& desc, const char* key,
                const maplesu::sdk::MapleSUSdkVersion& current) {
    if (!memchr(desc.id32, 0, sizeof(desc.id32)) || !desc.id32[0])
        return {KModErr::ERR_MODULE_PARAM, 0, false};
    const std::string directory = private_directory(key, desc.id32);
    if (maplesu_skip_disabled(directory.c_str()))
        return {static_cast<KModErr>(-20150), 0, true};
    // This compatibility floor comes from the existing SDK installer contract.
    constexpr maplesu::sdk::MapleSUSdkVersion minimum{4, 0, 5};
    if (current < desc.min_sdk_ver) return {KModErr::ERR_MODULE_REQUIRE_MIN_SDK, 0, false};
    if (desc.min_sdk_ver < minimum) return {KModErr::ERR_MODULE_SDK_TOO_OLD, 0, false};
    return {};
}
KModErr publish(const std::string& id, const Result& result) {
    const bool success = is_ok(result.loader) && result.entry == 0;
    RETURN_IF_ERROR(module_state::remove(success ? List::Abnormal : List::Running, id));
    return module_state::add(success ? List::Running : List::Abnormal, id);
}
}

std::string system_directory(const char* key) {
    if (!key || strnlen(key, 49) != 48) return {};
    return std::string(MAPLESU_MODULE_DATA_ROOT) + "/" + std::string(key, 16) + key[0] + "/";
}
std::string private_directory(const char* key, const char* id) {
    const std::string root = system_directory(key);
    if (root.empty() || !id || !*id) return {};
    return root + "modules/" + id + "/";
}

Result execute(const maplesu::sdk::module_desc& desc, const char* key) {
    const std::string directory = private_directory(key, desc.id32);
    if (directory.empty()) return {KModErr::ERR_MODULE_PARAM, 0, false};
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) return {KModErr::ERR_MODULE_OPEN_FILE, 0, false};
    fflush(nullptr);
    const pid_t child = fork();
    if (child < 0) {
        close(pipe_fds[0]); close(pipe_fds[1]);
        return {KModErr::ERR_MODULE_OPEN_FILE, 0, false};
    }
    if (child == 0) {
        close(pipe_fds[0]);
        Result result;
        try {
            const std::string override_path = system_directory(key) + "modules_new_state/" + desc.id32;
            if (unlink(override_path.c_str()) != 0 && errno != ENOENT)
                result.loader = KModErr::ERR_MODULE_DEL_FILE;
            setup(directory, desc.id32);
            if (is_ok(result.loader) && chdir(directory.c_str()) != 0)
                result.loader = KModErr::ERR_MODULE_OPEN_DIR;
            void* image = nullptr;
            if (is_ok(result.loader)) {
                image = dlopen((directory + desc.id32).c_str(), RTLD_NOW | RTLD_LOCAL);
                if (!image) result.loader = KModErr::ERR_MODULE_DLOPEN;
            }
            if (image) {
                using Entry = int (*)(const char*, const char*);
                auto entry = reinterpret_cast<Entry>(dlsym(image, kEntrySymbol));
                if (!entry) result.loader = KModErr::ERR_MODULE_DLSYM;
                else result.entry = entry(key, directory.c_str());
                dlclose(image);
            }
        } catch (...) { result.loader = KModErr::ERR_MODULE_DLOPEN; }
        int64_t loader = static_cast<int64_t>(result.loader);
        const bool sent = transfer(pipe_fds[1], &loader, sizeof(loader), true) &&
                          transfer(pipe_fds[1], &result.entry, sizeof(result.entry), true);
        close(pipe_fds[1]);
        fflush(nullptr);
        _exit(sent ? 0 : 125);
    }
    close(pipe_fds[1]);
    Result result;
    int64_t loader = 0;
    if (!transfer(pipe_fds[0], &loader, sizeof(loader), false))
        result.loader = KModErr::ERR_READ_CHILD_ERRCODE;
    else {
        result.loader = static_cast<KModErr>(loader);
        if (!transfer(pipe_fds[0], &result.entry, sizeof(result.entry), false))
            result.loader = KModErr::ERR_READ_CHILD_INT;
    }
    close(pipe_fds[0]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (is_ok(result.loader)) result.loader = KModErr::ERR_READ_CHILD_ERRCODE;
    }
    return result;
}

KModErr run_batch(const char* key, const maplesu::sdk::MapleSUSdkVersion& version,
                 std::vector<Record>& results) {
    results.clear();
    RETURN_IF_ERROR(module_state::save(List::Running, {}));
    RETURN_IF_ERROR(module_state::save(List::Abnormal, {}));
    RETURN_IF_ERROR(module_state::save(List::Removed, {}));
    std::vector<std::string> pending, finished;
    RETURN_IF_ERROR(module_state::read(List::PendingRunOnce, pending));
    RETURN_IF_ERROR(module_state::read(List::FinishedRunOnce, finished));
    std::vector<std::string> consumed = finished;
    for (const auto& id : pending) if (!contains(consumed, id)) consumed.push_back(id);
    // Persist consumption before clearing requests: a crash must not replay a run-once module.
    RETURN_IF_ERROR(module_state::save(List::FinishedRunOnce, consumed));
    RETURN_IF_ERROR(module_state::save(List::PendingRunOnce, {}));
    std::vector<maplesu::sdk::module_record> modules;
    const KModErr enumerated = maplesu::sdk::unsafe_get_all_modules(modules);
    if (enumerated == KModErr::ERR_MODULE_OPEN_DIR &&
        access((system_directory(key) + "modules").c_str(), F_OK) != 0 && errno == ENOENT)
        return KModErr::OK;
    if (is_failed(enumerated)) return enumerated;
    KModErr first = KModErr::OK;
    for (const auto& module : modules) {
        Result result = validate(module.desc, key, version);
        if (is_ok(result.loader) && contains(finished, module.desc.id32)) result.skipped = true;
        if (is_ok(result.loader) && !result.skipped) result = execute(module.desc, key);
        if (!result.skipped) remember(publish(module.desc.id32, result), first);
        fprintf(stderr, "[helper] module=%s loader=%lld main=%d skipped=%d\n", module.desc.id32,
                static_cast<long long>(result.loader), result.entry, result.skipped);
        results.push_back({module.desc.id32, result});
    }
    return first;
}

Result run_single(const char* key, const char* id,
                  const maplesu::sdk::MapleSUSdkVersion& version) {
    const std::string directory = private_directory(key, id);
    if (directory.empty()) return {KModErr::ERR_MODULE_PARAM, 0, false};
    std::ifstream stream(directory + id, std::ios::binary);
    if (!stream) return {KModErr::ERR_MODULE_READ_FILE, 0, false};
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(stream), {}};
    if (stream.bad()) return {KModErr::ERR_MODULE_READ_FILE, 0, false};
    maplesu::sdk::module_desc desc;
    KModErr error = maplesu::sdk::parse_module_meta_from_elf_bytes(bytes, desc);
    if (is_failed(error)) return {error, 0, false};
    if (!memchr(desc.id32, 0, sizeof(desc.id32)) || strcmp(desc.id32, id) != 0)
        return {KModErr::ERR_MODULE_PARAM, 0, false};
    Result result = validate(desc, key, version);
    if (is_failed(result.loader)) return result;
    std::vector<std::string> pending, finished;
    error = module_state::read(List::PendingRunOnce, pending);
    if (is_ok(error)) error = module_state::read(List::FinishedRunOnce, finished);
    if (is_ok(error) && contains(pending, id)) error = module_state::add(List::FinishedRunOnce, id);
    if (is_ok(error)) error = module_state::remove(List::PendingRunOnce, id);
    if (is_failed(error)) return {error, 0, false};
    if (contains(finished, id)) return {KModErr::OK, 0, true};
    result = execute(desc, key);
    error = publish(id, result);
    if (is_ok(result.loader) && is_failed(error)) result.loader = error;
    return result;
}
}  // namespace maplesu::module_runtime
