#include "module_policy_config.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace maplesu::module_policy {
namespace {
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) {}
    ~Fd() { if (value >= 0) close(value); }
};
[[noreturn]] void failure(const char* operation) {
    throw std::runtime_error(std::string("MODULE_POLICY_CONFIG_") + operation);
}
void validate_directory(int fd) {
    struct stat st{};
    if (fd < 0 || fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0022)) failure("DIRECTORY");
}
int child_directory(int parent, const char* name, bool create) {
    if (create && mkdirat(parent, name, 0700) && errno != EEXIST) failure("MKDIR");
    int child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child < 0 && !create && errno == ENOENT) return -1;
    try { validate_directory(child); }
    catch (...) { if (child >= 0) close(child); throw; }
    return child;
}
class Lock {
    Fd fd_;
public:
    explicit Lock(int directory, const char* name = ".lock") : fd_(openat(directory, name,
        O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600)) {
        struct stat st{};
        if (fd_.value < 0 || fstat(fd_.value, &st) || !S_ISREG(st.st_mode) ||
            st.st_uid != 0 || (st.st_mode & 0777) != 0600 || st.st_nlink != 1)
            failure("LOCK");
        // Mutations are queued by the caller; do not wait indefinitely for another writer.
        if (flock(fd_.value, LOCK_EX | LOCK_NB)) failure("BUSY");
    }
};
std::string mode_record(Mode mode) {
    if (!valid_mode(static_cast<unsigned>(mode))) failure("MODE");
    return "v1:" + std::to_string(static_cast<unsigned>(mode)) + "\n";
}
Mode parse_mode(const std::string& text) {
    if (text.size() != 5 || text.substr(0, 3) != "v1:" || text[4] != '\n' ||
        !valid_mode(static_cast<unsigned>(text[3] - '0'))) failure("RECORD");
    return static_cast<Mode>(text[3] - '0');
}
std::string parse_attempt(const std::string& text) {
    if (text.size() != 40 || text.substr(0, 3) != "v1:" || text[39] != '\n' ||
        !valid_boot_id(text.substr(3, 36))) failure("ATTEMPT_RECORD");
    return text.substr(3, 36);
}
BootState parse_effective(const std::string& text) {
    if (text.size() != 44 || text.substr(0, 3) != "v1:" || text[4] != ':' ||
        text[6] != ':' || text[43] != '\n') failure("BOOT_RECORD");
    unsigned mode = static_cast<unsigned>(text[3] - '0');
    unsigned capabilities = static_cast<unsigned>(text[5] - '0');
    std::string boot = text.substr(7, 36);
    if (!valid_mode(mode) || (capabilities != 1 && capabilities != 3) ||
        (mode == 3 && capabilities != 3) || !valid_boot_id(boot)) failure("BOOT_RECORD");
    return {static_cast<Mode>(mode), capabilities, boot};
}
}

bool valid_mode(unsigned mode) { return mode == 0 || mode == 1 || mode == 3; }
bool valid_boot_id(const std::string& value) {
    if (value.size() != 36) return false;
    for (unsigned i = 0; i < value.size(); ++i) {
        char c = value[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return false; }
        else if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return false;
    }
    return true;
}
Store::Store(int directory) : directory_(directory) {
    if (directory_ >= 0) {
        try { validate_directory(directory_); }
        catch (...) { close(directory_); throw; }
    }
}
Store::~Store() { if (directory_ >= 0) close(directory_); }
void Store::record_compatibility(const std::string& report) const noexcept {
    try {
        if (directory_ < 0 || report.empty() || report.size() > 8192) return;
        Lock lock(directory_, ".diagnostics.lock");
        auto open_log = [&] {
            int fd = openat(directory_, "compatibility.log", O_WRONLY | O_APPEND | O_CREAT |
                            O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
            struct stat st{};
            if (fd < 0) failure("DIAGNOSTICS_OPEN");
            if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
                (st.st_mode & 0777) != 0600 || st.st_nlink != 1) {
                close(fd); failure("DIAGNOSTICS_FILE");
            }
            return fd;
        };
        Fd log(open_log());
        struct stat st{};
        if (fstat(log.value, &st)) return;
        if (st.st_size > 65536 - static_cast<off_t>(report.size())) {
            if (renameat(directory_, "compatibility.log", directory_, "compatibility.previous.log")) return;
            close(log.value);
            log.value = -1;
            log.value = open_log();
        }
        size_t at = 0;
        while (at < report.size()) {
            ssize_t n = write(log.value, report.data() + at, report.size() - at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return;
            at += static_cast<size_t>(n);
        }
        (void)fsync(log.value);
        (void)fsync(directory_);
    } catch (...) { }
}
Store Store::open(bool create) {
    if (geteuid() != 0) failure("ROOT_REQUIRED");
    Fd data(::open("/data", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (data.value < 0) failure("DATA");
    Fd adb(child_directory(data.value, "adb", false));
    if (adb.value < 0) { if (create) failure("ADB"); return Store(-1); }
    Fd maple(child_directory(adb.value, "maplesu", create));
    if (maple.value < 0) return Store(-1);
    return Store(child_directory(maple.value, "module-policy", create));
}
std::optional<std::string> Store::read_file(const char* name) const {
    if (directory_ < 0) return std::nullopt;
    Fd fd(openat(directory_, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    if (fd.value < 0) { if (errno == ENOENT) return std::nullopt; failure("OPEN"); }
    struct stat st{};
    if (fstat(fd.value, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0777) != 0600 || st.st_nlink != 1 || st.st_size < 0 || st.st_size > 64)
        failure("FILE");
    char bytes[65];
    ssize_t size;
    do { size = ::read(fd.value, bytes, sizeof(bytes)); } while (size < 0 && errno == EINTR);
    if (size != st.st_size) failure("READ");
    return std::string(bytes, size);
}
void Store::remember_activation(const std::string& boot_id, uint64_t address) const {
    if (!valid_boot_id(boot_id) || address < 0xffff000000000000ULL || (address & 4095))
        failure("ACTIVATION_RECORD");
    constexpr char digits[] = "0123456789abcdef";
    std::string hex(16, '0');
    for (unsigned i = 0; i < 16; ++i) hex[15 - i] = digits[(address >> (i * 4)) & 15];
    replace("activation", "v1:" + boot_id + ":" + hex + "\n");
}
std::optional<uint64_t> Store::activation(const std::string& boot_id) const {
    if (!valid_boot_id(boot_id)) failure("BOOT_ID");
    auto text = read_file("activation");
    if (!text) return std::nullopt;
    if (text->size() != 57 || text->substr(0, 3) != "v1:" || (*text)[39] != ':' || (*text)[56] != '\n' ||
        !valid_boot_id(text->substr(3, 36))) failure("ACTIVATION_RECORD");
    uint64_t address = 0;
    for (unsigned i = 40; i < 56; ++i) {
        char c = (*text)[i];
        unsigned value = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : 16;
        if (value > 15) failure("ACTIVATION_RECORD");
        address = (address << 4) | value;
    }
    if (address < 0xffff000000000000ULL || (address & 4095)) failure("ACTIVATION_RECORD");
    return text->substr(3, 36) == boot_id ? std::optional<uint64_t>{address} : std::nullopt;
}
State Store::read(const std::string& boot_id) const {
    if (!valid_boot_id(boot_id)) failure("BOOT_ID");
    State state;
    if (auto text = read_file("requested")) state.requested = parse_mode(*text);
    if (auto text = read_file("experimental")) {
        auto value = parse_mode(*text);
        if (value != Mode::Block && value != Mode::Load) failure("RECORD");
        state.unverified_hide = state.requested == Mode::Hide && value == Mode::Load;
    }
    if (auto text = read_file("experimental-support")) state.can_try_unverified = parse_attempt(*text) == boot_id;
    if (auto text = read_file("fallback")) state.hide_failed = parse_attempt(*text) == boot_id;
    if (!state.hide_failed) if (auto text = read_file("effective")) {
        auto boot = parse_effective(*text);
        if (boot.boot_id == boot_id) state.effective = boot;
    }
    // The fallback marker is committed after cancellation and before the other
    // records. It also recovers an interrupted publication without reinstalling.
    if (state.hide_failed) state.effective = BootState{Mode::Load, 1, boot_id};
    // An interrupted hot transition supersedes both an older effective record
    // and an older successful fallback. The next prepare must reconcile the
    // resident backend before either state can be advertised again.
    if (auto text = read_file("hook-pending"))
        if (parse_attempt(*text) == boot_id) state.effective.reset();
    return state;
}
bool Store::owns_hook(const std::string& boot_id) const {
    if (!valid_boot_id(boot_id)) failure("BOOT_ID");
    auto owner = read_file("hook");
    return owner && parse_attempt(*owner) == boot_id;
}
bool Store::blocks_transactions(const std::string& boot_id, bool require_ready) const {
    if (!valid_boot_id(boot_id)) failure("BOOT_ID");
    if (auto text = read_file("hook-pending"))
        if (parse_attempt(*text) == boot_id) return true;
    if (auto text = read_file("fallback")) {
        if (parse_attempt(*text) == boot_id) return false;
    }
    if (auto text = read_file("effective")) {
        auto boot = parse_effective(*text);
        if (boot.boot_id == boot_id) return boot.mode == Mode::Block;
    }
    // An attempted backend may already own hooks even when it failed or crashed
    // before publication. Only an untouched legacy boot may use the old path.
    if (auto text = read_file("attempt")) {
        if (parse_attempt(*text) == boot_id) return true;
    }
    // Older environments have no proven boot backend. Preserve their behaviour;
    // the manager separately reports the global feature as unavailable.
    return require_ready;
}
void Store::replace(const char* name, const std::string& text) const {
    if (directory_ < 0) failure("DIRECTORY");
    std::string temporary = std::string(".") + name + ".tmp";
    // Only an unpublished temporary inode is removed. Existing state stays intact on failure.
    if (unlinkat(directory_, temporary.c_str(), 0) && errno != ENOENT) failure("TEMP");
    Fd fd(openat(directory_, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (fd.value < 0) failure("TEMP");
    bool published = false;
    try {
        size_t offset = 0;
        while (offset < text.size()) {
            ssize_t n = write(fd.value, text.data() + offset, text.size() - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) failure("WRITE");
            offset += n;
        }
        if (fchmod(fd.value, 0600) || fsync(fd.value)) failure("SYNC");
        if (renameat(directory_, temporary.c_str(), directory_, name)) failure("RENAME");
        published = true;
        if (fsync(directory_)) failure("SYNC");
    } catch (...) {
        if (!published) unlinkat(directory_, temporary.c_str(), 0);
        throw;
    }
}
void Store::request(Mode mode, const std::string& boot_id, bool allow_unverified) {
    std::string record = mode_record(mode);
    Lock lock(directory_);
    auto state = read(boot_id);
    // Block/Load only persist a next-boot preference, including during a legacy
    // environment upgrade. They never publish an effective backend or touch policy.
    if (mode == Mode::Hide && (!state.effective || !(state.effective->capabilities & 1))) failure("BACKEND_NOT_READY");
    if (allow_unverified && (mode != Mode::Hide || !state.can_try_unverified)) failure("EXPERIMENTAL_UNSUPPORTED");
    if (mode == Mode::Hide && !(state.effective->capabilities & 2) && !allow_unverified) failure("HIDE_UNSUPPORTED");
    // Clear even an orphaned approval from an interrupted older request, so a
    // later verified request can never inherit experimental consent silently.
    if (allow_unverified || read_file("experimental"))
        replace("experimental", mode_record(allow_unverified ? Mode::Load : Mode::Block));
    if (state.requested != mode) replace("requested", record);
}
void Store::publish(const BootState& state) {
    std::string record = mode_record(state.mode);
    record.pop_back();
    record += ":" + std::to_string(state.capabilities) + ":" + state.boot_id + "\n";
    (void)parse_effective(record);
    Lock lock(directory_);
    replace("effective", record);
}
BootState Store::prepare_hook(const std::string& boot_id, std::optional<Mode> requested,
                              unsigned (*prepare)(Mode, bool), bool allow_unverified) {
    if (!valid_boot_id(boot_id)) failure("BOOT_ID");
    if (requested && (!valid_mode(static_cast<unsigned>(*requested)) ||
        (*requested == Mode::Hide && !prepare))) failure("HOOK_HIDE_UNSUPPORTED");
    if (allow_unverified && (!prepare || requested != Mode::Hide)) failure("EXPERIMENTAL_UNSUPPORTED");
    Lock lock(directory_);
    auto state = read(boot_id);
    const bool owned = owns_hook(boot_id);
    auto attempt = read_file("attempt");
    // Never hot-adopt an SDK-owned or interrupted kernel installation. A bare
    // capability=1 does not prove that there are no resident, inactive Hooks.
    if (activation(boot_id) || (state.can_try_unverified && (!owned || !prepare)) ||
        (state.effective && state.effective->capabilities != 1 && (!owned || !prepare)) ||
        (!owned && (state.effective || (attempt && parse_attempt(*attempt) == boot_id))))
        failure("HOOK_BACKEND_IN_USE");
    auto pending = read_file("hook-pending");
    const bool interrupted = pending && parse_attempt(*pending) == boot_id;
    if (interrupted && !prepare) failure("HOOK_BACKEND_IN_USE");
    if (state.effective && !requested && !interrupted) {
        if (prepare && !state.can_try_unverified)
            replace("experimental-support", "v1:" + boot_id + "\n");
        return *state.effective;
    }
    const bool previous_interrupted = pending && !interrupted && !requested && state.requested == Mode::Hide;
    bool hide_fallback = previous_interrupted || (!prepare && !requested && state.requested == Mode::Hide);
    const Mode target = requested.value_or(hide_fallback ? Mode::Load : state.requested);
    BootState ready{target, 1, boot_id};
    if (!owned) replace("hook", "v1:" + boot_id + "\n");
    replace("attempt", "v1:" + boot_id + "\n");
    std::string fallback_reason = previous_interrupted ? "MODULE_POLICY_CONFIG_PREVIOUS_BOOT_INTERRUPTED" :
        "MODULE_POLICY_HOOK_HIDE_UNSUPPORTED";
    if (prepare) {
        // Persist intent before touching a resident kernel backend. Recovery
        // invokes its query/resume path, never a second snapshot installation.
        const bool consent = !hide_fallback && (requested ? allow_unverified : state.unverified_hide);
        replace("requested", mode_record(target));
        replace("experimental", mode_record(consent ? Mode::Load : Mode::Block));
        replace("hook-pending", "v1:" + boot_id + "\n");
        try {
            ready.capabilities = prepare(target, consent);
            if ((ready.capabilities != 1 && ready.capabilities != 3) ||
                (target == Mode::Hide && ready.capabilities != 3)) failure("HIDE_UNSUPPORTED");
            if (hide_fallback) ready.capabilities = 1;
        } catch (const std::exception& error) {
            if (target != Mode::Hide) throw;
            fallback_reason = error.what();
            // Publish ordinary loading only after the backend confirms that
            // cancellation/reconciliation succeeded. A failed rollback stays
            // pending and retains its diagnostic evidence for the next retry.
            try { (void)prepare(Mode::Load, false); }
            catch (const std::exception& cancel_error) {
                record_compatibility("schema=1 operation=hook-cancel boot=" + boot_id +
                    "\nresult=pending reason=" + fallback_reason +
                    "\ncancelReason=" + cancel_error.what() + "\nEND\n");
                throw;
            }
            ready = {Mode::Load, 1, boot_id};
            hide_fallback = true;
            replace("fallback", "v1:" + boot_id + "\n");
        }
        replace("experimental-support", "v1:" + boot_id + "\n");
    }
    if (read_file("experimental") && (!prepare || hide_fallback || ready.mode != Mode::Hide))
        replace("experimental", mode_record(Mode::Block));
    replace("requested", mode_record(ready.mode));
    replace("effective", "v1:" + std::to_string(static_cast<unsigned>(ready.mode)) + ":" +
        std::to_string(ready.capabilities) + ":" + boot_id + "\n");
    if (hide_fallback) {
        replace("fallback", "v1:" + boot_id + "\n");
        record_compatibility("schema=1 operation=hook-prepare boot=" + boot_id +
            "\nresult=load-fallback reason=" + fallback_reason + "\nEND\n");
    } else if (state.hide_failed && (requested || prepare)) {
        // Clear only after the replacement gate is durable. A failed unlink
        // leaves the old Load fallback visible, never a false Block success.
        if (unlinkat(directory_, "fallback", 0) || fsync(directory_)) failure("SYNC");
    }
    if (prepare && (unlinkat(directory_, "hook-pending", 0) || fsync(directory_))) failure("SYNC");
    return ready;
}
BootState Store::prepare_boot(const std::string& boot_id, unsigned (*prepare)(Mode, bool), bool supports_unverified) {
    Lock lock(directory_);
    auto state = read(boot_id);
    if (state.effective) {
        // Repair older boot records without rerunning an installed backend.
        // Only this capable boot entry may advertise experimental requests.
        if (prepare && supports_unverified && !state.can_try_unverified)
            replace("experimental-support", "v1:" + boot_id + "\n");
        return *state.effective;
    }
    if (!prepare) failure("BACKEND_NOT_READY");
    auto publish_ready = [&](const BootState& ready) {
        std::string record = mode_record(ready.mode);
        record.pop_back();
        record += ":" + std::to_string(ready.capabilities) + ":" + boot_id + "\n";
        (void)parse_effective(record);
        if (supports_unverified) replace("experimental-support", "v1:" + boot_id + "\n");
        replace("effective", record);
    };
    auto fallback = [&](const std::string& reason) {
        std::string evidence = "schema=1 operation=hide-fallback boot=" + boot_id + "\n";
        // Only a confirmed cancellation may publish ordinary loading. Keep the
        // existing attempt on failure; retries cancel without preparing again.
        try {
            unsigned capabilities = prepare(Mode::Load, false);
            if (capabilities != 1 && capabilities != 3) failure("CANCEL_CAPABILITIES");
        } catch (const std::exception& error) {
            record_compatibility(evidence + "result=pending reason=" + reason +
                "\ncancelReason=" + error.what() + "\nEND\n");
            throw;
        }
        evidence += "result=load-fallback reason=" + reason + "\n";
        const BootState ready{Mode::Load, 1, boot_id};
        replace("fallback", "v1:" + boot_id + "\n");
        // The marker already publishes ordinary loading. A later filesystem
        // error must not turn a hide failure into another module-start barrier.
        try { replace("requested", mode_record(Mode::Load)); }
        catch (const std::exception& error) { evidence += std::string("requestReason=") + error.what() + "\n"; }
        try { replace("experimental", mode_record(Mode::Block)); }
        catch (const std::exception& error) { evidence += std::string("consentReason=") + error.what() + "\n"; }
        try { publish_ready(ready); }
        catch (const std::exception& error) { evidence += std::string("publishReason=") + error.what() + "\n"; }
        record_compatibility(evidence + "END\n");
        return ready;
    };
    if (auto text = read_file("attempt")) {
        const auto previous_boot = parse_attempt(*text);
        if (previous_boot == boot_id) {
            // Never stack another hidden installation after interruption.
            if (state.requested == Mode::Hide) return fallback("MODULE_POLICY_CONFIG_PREPARATION_INTERRUPTED");
            failure("PREPARATION_INTERRUPTED");
        }
        if (state.requested == Mode::Hide) {
            const auto completed = read_file("effective");
            const auto pending = read_file("hook-pending");
            if (!completed || parse_effective(*completed).boot_id != previous_boot ||
                (pending && parse_attempt(*pending) == previous_boot))
                return fallback("MODULE_POLICY_CONFIG_PREVIOUS_BOOT_INTERRUPTED");
        }
    }
    replace("attempt", "v1:" + boot_id + "\n");
    try {
        BootState ready{state.requested, prepare(state.requested, state.unverified_hide), boot_id};
        publish_ready(ready);
        return ready;
    } catch (const std::exception& error) {
        if (state.requested != Mode::Hide) throw;
        return fallback(error.what());
    }
}
std::string current_boot_id() {
    Fd fd(::open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC));
    char bytes[38]{};
    if (fd.value < 0 || ::read(fd.value, bytes, sizeof(bytes)) != 37 || bytes[36] != '\n') failure("BOOT_ID");
    std::string id(bytes, 36);
    if (!valid_boot_id(id)) failure("BOOT_ID");
    return id;
}
std::string json(const State& state) {
    return "{\"schemaVersion\":1,\"requested\":" + std::to_string(static_cast<unsigned>(state.requested)) +
        ",\"effective\":" + (state.effective ? std::to_string(static_cast<unsigned>(state.effective->mode)) : "null") +
        ",\"capabilities\":" + std::to_string(state.effective ? state.effective->capabilities : 0) +
        ",\"unverifiedHide\":" + (state.unverified_hide ? "true" : "false") +
        ",\"canTryUnverified\":" + (state.can_try_unverified ? "true" : "false") +
        ",\"hideFailed\":" + (state.hide_failed ? "true" : "false") + "}";
}
} // namespace maplesu::module_policy
