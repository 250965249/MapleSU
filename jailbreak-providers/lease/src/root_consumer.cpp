#include "lease_contract.h"


#include <array>
#include <cctype>
#include <cerrno>
#include <ctime>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Diagnostic switches (2026-10-28): markers in the device-protected directory let a
 * single step be skipped without rebuilding, to isolate which consumer action
 * destabilises this kernel. The reference implementation performs none of them.
 */
static bool skip_step(const char* marker) {
    return access(marker, F_OK) == 0;
}
namespace {
// Provider-stage diagnostics. The kernel helper starts with /dev/null stdio, so
// the App-owned log is the only durable record of the privileged half; the /dev
// copy is readable through the authenticated root shell when the App path is
// not writable from the helper's domain.
/* Written by the App before the attempt: the ART variables a raw app_process64
 * launch needs (a kernel-helper child inherits no Android runtime environment). */
const char* const kEnvFile = "/data/user_de/0/dev.maplesu.manager/maplesu-env";
const char* const kLogPrimary = "/data/user_de/0/dev.maplesu.manager/maplesu-provider.log";
const char* const kLogFallback = "/dev/maplesu-provider.log";
int g_log_primary = -1;
int g_log_fallback = -1;
/* Wall clock at start: attempt-scoped freshness for the disarm proof (S08). */
std::time_t g_start_wallclock = 0;

std::string policy_identity();

void open_logs() {
    if (g_log_primary < 0)
        g_log_primary = open(kLogPrimary, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (g_log_fallback < 0)
        g_log_fallback = open(kLogFallback, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (g_log_primary >= 0) (void)fchmod(g_log_primary, 0644);
    if (g_log_fallback >= 0) (void)fchmod(g_log_fallback, 0644);
}
void log_line(const char* format, ...) {
    char text[512];
    va_list arguments;
    va_start(arguments, format);
    const int count = vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    if (count <= 0) return;
    const size_t size = static_cast<size_t>(count < static_cast<int>(sizeof(text)) ? count
                                                                                  : static_cast<int>(sizeof(text)) - 1);
    if (g_log_primary >= 0) (void)write(g_log_primary, text, size);
    if (g_log_fallback >= 0) (void)write(g_log_fallback, text, size);
    (void)write(STDERR_FILENO, text, size);
}
int fail(const char* message) {
    log_line("maplesu-root-consumer: %s errno=%d\n", message, errno);
    return 71;
}
bool send_all(int fd, const void* data, size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    while (size) {
        const ssize_t n = send(fd, bytes, size, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n;
        size -= static_cast<size_t>(n);
    }
    return true;
}
bool text_file(const char* path, std::string& result, size_t limit, bool* absent = nullptr);

/*
 * app_process64 fails inside ART with "BOOTCLASSPATH and DEX2OATBOOTCLASSPATH
 * must not be empty" when it is started from a kernel helper. The App publishes
 * both from its own (zygote inherited) environment; only these two names are
 * accepted, so the file cannot inject arbitrary variables.
 */
void load_runtime_environment() {
    std::string content;
    if (!text_file(kEnvFile, content, 64 * 1024)) {
        log_line("maplesu-root-consumer: runtime environment absent\n");
        return;
    }
    size_t start = 0;
    while (start < content.size()) {
        size_t end = content.find('\n', start);
        if (end == std::string::npos) end = content.size();
        const std::string line = content.substr(start, end - start);
        start = end + 1;
        const size_t equals = line.find('=');
        if (equals == std::string::npos || equals == 0) continue;
        const std::string key = line.substr(0, equals);
        if (key != "BOOTCLASSPATH" && key != "DEX2OATBOOTCLASSPATH") continue;
        const std::string value = line.substr(equals + 1);
        if (value.empty()) continue;
        if (setenv(key.c_str(), value.c_str(), 1) != 0) {
            log_line("maplesu-root-consumer: setenv %s failed errno=%d\n", key.c_str(), errno);
        } else {
            log_line("maplesu-root-consumer: runtime environment %s=%zu bytes\n", key.c_str(),
                     value.size());
        }
    }
    (void)unlink(kEnvFile);
}

bool text_file(const char* path, std::string& result, size_t limit, bool* absent) {
    if (absent) *absent = false;
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (absent) *absent = errno == ENOENT;
        return false;
    }
    std::array<char, 512> bytes{};
    bool ok = true;
    while (true) {
        const ssize_t n = read(fd, bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || result.size() + static_cast<size_t>(n) > limit) { ok = false; break; }
        if (n == 0) break;
        result.append(bytes.data(), static_cast<size_t>(n));
    }
    close(fd);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\0')) result.pop_back();
    return ok && !result.empty();
}
bool write_one_byte(const char* path, char value) {
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const ssize_t n = write(fd, &value, 1);
    close(fd);
    return n == 1;
}
bool number(int fd, uint32_t value) {
    const std::array<unsigned char, 4> bytes{static_cast<unsigned char>(value >> 24),
        static_cast<unsigned char>(value >> 16), static_cast<unsigned char>(value >> 8),
        static_cast<unsigned char>(value)};
    return send_all(fd, bytes.data(), bytes.size());
}
/** Widens number() to a 64-bit value for the S12 starttime field. */
bool number64(int fd, uint64_t value) {
    const uint32_t high = static_cast<uint32_t>(value >> 32);
    const uint32_t low = static_cast<uint32_t>(value & 0xffffffffu);
    return number(fd, high) && number(fd, low);
}

bool field(int fd, const std::string& value) {
    return number(fd, static_cast<uint32_t>(value.size())) && send_all(fd, value.data(), value.size());
}
int receive_stdio(int fd, std::array<int, 3>& descriptors) {
    char accepted = 0;
    iovec io{&accepted, 1};
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(16 * sizeof(int))> ancillary{};
    msghdr message{};
    message.msg_iov = &io; message.msg_iovlen = 1;
    message.msg_control = ancillary.data(); message.msg_controllen = ancillary.size();
    ssize_t received;
    do { received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC); } while (received < 0 && errno == EINTR);
    size_t count = 0;
    bool valid = received == 1 && accepted == 'A' && !(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC));
    for (cmsghdr* c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS || c->cmsg_len < CMSG_LEN(0)) {
            valid = false; continue;
        }
        const size_t bytes = c->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int)) valid = false;
        for (size_t i = 0; i < bytes / sizeof(int); ++i) {
            int descriptor = -1;
            std::memcpy(&descriptor, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
            if (count < descriptors.size()) descriptors[count] = descriptor;
            else { close(descriptor); valid = false; }
            ++count;
        }
    }
    if (!valid || count != descriptors.size()) {
        for (const int descriptor : descriptors) if (descriptor >= 0) close(descriptor);
        descriptors.fill(-1);
        return -1;
    }
    return 0;
}
/*
 * TRANSIENT_PROVIDER_RESTORE_V1: the provider stage is allowed to leave the
 * kernel transient while it is being used. The moment the authenticated lease
 * exists, the same attempt must restore the pre-entry policy.
 *
 * R05 (review 2026-10-26): the restore used to live inside the success branch of
 * the shell spawn, so a cancelled transport, a refused exec or any early return
 * after the provider transient existed skipped it entirely and the device kept
 * the permissive state until reboot. Every exit path now funnels through
 * teardown_once(), which is called exactly once and reports its result on the
 * lease transport (the restore frame `P` when the shell was announced, a failure
 * frame `F` otherwise).
 *
 * R04: the pre-entry enforcing value is *not* assumed silently any more. The
 * frame carries the origin of the value that was written back:
 *   0 observed   - the App read the entry value before the attempt and sent it;
 *   1 baseline   - the value could not be observed from the App domain, so the
 *                  documented Android release baseline was applied and labelled;
 *   2 unknown    - no value at all: nothing is written and the attempt fails;
 *   3 provider   - the provider restores through its own script (Ghostlock).
 * The product must never render 1 or 2 as "the original policy was restored".
 */
enum RestoreOrigin : unsigned char {
    kOriginObserved = 0,
    kOriginBaseline = 1,
    kOriginUnknown = 2,
    kOriginProvider = 3,
};

struct RestoreReport {
    unsigned char applied;      // 1 restored(observed), 3 restored(baseline), 0 failed, 2 not applicable
    unsigned char origin;       // RestoreOrigin
    unsigned char enforcing;    // read back value, 0xff unknown
    unsigned char checkreqprot; // read back value, 2 confirmed absent (Ghostlock), 0xff unknown
    unsigned char policy;       // 0 identical across the restore, 1 changed, 2 unknown
    int unload_errno;           // 0 when the module is gone
};

// Only used when the App cannot read selinuxfs. An Android device that boots
// with verified boot and without androidboot.selinux=permissive starts enforcing,
// and the product records this value as *baseline*, never as the observed one.
constexpr char kBaselineEnforcing = '1';

/* 0xff is unobservable; optional entries report 2 only for open(2) ENOENT. */
unsigned char read_selinux_flag(const char* path, char& value, bool optional = false) {
    std::string text;
    bool absent = false;
    if (!text_file(path, text, 8, &absent)) return optional && absent ? 2 : 0xff;
    if (text.size() != 1) return 0xff;
    value = text[0];
    return value == '1' ? 1 : value == '0' ? 0 : 0xff;
}
unsigned char read_enforcing_byte(char& value) {
    return read_selinux_flag("/sys/fs/selinux/enforce", value);
}

RestoreReport restore_policy(int expected) {
    RestoreReport report{0, kOriginUnknown, 0xff, 0xff, 2, 0};
    char target = 0;
    if (expected == 0 || expected == 1) {
        target = static_cast<char>('0' + expected);
        report.origin = kOriginObserved;
    } else if (expected == -2) {
        target = kBaselineEnforcing;
        report.origin = kOriginBaseline;
    }
    // The policy is read while the provider transient is still in place, so the
    // read is not itself gated by the value we are about to restore.
    const std::string policy_before = policy_identity();
    char checkreqprot_before = 0;
    const unsigned char checkreqprot_before_state =
        read_selinux_flag("/sys/fs/selinux/checkreqprot", checkreqprot_before);
    log_line("maplesu-root-consumer: policy identity %s\n", policy_before.c_str());
    char current = 0;
    const unsigned char current_state = read_enforcing_byte(current);
    log_line("maplesu-root-consumer: restore start target=%c origin=%d current=%c checkreqprot=%c\n",
             target ? target : '?', report.origin, current_state == 0xff ? '?' : current,
             checkreqprot_before_state == 0xff ? '?' : checkreqprot_before);
    /*
     * The guard file /dev/df is the native stage's re-entry guard: removing it
     * while the hook is still armed re-runs the whole chain with no consumer left
     * to restore the policy. The native stage publishes one file after it verified
     * every restore, and that file lives in the App's own data directory - which
     * the helper can only reach while the provider transient still applies. So the
     * handshake and the marker removal happen first and the policy is restored
     * last; the wait is bounded, and a timeout keeps the guard, which the App
     * treats as an unclean attempt.
     */
    const char* disarm = "/data/user_de/0/dev.maplesu.manager/maplesu-disarmed";
    // A marker means the native stage is (or was) running; without it there is
    // nothing to disarm and waiting would only delay a failed attempt.
    const bool stage_running = access("/dev/dfm0", F_OK) == 0;
    bool disarmed = false;
    int waited = 0;
    /*
     * S08: the proof must belong to *this* attempt, not merely exist. A file left
     * by an earlier attempt would let the re-entry guard be removed before the
     * current stage ever disarmed its own hook, so a stale proof is dropped and the
     * wait continues. Freshness is measured against this consumer's start time.
     */
    for (int i = 0; stage_running && i < 300; ++i) {
        /*
         * A stale page cache makes the stage skip its restore path entirely, so no
         * proof can ever arrive; stop waiting instead of burning the full window and
         * report it as its own condition (DEV-47). The guard stays.
         */
        /*
         * The stage logs "already patched" when a previous attempt left the patch in
         * the page cache; it then skips its restore path, so the proof can never
         * arrive. Read its log instead of waiting out the window (DEV-47).
         */
        if ((i % 10) == 0) {
            std::string stage_log_text;
            if (text_file("/data/user_de/0/dev.maplesu.manager/native-stage.log",
                          stage_log_text, 8192) &&
                stage_log_text.find("already patched") != std::string::npos) {
                log_line("maplesu-root-consumer: stage reports an already patched lib; no proof expected\n");
                /*
                 * The original bytes are unrecoverable once an earlier attempt
                 * patched the page cache (pread reads through the cache), so this
                 * attempt cannot restore them. Leave a flag the App turns into an
                 * explicit "reboot required" verdict instead of a generic failure.
                 */
                {
                    const int flag = open("/data/user_de/0/dev.maplesu.manager/maplesu-stale-flag",
                                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (flag >= 0) { (void)write(flag, "stale", 5); close(flag); }
                }
                break;
            }
        }
        if (access("/data/user_de/0/dev.maplesu.manager/maplesu-stale", F_OK) == 0) {
            log_line("maplesu-root-consumer: stale page cache reported by the stage; no disarm proof expected\n");
            unlink("/data/user_de/0/dev.maplesu.manager/maplesu-stale");
            break;
        }
        struct stat proof {};
        if (stat(disarm, &proof) == 0) {
            if (proof.st_mtime + 2 >= g_start_wallclock) { disarmed = true; break; }
            log_line("maplesu-root-consumer: stale disarm proof mtime=%ld start=%ld; dropped\n",
                     static_cast<long>(proof.st_mtime), static_cast<long>(g_start_wallclock));
            unlink(disarm);
        }
        usleep(50000);
        waited += 50;
    }
    int markers_left = 0;
    for (const char* marker : {"/dev/dfm0", "/dev/dfm1", "/dev/dfm2", "/dev/dfm3",
                               "/dev/dfm4", "/dev/dfm5", "/dev/dfme0", "/dev/dfme1", "/dev/dfme2",
                               "/dev/dfmw0", "/dev/dfmw1"}) {
        if (unlink(marker) == 0) log_line("maplesu-root-consumer: removed %s\n", marker);
        else if (errno != ENOENT && access(marker, F_OK) == 0) ++markers_left;
    }
    if (disarmed) {
        /*
         * /dev/df is init's one-shot re-entry mutex, not an attempt marker: removing
         * it re-arms the whole chain (a second insmod, a second dfroot_init and a
         * second SELinux flip) inside the window we just restored, which is exactly
         * what panicked this kernel. It is therefore kept for the rest of the boot and
         * cleared by the reboot, as in the reference implementation. It does not count
         * towards the attempt's marker residue.
         */
        if (access("/dev/df", F_OK) == 0)
            log_line("maplesu-root-consumer: guard kept for this boot (reboot clears it)\n");
        unlink(disarm);
    } else if (stage_running) {
        log_line("maplesu-root-consumer: guard kept: native stage did not disarm\n");
        if (access("/dev/df", F_OK) == 0) ++markers_left;
    } else {
        log_line("maplesu-root-consumer: no stage marker; nothing to disarm\n");
    }
    log_line("maplesu-root-consumer: disarmed=%d waitedMs=%d markers remaining=%d\n",
             disarmed ? 1 : 0, waited, markers_left);
    /*
     * Restoring the policy is the last step: it closes the permissive window, and
     * everything above needs that window to still be open. An unknown target is
     * not replaced by a guess: nothing is written and the attempt is reported as
     * failed instead of silently picking a value.
     */
    /*
     * The policy image is compared *before* the switch back to enforcing: once
     * SELinux is enforcing again this kernel-domain helper can no longer open
     * selinuxfs/policy (measured: "after=unavailable"), and a denied read must
     * never be reported as "changed". Both reads happen inside the same
     * transient state, which is what the "no persistent MapleSU policy" claim is
     * actually about.
     */
    const std::string policy_after = policy_identity();
    /*
     * S07: two failed reads are not a match. "unavailable" is not evidence, so an
     * unreadable pair is reported as "not compared" (2) and, because DirtyFrag is
     * required to keep the same policy, the restoration is *failed* rather than
     * accepted. A readable pair that differs is a change and fails the same way.
     */
    const bool policy_readable = policy_before != "unavailable" &&
        policy_after != "unavailable";
    report.policy = !policy_readable ? 2 : policy_after == policy_before ? 0 : 1;
    if (report.policy != 0)
        log_line("maplesu-root-consumer: policy identity unreadable-or-changed result=%d "
                 "before=%s after=%s\n", report.policy, policy_before.c_str(),
                 policy_after.c_str());
    bool wrote = false;
    if (!target) {
        log_line("maplesu-root-consumer: entry policy unknown; refusing to write\n");
    } else if (current_state == 0xff) {
        log_line("maplesu-root-consumer: enforcing unreadable; restoring without comparison\n");
        wrote = write_one_byte("/sys/fs/selinux/enforce", target);
    } else if (current != target) {
        wrote = write_one_byte("/sys/fs/selinux/enforce", target);
        if (wrote) log_line("maplesu-root-consumer: wrote enforcing=%c\n", target);
        else log_line("maplesu-root-consumer: enforcing write failed errno=%d\n", errno);
    } else {
        wrote = true;
    }
    const long unload = skip_step("/data/user_de/0/dev.maplesu.manager/no-unload")
        ? -2
        : syscall(__NR_delete_module, "dfroot", O_NONBLOCK);
    report.unload_errno = unload == 0 ? 0 : errno;
    log_line("maplesu-root-consumer: delete_module dfroot=%ld errno=%d\n", unload,
             unload == 0 ? 0 : errno);
    char after = 0;
    const unsigned char after_state = read_enforcing_byte(after);
    report.enforcing = after_state;
    char checkreqprot_after = 0;
    report.checkreqprot = read_selinux_flag("/sys/fs/selinux/checkreqprot", checkreqprot_after) == 0xff
        ? 0xff : checkreqprot_after == '1' ? 1 : checkreqprot_after == '0' ? 0 : 0xff;
    if (!target) report.applied = 0;
    else if (report.policy != 0) report.applied = 0;
    else if (!wrote || after_state == 0xff) report.applied = 0;
    else if (after != target) report.applied = 0;
    else report.applied = report.origin == kOriginObserved ? 1 : 3;
    if (markers_left != 0 && report.applied != 0) report.applied = 0;
    const bool checkreqprot_changed = checkreqprot_before_state != 0xff &&
        report.checkreqprot != 0xff && checkreqprot_before_state != report.checkreqprot;
    if (checkreqprot_changed && report.applied != 0) report.applied = 0;
    char enforcing_text[8];
    char checkreqprot_text[8];
    snprintf(enforcing_text, sizeof(enforcing_text), "%c", after_state == 0xff ? '?' : after);
    snprintf(checkreqprot_text, sizeof(checkreqprot_text), "%c",
             report.checkreqprot == 0xff ? '?' : checkreqprot_after);
    log_line("maplesu-root-consumer: restore readback enforcing=%s applied=%d origin=%d "
             "checkreqprot=%s policy=%d markers=%d\n",
             enforcing_text, report.applied, report.origin, checkreqprot_text, report.policy,
             markers_left);
    return report;
}
// Policy identity: a bounded read of the live binary policy with a 64-bit
// FNV-1a digest. This is an identity observation of the running policy, not a
// claim that it equals the pre-entry policy; the record keeps both readings.
std::string policy_identity() {
    const int fd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::string("unavailable");
    uint64_t hash = 1469598103934665603ull;
    size_t total = 0;
    std::array<unsigned char, 65536> buffer{};
    while (true) {
        const ssize_t n = read(fd, buffer.data(), buffer.size());
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; ++i) { hash ^= buffer[static_cast<size_t>(i)]; hash *= 1099511628211ull; }
        total += static_cast<size_t>(n);
    }
    close(fd);
    char text[96];
    snprintf(text, sizeof(text), "bytes=%zu fnv1a64=%016llx", total,
             static_cast<unsigned long long>(hash));
    return std::string(text);
}

bool send_report(int control, const RestoreReport& report) {
    std::array<unsigned char, 10> frame{'P', report.applied, report.origin, report.enforcing,
        report.checkreqprot, report.policy,
        static_cast<unsigned char>(report.unload_errno >> 24),
        static_cast<unsigned char>(report.unload_errno >> 16),
        static_cast<unsigned char>(report.unload_errno >> 8),
        static_cast<unsigned char>(report.unload_errno)};
    return send_all(control, frame.data(), frame.size());
}
/* Failure frame: the consumer can fail before the shell exists, and the App must
 * learn that instead of waiting for its provider timeout. */
/* Sent by the App once the Root executor answered its identity. */
constexpr char kHandoverFrame = 'D';
constexpr unsigned char kStageArguments = 1;
constexpr unsigned char kStageRootWorker = 2;
constexpr unsigned char kStageIdentity = 3;
constexpr unsigned char kStageSocket = 4;
constexpr unsigned char kStagePeer = 5;
constexpr unsigned char kStageStdio = 6;
constexpr unsigned char kStageExec = 7;

bool send_failure(int control, unsigned char stage) {
    const std::array<unsigned char, 5> frame{'F', stage, 0, 0, 0};
    return send_all(control, frame.data(), frame.size());
}
/* The Root executor renames itself and detaches; it is identified by uid 0 plus
 * that exact command line, so this never touches an unrelated root process. */
constexpr const char kDaemonName[] = "dev.maplesu.manager:root:";
constexpr int kReapAttempts = 25;

/* Start time (field 22 of /proc/<pid>/stat) of this consumer, in clock ticks.
 * Only processes that appeared after us can belong to this attempt. */
uint64_t g_self_starttime = 0;

uint64_t starttime_of(const char* path) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buffer[1024];
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (count <= 0) return 0;
    buffer[count] = '\0';
    // The command name may contain spaces and parentheses: skip past the last ')'.
    const char* close = strrchr(buffer, ')');
    if (!close) return 0;
    int field = 2;  // the field right after ')' is state (3); starttime is 22
    const char* cursor = close + 1;
    while (*cursor && field < 22) {
        while (*cursor == ' ') ++cursor;
        while (*cursor && *cursor != ' ') ++cursor;
        ++field;
    }
    return strtoull(cursor, nullptr, 10);
}

int reap_once(void) {
    DIR* directory = opendir("/proc");
    if (!directory) return -1;
    int killed = 0;
    dirent* entry = nullptr;
    while ((entry = readdir(directory)) != nullptr) {
        if (!isdigit(static_cast<unsigned char>(entry->d_name[0]))) continue;
        char* end = nullptr;
        const long pid = strtol(entry->d_name, &end, 10);
        if (!end || *end || pid <= 1) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char command[192];
        const ssize_t count = read(fd, command, sizeof(command) - 1);
        close(fd);
        if (count <= 0) continue;
        command[count] = '\0';
        if (strncmp(command, kDaemonName, sizeof(kDaemonName) - 1) != 0) continue;
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%ld/status", pid);
        std::string status;
        if (!text_file(status_path, status, 4096)) continue;
        const size_t uid = status.find("Uid:");
        if (uid == std::string::npos || status.compare(uid + 4, 5, "\t0\t") != 0) continue;
        // Identity, not a name prefix: only processes younger than this attempt.
        if (g_self_starttime != 0) {
            snprintf(status_path, sizeof(status_path), "/proc/%ld/stat", pid);
            const uint64_t started = starttime_of(status_path);
            if (started != 0 && started < g_self_starttime) continue;
        }
        kill(static_cast<pid_t>(pid), SIGKILL);
        ++killed;
    }
    closedir(directory);
    return killed;
}

void reap_detached_executor() {
    for (int attempt = 0; attempt < kReapAttempts; ++attempt) {
        const int killed = reap_once();
        if (killed <= 0) {
            /* A second pass proves the process did not simply respawn. */
            if (attempt == 0 && killed == 0) continue;
            break;
        }
        log_line("maplesu-root-consumer: reaped %d detached executor process(es)\n", killed);
        usleep(20000);
    }
    log_line("maplesu-root-consumer: executor reap finished\n");
}

/*
 * The provider writes through the page cache of read-only files. Content is
 * restored and verified by the native stage, but the pages stay dirty: any
 * mapping of those files reports Shared_Dirty until the page leaves the cache,
 * which is exactly what a "shared dirty system code" check looks for. Force the
 * (bound to fail) writeback attempt and then ask the kernel to drop the pages.
 */
/*
 * Diagnostic switches (2026-10-28): markers in the device-protected directory let a
 * single step be skipped without rebuilding, to isolate which consumer action
 * destabilises this kernel. The reference implementation performs none of them.
 */
void evict_restored_pages() {
    if (skip_step("/data/user_de/0/dev.maplesu.manager/no-evict")) {
        log_line("maplesu-root-consumer: evict skipped by request\n");
        return;
    }
    /*
     * No sync() here: the reference implementation never forces writeback, and with
     * the block devices set read-only by the bootstrap the flush is pointless while it
     * widens the window in which the exploit's dirty pages reach the block layer.
     */
    for (const char* path : {"/system/lib64/libc++.so",
                             "/vendor/lib64/libbinderdebug.so",
                             "/apex/com.android.runtime/bin/crash_dump64"}) {
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { log_line("maplesu-root-consumer: evict %s open errno=%d\n", path, errno); continue; }
        const int advice = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
        close(fd);
        log_line("maplesu-root-consumer: evict %s advice=%d\n", path, advice);
    }
}

/*
 * One attempt, one teardown. The provider transient exists before this process
 * starts (the kernel helper is dispatched after the module disabled SELinux), so
 * every exit path - refused arguments, non-root worker, identity failure, socket
 * failure, peer mismatch, FD admission failure, exec failure, cancelled owner or
 * a normal shell exit - runs through here.
 */
struct Session {
    int control = -1;
    bool announced = false;
    bool transient = false;
    bool dumped = false;
    int expected = -2;
    // Ghostlock restores through its own script before this process starts; the
    // provider hands its exit code and the booleans it observed to argv[6].
    bool ghostlock_report = false;
    int ghostlock_rc = -1;
    int ghostlock_enforcing = -1;
    int ghostlock_checkreqprot = -1;
    int ghostlock_source = -1;  // 0 observed, 1 documented baseline
};
Session g_session;

/*
 * Ghostlock's provider restored the policy before starting us. Two independent
 * conditions are required before this counts as a restoration: the provider's
 * script reported success, and the booleans this process reads now equal the
 * values it reported. The policy identity is deliberately reported as "not
 * compared" - the provider reloads the policy, so claiming equality would be a
 * false proof.
 */
RestoreReport ghostlock_report() {
    RestoreReport report{0, g_session.ghostlock_source == 0 ? kOriginObserved : kOriginBaseline,
                         0xff, 0xff, 2, -1};
    char enforcing = 0;
    char checkreqprot = 0;
    const unsigned char live_enforcing = read_enforcing_byte(enforcing);
    const unsigned char live_checkreqprot = read_selinux_flag("/sys/fs/selinux/checkreqprot",
                                                              checkreqprot, true);
    report.enforcing = live_enforcing;
    report.checkreqprot = live_checkreqprot;
    const bool drained = g_session.ghostlock_rc == 0;
    const bool enforcing_matches = live_enforcing <= 1 &&
        static_cast<int>(live_enforcing) == g_session.ghostlock_enforcing;
    const bool checkreqprot_matches = g_session.ghostlock_checkreqprot == -2
        ? live_checkreqprot == 2
        : (live_checkreqprot <= 1 &&
           static_cast<int>(live_checkreqprot) == g_session.ghostlock_checkreqprot);
    log_line("maplesu-root-consumer: ghostlock restore rc=%d reportedEnforcing=%d liveEnforcing=%d "
             "reportedCheckreqprot=%d liveCheckreqprot=%d source=%d\n",
             g_session.ghostlock_rc, g_session.ghostlock_enforcing, static_cast<int>(live_enforcing),
             g_session.ghostlock_checkreqprot, static_cast<int>(live_checkreqprot),
             g_session.ghostlock_source);
    if (!drained || !enforcing_matches || !checkreqprot_matches) return report;
    if (live_enforcing == 0xff || live_checkreqprot == 0xff) return report;
    report.applied = g_session.ghostlock_source == 0 ? 1 : 3;
    return report;
}

void teardown_once(unsigned char failure_stage) {
    if (g_session.dumped) return;
    g_session.dumped = true;
    RestoreReport report{2, kOriginProvider, 0xff, 0xff, 2, 0};
    if (g_session.transient) {
        report = restore_policy(g_session.expected);
        evict_restored_pages();
    } else if (g_session.ghostlock_report) {
        report = ghostlock_report();
    } else {
        log_line("maplesu-root-consumer: provider owns restoration; no consumer teardown\n");
    }
    if (g_session.control >= 0) {
        if (g_session.announced) {
            if (!send_report(g_session.control, report))
                log_line("maplesu-root-consumer: restore report failed\n");
        } else if (failure_stage != 0) {
            if (!send_failure(g_session.control, failure_stage))
                log_line("maplesu-root-consumer: failure frame failed\n");
        }
    }
}

/* Every privileged exit path returns through here; no path may skip teardown. */
int finish(unsigned char failure_stage, int code) {
    teardown_once(failure_stage);
    if (g_session.control >= 0) close(g_session.control);
    g_session.control = -1;
    close(g_log_primary);
    close(g_log_fallback);
    g_log_primary = -1;
    g_log_fallback = -1;
    return code;
}

std::int64_t now_millis() {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return static_cast<std::int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

int supervise(int control, const std::array<int, 3>& descriptors) {
    /*
     * Set the exec context while the transient still permits it: the shell must
     * enter a context a su-style helper already has on this platform, not the
     * kernel domain the helper was dispatched in. The transition applies at
     * execve, so it is written here and consumed by the child below.
     */
    {
        const int exec_attr = open("/proc/self/attr/exec", O_WRONLY | O_CLOEXEC);
        if (exec_attr >= 0) {
            const char domain[] = "u:r:shell:s0";
            if (write(exec_attr, domain, sizeof(domain) - 1) == (ssize_t)(sizeof(domain) - 1))
                log_line("maplesu-root-consumer: shell exec domain u:r:shell:s0\n");
            else
                log_line("maplesu-root-consumer: shell exec domain refused errno=%d\n", errno);
            close(exec_attr);
        }
    }
    int exec_status[2];
    if (pipe2(exec_status, O_CLOEXEC) != 0) return fail("exec pipe failed");
    const pid_t child = fork();
    if (child < 0) { close(exec_status[0]); close(exec_status[1]); return fail("fork failed"); }
    if (child == 0) {
        close(exec_status[0]);
        int error = 0;
        if (setpgid(0, 0) != 0) error = errno;
        for (int i = 0; i < 3 && !error; ++i) if (dup2(descriptors[static_cast<size_t>(i)], i) < 0) error = errno;
        if (!error) {
            signal(SIGPIPE, SIG_DFL);
            // The fresh worker owns this shell. Do not retain provider pipes,
            // GLK profile/ACK stdin, or any sprayed descriptor across exec.
            const long maximum = sysconf(_SC_OPEN_MAX);
            if (maximum < 0 || maximum > 1048576) error = EMFILE;
            else for (int fd = 3; fd < maximum; ++fd) {
                const int flags = fcntl(fd, F_GETFD);
                if (flags >= 0) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
            }
            /*
             * The kernel helper is dispatched with a minimal environment
             * ("PATH=/system/bin" only). A shell started like that cannot run
             * app_process64: the linker resolves libnativeloader.so through the
             * ART apex namespace, which needs the standard Android variables -
             * measured as "CANNOT LINK EXECUTABLE app_process64: library
             * libnativeloader.so not found". Provide the environment every other
             * root shell on this platform already has.
             */
            if (!error) {
                /*
                 * The kernel helper is dispatched from a kernel thread, i.e. from
                 * the mount namespace first-stage init had. APEX payloads such as
                 * /apex/com.android.art/lib64/libnativeloader.so are mounted in
                 * init's current namespace, so app_process64 could not be linked
                 * ("library libnativeloader.so not found"). Join pid 1's namespace
                 * before starting the shell; the global namespace is also what the
                 * su client publication verifies.
                 */
                /*
                 * Diagnostic (2026-10-28): <DE>/no-setns keeps the helper's namespace
                 * instead of joining init's, to isolate whether the namespace switch is
                 * what destabilises the kernel.
                 */
                const int init_mnt = skip_step("/data/user_de/0/dev.maplesu.manager/no-setns")
                    ? -1
                    : open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
                if (init_mnt >= 0) {
                    if (setns(init_mnt, CLONE_NEWNS) != 0)
                        log_line("maplesu-root-consumer: setns(init mnt) failed errno=%d\n", errno);
                    else
                        log_line("maplesu-root-consumer: shell joined init mount namespace\n");
                    close(init_mnt);
                }
                load_runtime_environment();
                setenv("PATH", "/system/bin:/system/xbin:/vendor/bin", 1);
                setenv("ANDROID_ROOT", "/system", 1);
                setenv("ANDROID_DATA", "/data", 1);
                setenv("ANDROID_ART_ROOT", "/apex/com.android.art", 1);
                setenv("ANDROID_I18N_ROOT", "/apex/com.android.i18n", 1);
                setenv("ANDROID_TZDATA_ROOT", "/apex/com.android.tzdata", 1);
                setenv("LD_LIBRARY_PATH",
                       "/system/lib64:/system_ext/lib64:/vendor/lib64:"
                       "/apex/com.android.runtime/lib64:/apex/com.android.art/lib64", 1);
                setenv("HOME", "/", 1);
                setenv("TMPDIR", "/data/local/tmp", 1);
                /*
                 * stdout and stderr stay inherited: libsu uses them as the
                 * command channel of this shell (its root probe and every task
                 * read their output from there). Redirecting them for
                 * diagnostics made the shell look dead/unprivileged -
                 * "SU_DIRECTORY_jailbreak_lease_shell" with the cause
                 * SU_DIRECTORY_KEY_SHELL_NOT_ROOT - so the daemon never bound.
                 */
                /*
                 * Diagnostic (2026-10-28): <DE>/no-art replaces the command channel
                 * with a sleeping process, so the App's `exec app_process64` never runs.
                 * It isolates whether ART inside the patched kernel is the trigger,
                 * while keeping the namespace switch in place.
                 */
                if (skip_step("/data/user_de/0/dev.maplesu.manager/no-art"))
                    execl("/system/bin/sleep", "sleep", "600", static_cast<char*>(nullptr));
                execl("/system/bin/sh", "sh", static_cast<char*>(nullptr));
            }
            if (!error) error = errno;
        }
        (void)write(exec_status[1], &error, sizeof(error));
        _exit(126);
    }
    close(exec_status[1]);
    if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) kill(child, SIGKILL);
    for (const int descriptor : descriptors) close(descriptor);
    int exec_error = 0;
    ssize_t count;
    do { count = read(exec_status[0], &exec_error, sizeof(exec_error)); } while (count < 0 && errno == EINTR);
    close(exec_status[0]);
    bool cancelled = count != 0;
    if (!cancelled) {
        cancelled = !send_all(control, "R", 1) || !number(control, static_cast<uint32_t>(child));
        g_session.announced = !cancelled;
    }
    /*
     * TRANSIENT_PROVIDER_RESTORE_V1: the shell exists now (or the attempt failed),
     * so restoration is due in both cases; teardown_once() runs it exactly once
     * and publishes the observation frame on the same transport. It stays here
     * because the App gates the handover on that frame.
     */
    teardown_once(cancelled ? kStageExec : 0);
    /*
     * TRANSIENT_PROVIDER_RESTORE_V1, but ordered: the launcher shell exists now,
     * and the Root executor needs the transient window to start inside it (a raw
     * app_process64 launch has to link against APEX payloads and register its
     * binder while this domain is still permissive). Restoration therefore
     * happens once the App either confirms the handover or the window expires -
     * never before the executor had its chance, and never unbounded.
     */
    constexpr int kHandoverWindowSeconds = 90;
    const std::int64_t handover_deadline = now_millis() + kHandoverWindowSeconds * 1000LL;
    int status = 0;
    bool handed_over = false;
    while (true) {
        siginfo_t exited{};
        const int result = waitid(P_PID, static_cast<id_t>(child), &exited, WEXITED | WNOHANG | WNOWAIT);
        if (result == 0 && exited.si_pid == child) break;
        if (result < 0 && errno != EINTR) { cancelled = true; break; }
        if (cancelled) break;
        if (now_millis() > handover_deadline) {
            cancelled = true;
            log_line("maplesu-root-consumer: handover window expired after %d s\n",
                     kHandoverWindowSeconds);
            break;
        }
        pollfd event{control, POLLIN | POLLHUP | POLLERR, 0};
        const int polled = poll(&event, 1, 100);
        if (polled < 0 && errno == EINTR) continue;
        if (polled == 0) continue;
        char frame = 0;
        const ssize_t got = recv(control, &frame, 1, MSG_DONTWAIT);
        if (got == 1 && frame == kHandoverFrame) {
            /* The Root executor owns the lease now: this shell is only its
             * launcher and must go away without taking the executor with it. */
            handed_over = true;
            log_line("maplesu-root-consumer: handover confirmed; launcher exits, executor kept\n");
            continue;
        }
        cancelled = true;
        break;
    }
    /*
     * The policy is restored before the handover wait by design: teardown_once()
     * above already wrote the entry value back and read it back, so the executor is
     * started under the restored (enforcing) state and the 'D' frame only confirms
     * that the executor answered.
     *
     * Terminate and reap *before* writing the entry policy back: once SELinux is
     * enforcing again this kernel-domain helper loses { sigkill } on the shell
     * domain (measured: avc denied sigkill scontext=u:r:kernel:s0
     * tcontext=u:r:shell:s0), so a later kill could never clean up.
     */
    if (!handed_over) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
        /*
         * The reaper targets "<package>:root:*" processes started after this
         * consumer - which is exactly the executor the launcher has just started
         * for the App to bind. Measured: it killed the executor seconds after the
         * shell reported "maplesu-launch-submitted" ("executor:Killed"). It now
         * runs only when the launcher never announced readiness, i.e. when no
         * executor can legitimately exist for this attempt.
         */
        if (!g_session.announced) reap_detached_executor();
    }
    if (handed_over) {
        // The launcher shell is gone by design; do not block the consumer on it.
        for (int i = 0; i < 20; ++i) {
            if (waitpid(child, &status, WNOHANG) == child) break;
            usleep(100000);
        }
    } else {
        while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return fail("wait failed");
    }
    /*
     * Without a handover the launcher must not leave a root process behind, so
     * the attempt-scoped reaper already ran above. With a handover the executor
     * *is* the product's daemon and stays.
     */
    const int code = handed_over ? 0 : cancelled ? 137
        : WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    (void)send_all(control, "X", 1);
    (void)number(control, static_cast<uint32_t>(code));
    return code;
}
}
int main(int argc, char** argv) {
    open_logs();
    g_self_starttime = starttime_of("/proc/self/stat");
    g_start_wallclock = std::time(nullptr);
    // Fixed argv only: no arbitrary command, su fallback, key, policy writes or
    // installer entry. The optional sixth argument is the pre-entry enforcing
    // value recorded by the App; providers that restore through their own
    // script omit it.
    if (argc != 6 && argc != 7) return finish(kStageArguments, fail("usage: ENDPOINT NONCE MANAGER_UID BOOT_ID provider [ENFORCE]"));
    std::array<unsigned char, 32> nonce{};
    int manager_uid = 0;
    int expected_enforce = -2;
    const uint32_t provider = !std::strcmp(argv[5], "ghostlock") ? 1u : !std::strcmp(argv[5], "dirtyfrag") ? 2u : 0u;
    if (!maplesu_lease_endpoint(argv[1]) || !maplesu_lease_nonce(argv[2], nonce.data()) ||
        !maplesu_lease_decimal(argv[3], 10000, &manager_uid) || !maplesu_lease_boot_id(argv[4]) || !provider)
        return finish(kStageArguments, fail("invalid lease arguments"));
    // The provider transient belongs to the provider that dispatched this helper.
    // DirtyFrag disables SELinux in the kernel before the helper runs, so the
    // consumer owns the restoration; Ghostlock restores through its own script.
    g_session.transient = provider == 2u;
    if (provider == 1u && argc == 7 && argv[6][0] == 'r') {
        // Ghostlock restore record: r<rc>:<enforce>:<checkreqprot>:<o|d>
        int rc = -1;
        int enforcing = -1;
        int checkreqprot = -1;
        char source = 'd';
        int used = 0;
        if (std::sscanf(argv[6] + 1, "%d:%d:%d:%c%n", &rc, &enforcing, &checkreqprot, &source, &used) != 4 ||
            argv[6][used + 1] != '\0' || rc < 0 || rc > 255 ||
            enforcing < -1 || enforcing > 1 || checkreqprot < -2 || checkreqprot > 1 ||
            (source != 'o' && source != 'd'))
            return finish(kStageArguments, fail("invalid ghostlock restore record"));
        g_session.ghostlock_report = true;
        g_session.ghostlock_rc = rc;
        g_session.ghostlock_enforcing = enforcing;
        g_session.ghostlock_checkreqprot = checkreqprot;
        g_session.ghostlock_source = source == 'o' ? 0 : 1;
    } else if (argc == 7) {
        // "u" means the ordinary App could not read selinuxfs, so the pre-entry
        // value is not observable from inside the app domain: the consumer
        // applies the documented baseline and labels it as such.
        if (!std::strcmp(argv[6], "u")) expected_enforce = -2;
        else {
            int value = -1;
            if (!maplesu_lease_decimal(argv[6], 0, &value) || value > 1) return finish(kStageArguments, fail("invalid enforce argument"));
            expected_enforce = value;
        }
    }
    g_session.expected = expected_enforce;
    if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0)
        return finish(kStageRootWorker, fail("root worker required"));
    std::string boot, domain, enforce;
    if (!text_file("/proc/sys/kernel/random/boot_id", boot, 128) || boot != argv[4] ||
        !text_file("/proc/self/attr/current", domain, 256) ||
        !text_file("/sys/fs/selinux/enforce", enforce, 8) || (enforce != "0" && enforce != "1"))
        return finish(kStageIdentity, fail("worker identity unavailable"));
    log_line("maplesu-root-consumer: start provider=%s pid=%d uid=%d domain=%s enforcing=%s transient=%d\n",
             argv[5], static_cast<int>(getpid()), static_cast<int>(getuid()), domain.c_str(),
             enforce.c_str(), g_session.transient ? 1 : 0);
    const int control = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (control < 0) return finish(kStageSocket, fail("control socket failed"));
    g_session.control = control;
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    const size_t length = std::strlen(argv[1]);
    std::memcpy(address.sun_path + 1, argv[1], length);
    timeval timeout{10, 0};
    setsockopt(control, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(control, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(control, reinterpret_cast<sockaddr*>(&address),
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + length)) != 0) return finish(kStageSocket, fail("control connect failed"));
    ucred peer{}; socklen_t size = sizeof(peer);
    if (getsockopt(control, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
        peer.uid != static_cast<uid_t>(manager_uid) || peer.pid <= 1) return finish(kStagePeer, fail("manager peer invalid"));
    /*
     * S12: the v2 identity frame adds the worker's start time (defeats pid reuse) and
     * an explicit capability flag. Both are written after uid; the App accepts v1 and
     * v2, but only v2 lets it record provesWorkerIdentity.
     */
    if (!send_all(control, "MJBL", 4) || !number(control, 2) || !number(control, provider) ||
        !number(control, static_cast<uint32_t>(getpid())) || !number(control, static_cast<uint32_t>(getuid())) ||
        !number64(control, g_self_starttime) || !number(control, 1) ||
        !send_all(control, nonce.data(), nonce.size()) || !field(control, boot) || !field(control, domain) ||
        !number(control, enforce == "1" ? 1u : 0u) || !number(control, static_cast<uint32_t>(prctl(PR_GET_SECCOMP))))
        return finish(kStagePeer, fail("identity send failed"));
    std::array<int, 3> descriptors{-1, -1, -1};
    if (receive_stdio(control, descriptors) != 0) return finish(kStageStdio, fail("stdio admission failed"));
    log_line("maplesu-root-consumer: lease formed; entry policy restoration follows the shell\n");
    const int result = supervise(control, descriptors);
    return finish(0, result);
}
