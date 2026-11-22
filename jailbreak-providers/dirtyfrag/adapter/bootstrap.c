/*
 * _GNU_SOURCE is required for exactly one declaration: pipe2(), which the UMH daemon
 * slot (design §4.3) uses for its CLOEXEC exec-report channel. bionic guards pipe2
 * behind __USE_GNU, and hand-declaring a libc function to avoid the feature macro
 * would be worse than enabling it: the macro only widens the declarations, and every
 * other call this file makes is POSIX/ANSI either way. It must precede every include.
 */
#define _GNU_SOURCE 1
#include "lease_contract.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#ifndef MAPLESU_ATTEMPT_DIRECTORY
#define MAPLESU_ATTEMPT_DIRECTORY "/data/user_de/0/dev.maplesu.manager"
#endif
#ifndef MAPLESU_ATTEMPT_FILE
#define MAPLESU_ATTEMPT_FILE "maplesu-dirtyfrag.attempt"
#endif
#define MAPLESU_LOG_PRIMARY MAPLESU_ATTEMPT_DIRECTORY "/maplesu-provider.log"
#define MAPLESU_DISARM MAPLESU_ATTEMPT_DIRECTORY "/maplesu-disarmed"
#define MAPLESU_TEARDOWN "maplesu-teardown"
#define MAPLESU_LOG_FALLBACK "/dev/maplesu-provider.log"
/* In-kernel root (IR) route. The App stages both files next to this bootstrap
 * and creates the marker; the module itself is generic across releases and the
 * spec is what makes it target-exact. */
#define MAPLESU_USE_IR MAPLESU_ATTEMPT_DIRECTORY "/use-ir"
/* W0 decision experiment (manual 8 / W0): apply the patches, restore the entry
 * policy, and stay in the current boot so a caller can probe whether ART survives
 * in this kernel state. Never present in a product run. */
#define MAPLESU_IR_NO_REBOOT MAPLESU_ATTEMPT_DIRECTORY "/ir-no-reboot"
#define MAPLESU_IR_MODULE_FILE "maplesu_ir.ko"
#define MAPLESU_IR_CANARY MAPLESU_ATTEMPT_DIRECTORY "/maplesu_ir_canary.ko"
/* Bring-up only: patch the real spec into the probed image so a staged variant
 * follows the product path exactly. */
#define MAPLESU_IR_PROBE_WITH_SPEC MAPLESU_ATTEMPT_DIRECTORY "/ir-probe-with-spec"
#define MAPLESU_IR_SPEC_FILE "ir.spec"
#define MAPLESU_IR_MODULE_NAME "maplesu_ir"
#define MAPLESU_IR_SECTION ".ir_spec"
#define MAPLESU_IR_MODULE_LIMIT (256 * 1024)
#define MAPLESU_IR_SPEC_LIMIT 4096
/* bionic's <sys/syscall.h> already provides these, but naming them here keeps the
 * two numbers that matter reviewable in one place. */
#define MAPLESU_NR_INIT_MODULE 105
#define MAPLESU_NR_SYSLOG 116
/* syslog(2) actions: READ_ALL copies the ring buffer without clearing it. */
#define MAPLESU_SYSLOG_READ_ALL 3
#define MAPLESU_NR_FINIT_MODULE 273
#define MAPLESU_NR_MEMFD_CREATE 279
#define MAPLESU_MFD_CLOEXEC 0x0001U
/* Opt-in only: hand the escalation to a staged KernelSU daemon instead of the
 * MapleSU consumer. KernelSU is a control experiment here - it proved the
 * exploit itself is sound on this device - not the product backend, so the
 * branch runs only when this marker exists. */
#define MAPLESU_USE_KSU MAPLESU_ATTEMPT_DIRECTORY "/use-ksu"
#define MAPLESU_KSU_PACKAGE "dev.maplesu.manager" /* the module serves OUR manager */
#define MAPLESU_KSUD_INSTALLED "/data/adb/ksud"
/*
 * P1 (2026-10-31): where the App stages its own daemon for the *helper* route.
 * `DirtyfragAttempt.stageKernelSuDaemon()` copies libksud_ksu.so to
 * `context.getFilesDir().getParentFile()/ksud`, which is the credential-protected
 * CE directory below. Stage-1 gets the same file as its eighth attempt field; the
 * module-dispatched helper has no attempt document to read, so it needs the
 * App-owned location as a constant. Do not derive it from MAPLESU_ATTEMPT_DIRECTORY:
 * that one is the device-protected DE directory and never holds the daemon.
 */
#define MAPLESU_CE_KSUD "/data/user/0/dev.maplesu.manager/ksud"
/* Upper bound for the reference's unbounded "wait for the detached daemon".
 * ksud's own shared boot-stage deadline is 35 s; this leaves room for the module
 * mounts and the Manager restart that follow it. */
#define MAPLESU_LATE_LOAD_SECONDS 120

/*
 * ============================================================================
 * UMH mode (step-3): the module -> kernel-domain helper handover
 * ============================================================================
 * This same binary is both stage-1 (exec'd by the stock dfroot.ko as `<CE>/bs`,
 * argc == 1) and the helper our own module dispatchd as
 * `<CE>/bs --umh --entry-enforcing <0|1>` (design
 * docs/patching/maplesu-step3-umh-mode-design-2026-10-29.md §2). One binary, one
 * path, two modes.
 *
 * The mode is selected by *argv only* (D3-1). It is deliberately NOT selected by
 * "does the attempt document exist": that document is stage-1's one-shot input and
 * stage-1 unlinks it (main below), so using it as the discriminator would confuse
 * "a second instance" with "a normal boot with no attempt". The exploit route's
 * argv is always `{<bs>, NULL}` (`sh -c exec`, upstream/lkm/dfroot.c:90), so the
 * two cannot collide.
 *
 * What UMH mode must NEVER do, and why each one is a real breakage:
 *   - open, require or unlink the attempt document  -> the second instance would
 *     die on ENOENT (the first one consumed the document), or steal stage-1's input;
 *   - touch /dev/dfm*, /dev/dfme*, /dev/dfmw*, /dev/df -> the native stage polls
 *     those markers as progress, so a second writer is read as "the consumer
 *     started", and /dev/df is init's one-shot re-entry guard (removing it re-arms
 *     the hook; DEV-88 panicked this kernel that way);
 *   - call emergency_teardown() -> it unlinks all of the above;
 *   - execv the consumer -> it needs the lease endpoint/nonce that only stage-1
 *     parses;
 *   - ksu_handoff()/set_current_domain() -> the product UMH sequence is mutually
 *     exclusive with the use-ksu control experiment. The one exception is the P1
 *     marker-gated branch at the top of umh_main(): when the App wrote
 *     MAPLESU_USE_KSU and staged <CE>/ksud, this process *is* the KernelSU
 *     handoff and returns before any hook work, so no hook state exists to skip;
 *   - soft reboot -> step-3 acceptance needs restore *and* unload in one boot;
 *   - assume enforcing == 1 -> a permissive-boot device must be left permissive.
 *
 * What it does instead: read the App's pre-entry baseline (`<DE>/maplesu-hook-env`),
 * close the window from *inside* the window - once, from the forked unload child, and
 * only after delete_module() - read it back, and leave three evidence files behind plus
 * a live attestation worker. argv's `--entry-enforcing` is kept as the kernel's
 * *inherited observation* (it is the only value the module could see, and it is what
 * `status.enforcingAtLease` reports); it is no longer the restore target. Ordered as
 * design §5.1; every descriptor it will need is opened while the window is still open,
 * because after the restore this process (u:r:kernel:s0) is denied app-data lookups.
 */
#define MAPLESU_HOOK_EVIDENCE MAPLESU_ATTEMPT_DIRECTORY "/maplesu-hook.json"
#define MAPLESU_HOOK_UNLOAD_EVIDENCE \
    MAPLESU_ATTEMPT_DIRECTORY "/maplesu-hook-unload.json"
/*
 * Step-4 (D2, design §2.1): the pre-entry baseline the App writes before the window
 * opens. The helper can only ever read 0 here (the module loads after dfroot already
 * wrote 0), so the *target* has to come from the one subject that was alive before
 * the window: the App. It reports a target plus its provenance, never a bare value.
 *
 * Format (frozen, one line, space separated, fixed key order, <= 192 bytes, optional
 * trailing newline):
 *   schema=maplesu.hook.env.v1 boot=<boot_id> attempt=<attemptId>
 *   expected=<0|1|-1> source=<observed|baseline|unknown>
 */
#define MAPLESU_HOOK_ENV_NAME "maplesu-hook-env"
#define MAPLESU_HOOK_ENV_SCHEMA "maplesu.hook.env.v1"
#define MAPLESU_HOOK_ENV_MAX 192
/*
 * Step-4 (D4, design §3.2): the daemon slot's occupant. `bs --attest` is the same
 * binary in a third mode: it binds a unix socket in the attempt directory, proves its
 * own identity through the kernel's SO_PEERCRED ucred, and answers one enforcing
 * readback per connection from a pool of descriptors opened inside the window.
 */
#define MAPLESU_HOOK_DAEMON_DOC MAPLESU_ATTEMPT_DIRECTORY "/maplesu-hook-daemon.json"
#define MAPLESU_HOOK_DAEMON_SOCK_FMT "/maplesu-hook-%.8s.sock"
#define MAPLESU_HOOK_ATTEST_SCHEMA "maplesu.hook.attest.v1"
#define MAPLESU_HOOK_ATTEST_TOKEN "--attest"
#define MAPLESU_ATTEST_POOL 8
#define MAPLESU_ATTEST_SERVES 8
#define MAPLESU_ATTEST_ENV_RECORD_FD "MAPLESU_ATTEST_RECORD_FD"
#define MAPLESU_ATTEST_ENV_ENFORCE_FD "MAPLESU_ATTEST_ENFORCE_FD"
#define MAPLESU_ATTEST_ENV_DIR_FD "MAPLESU_ATTEST_DIR_FD"
/*
 * R-D1: the socket inode's SELinux context. A filesystem AF_UNIX socket inherits the
 * parent directory's *type* but its creator's MLS level, and this worker's domain is
 * `u:r:kernel:s0` (no categories) while the App's is `untrusted_app:s0:c225,…`. The
 * MLS constraint on `unix_stream_socket connectto` compares the two levels for
 * equality, so the App's connect() is refused before it can ever reach this process's
 * accept queue (the device showed zero `attest client` lines). The helper copies the
 * attempt directory's own context onto the socket so the object becomes exactly the
 * one the App itself would have created in its own data directory.
 *
 * Bounded by construction: one 256-byte stack buffer, no allocation, and the only
 * paths touched are the compile-time `<DE>` constant and the socket path derived from
 * it (no new `/data/` literal - G5). Fail-closed: every failure is logged and ignored,
 * so the socket, the daemon document and the handover survive unchanged.
 */
#define MAPLESU_SELINUX_XATTR "security.selinux"
#define MAPLESU_ATTEST_LABEL_MAX 256
#define MAPLESU_STAGE2_NAME "maplesu_stage2.ko"
#define MAPLESU_DAEMON_NAME "maplesu-daemon"
#define MAPLESU_HOOK_MODULE_NAME "maplesu_root"
/*
 * L3 ABI v2 (controller decision, 2026-10-31; replaces ABI v1). The kernel-side gate
 * is armed from this helper, after the stage-2 image is resident and before the
 * restore closes the window:
 *
 *   prctl(option = 4 (PR_SET_DUMPABLE), arg2 = 0 (ARM),
 *         arg3 = token_lo, arg4 = token_hi, arg5 = owner_uid)
 *
 * The magic is the argument shape, not a private option number: a call is this
 * gate's only when option == 4 and (arg3 | arg4) != 0. A real
 * prctl(PR_SET_DUMPABLE, 0|1) carries a zero token and stays an ordinary prctl.
 *
 * Because PR_SET_DUMPABLE is a *real* option, its native return for arg2 in {0, 1} is
 * 0 - a granted ARM, a denied ARM and "no `maplesu_l3` module at all" are
 * indistinguishable by rc. So rc == 0 is only a necessary condition here, and the
 * ARM success criterion is the module's own acknowledgement in the kernel ring
 * buffer:
 *
 *   maplesu_l3: armed owner=<dir_uid> pool=<n>
 *
 * The helper samples that marker's occurrence count immediately before the call and
 * again immediately after it, both inside the open window, and only a *growth* is
 * ARMED (existence alone would accept a stale line from an earlier attempt in the
 * same boot). Readable-but-unchanged is suGateReason=ARM_NOT_OBSERVED; an unreadable
 * ring buffer is KLOG_UNAVAILABLE (fail closed). A kernel without the module, an
 * unloaded module and a refused ARM therefore all land on suGate=UNAVAILABLE, which
 * is evidence only: DAEMON_READY must not depend on L3 (the module and this leg land
 * separately).
 *
 * B1 (controller decision, 2026-10-31): the stage-2 slot *is* the L3 slot, so a module
 * the kernel refuses to load is equally an L3-only fact. hook_stage2()'s LOAD_FAILED
 * branch therefore raises no failure token: it records stage2.state=LOAD_FAILED with
 * the kernel's rc/errno, leaves suGate=UNAVAILABLE and publishes suGateReason, and
 * hook_verdict() no longer reads that state. A *staged input* that is not a loadable
 * image at all is still INVALID and still fails the handover - that is a stager defect,
 * not "the module did not load", and it must not be reported as a working L3.
 *
 * The 64-bit token is generated here, never logged, and handed to the App through the
 * two evidence records (`suToken` is 16 lowercase hex digits). The ARM owner is the
 * attempt directory's uid - the same subject hook_daemon() already admits - so the SU
 * op (arg2 = 1) can only ever commit a root cred to the App that armed the gate.
 *
 * The worker is a separate exec of this same binary, so the token has to cross that
 * boundary. It travels in the environment (MAPLESU_SU_TOKEN), never in argv: argv is
 * /proc/<pid>/cmdline, mode 0444 and world-readable for the worker's whole lifetime,
 * while /proc/<pid>/environ is mode 0400 owned by the process's own uid and gated by
 * the kernel's ptrace check - an app uid (>= 10000) cannot read a root worker's
 * environment through DAC or through SELinux. The variable is set immediately before
 * execv() and is never written to disk, so it dies with the worker.
 */
/* ABI v2 (controller decision, 2026-10-31): the option is the kernel's own
 * PR_SET_DUMPABLE, arg2 selects the op, arg3/arg4 carry the token's halves and arg5
 * the owner. The magic is option == PR_SET_DUMPABLE && (arg3 | arg4) != 0, so an
 * ordinary prctl(PR_SET_DUMPABLE, 0|1) is never this gate's call. Both ops reuse the
 * option's native return value (0); ARM's proof is the module's log line below. */
#define MAPLESU_L3_PR_SET_DUMPABLE 4
#define MAPLESU_L3_OP_ARM 0
#define MAPLESU_L3_OP_SU 1
#define MAPLESU_L3_TOKEN_DIGITS 16
/* "maplesu_l3: armed owner=4294967295 " is 37 bytes; 64 is a deliberate margin. */
#define MAPLESU_L3_MARKER_MAX 64
/* The module's ARM acknowledgement (ABI v2 contract), owner substituted. The token is
 * not in the line, and it must never be added to it. */
#define MAPLESU_L3_ARM_MARKER_FMT "maplesu_l3: armed owner=%u "
#define MAPLESU_L3_GATE_ARMED "ARMED"
#define MAPLESU_L3_GATE_UNAVAILABLE "UNAVAILABLE"
/* Why suGate is UNAVAILABLE, in the two evidence records (B1). Absent while ARMED, so
 * an armed record keeps exactly the frozen suToken/suGate pair. The strings are fixed
 * codes, not caller text: the worker re-validates them against this same list. */
#define MAPLESU_L3_REASON_NOT_EXERCISED "STAGE2_NOT_EXERCISED"
#define MAPLESU_L3_REASON_INVALID "STAGE2_INVALID"
#define MAPLESU_L3_REASON_LOAD_FAILED "STAGE2_LOAD_FAILED"
#define MAPLESU_L3_REASON_ARM_REJECTED "ARM_REJECTED"
#define MAPLESU_L3_REASON_WINDOW_CLOSED "WINDOW_CLOSED"
/* ABI v2's second confirmation (Y2): prctl() == 0 was not enough. The ring buffer was
 * readable but did not grow (the module never acknowledged this ARM), or it could not
 * be read at all - both fail closed and never publish a token. */
#define MAPLESU_L3_REASON_ARM_NOT_OBSERVED "ARM_NOT_OBSERVED"
#define MAPLESU_L3_REASON_KLOG_UNAVAILABLE "KLOG_UNAVAILABLE"
/* The worker's own default: nothing reached it, so it cannot claim ARMED. */
#define MAPLESU_L3_REASON_NOT_ARMED "NOT_ARMED"
/* The token's transport to the attest worker (B1): environment, never argv. */
#define MAPLESU_L3_ENV_TOKEN "MAPLESU_SU_TOKEN"
#define MAPLESU_L3_ENV_REASON "MAPLESU_SU_GATE_REASON"
#define MAPLESU_ENFORCE_PATH "/sys/fs/selinux/enforce"
#define MAPLESU_BOOT_ID_PATH "/proc/sys/kernel/random/boot_id"
#define MAPLESU_CURRENT_DOMAIN_PATH "/proc/self/attr/current"
/* Same asm-generic table as MAPLESU_NR_INIT_MODULE (105): delete_module is 106.
 * The static assertion below keeps the bare number and bionic's SYS_* name from
 * drifting apart, which is why both are named here. */
#define MAPLESU_NR_DELETE_MODULE 106
#define MAPLESU_NR_CLOCK_GETTIME 113
#define MAPLESU_CLOCK_REALTIME 0
_Static_assert(SYS_delete_module == MAPLESU_NR_DELETE_MODULE,
               "delete_module syscall number drifted from the asm-generic table");
/* L3 (ABI v2) enters through exactly this slot (167 on arm64 asm-generic). The module
 * observes it with a kprobe on `__arm64_sys_prctl` (no sys_call_table write); naming
 * both numbers and asserting them is the same discipline as delete_module above: a
 * drift fails the build, not the device. */
#define MAPLESU_NR_PRCTL 167
_Static_assert(SYS_prctl == MAPLESU_NR_PRCTL,
               "prctl syscall number drifted from the asm-generic table");
/* Bounded retry for the unload. Only EWOULDBLOCK/EBUSY are retried (the module may
 * still be referenced for a few microseconds after init_module() returns), anything
 * else is final immediately (design §6).
 *
 * The window, not the attempt count, is the bound: it must outlast the parent's
 * 1500 ms wait, because R12's mitigation is exactly "the parent exits, init_module
 * returns and releases module_mutex, then the child's retry succeeds". A 5 x 100 ms
 * budget would give up while the parent is still waiting, which is the one case the
 * design's fork exists for. 4 s is still bounded and the parent never waits for it.
 */
#define MAPLESU_DELETE_RETRY_USEC 100000
#define MAPLESU_DELETE_WINDOW_MS 4000
#define MAPLESU_DELETE_ATTEMPTS (MAPLESU_DELETE_WINDOW_MS / 100 + 1)
/* Parent-side bound on the unload child (design §6/§10 R12). */
#define MAPLESU_UNLOAD_WAIT_MS 1500
#define MAPLESU_UNLOAD_POLL_USEC 25000
/* 1536, not 1280: L3 (ABI v2) adds suToken/suGate to both the attempt record and the
 * daemon record, and a truncated document is not evidence. The worst-case field set
 * (95-byte attempt id, PATH_MAX-bounded helper/stage2/daemon paths, 95-byte domain)
 * fits with margin; each writer logs `truncated` if snprintf still overflows. */
#define MAPLESU_HOOK_JSON_MAX 1536
#define MAPLESU_HOOK_SMALL_MAX 96

static int logs[2] = {-1, -1};

static void open_logs(void) {
    /* Readable by the App and by an observing shell: the privileged half starts
     * with /dev/null stdio, so this file is the only durable record and it must
     * survive the App process dying. It carries no nonce, key or credential. */
    logs[0] = open(MAPLESU_LOG_PRIMARY, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    logs[1] = open(MAPLESU_LOG_FALLBACK, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    for (int i = 0; i < 2; ++i) if (logs[i] >= 0) (void)fchmod(logs[i], 0644);
}

static void log_line(const char *format, ...) {
    char text[512];
    va_list arguments;
    va_start(arguments, format);
    const int count = vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    if (count <= 0) return;
    const size_t size = (size_t)(count < (int)sizeof(text) ? count : (int)sizeof(text) - 1);
    for (int i = 0; i < 2; ++i) {
        if (logs[i] < 0) continue;
        (void)write(logs[i], text, size);
        /*
         * Flush to the block device. A kernel panic loses dirty page-cache pages,
         * and this log is the only record of what the privileged half did before
         * the panic: without fsync the last lines of a fatal attempt simply vanish,
         * which is exactly what happened during bring-up (DEV-114).
         */
        (void)fsync(logs[i]);
    }
    (void)write(STDERR_FILENO, text, size);
}

/* The documented Android baseline, used only when the App could not observe the
 * entry value. The consumer records the same distinction in its report. */
static char entry_enforcing(const char *field) {
    return field != NULL && (field[0] == '0' || field[0] == '1') && field[1] == '\0' ? field[0] : '1';
}

/*
 * Switches the SELinux domain of this process or of its next exec, exactly like
 * the reference implementation's run_ctx(). "exec" applies to the next execve;
 * "current" applies immediately and is what the reference uses to become init
 * before KernelSU is loaded.
 */
static int set_domain(const char *attribute, const char *context) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/attr/%s", attribute);
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const ssize_t written = write(fd, context, strlen(context));
    const int saved = errno;
    close(fd);
    errno = saved;
    return written == (ssize_t)strlen(context) ? 0 : -1;
}

/*
 * Reference parity: the consumer - and the ART runtime it starts - must not keep
 * the kernel domain the module dispatched from.
 */
static int set_exec_domain(const char *context) { return set_domain("exec", context); }

/*
 * Reference parity: the switch has to happen while SELinux is still permissive.
 * Once KernelSU is live only init may enter u:r:ksu:s0, so a caller that wants
 * the KernelSU handoff first becomes init here.
 */
static int set_current_domain(const char *context) { return set_domain("current", context); }

/*
 * Reference run_ctx(): run one program in a forked child, optionally in a new
 * exec domain, and report its exit status (-1 when it did not exit normally).
 * The reference uses this for both hops of its KernelSU handoff.
 */
static int run_ctx(const char *context, char *const argv[]) {
    const pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        /* A refused domain switch must not stop the program: the reference
         * ignores the write result as well and lets the exec decide. */
        if (context != NULL) (void)set_exec_domain(context);
        execv(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*
 * Reference late_load_running(): is any "ksud ... late-load" process alive?
 * /proc/<pid>/cmdline is NUL separated, so the separators are rewritten to
 * spaces before the two substrings are searched.
 */
static int late_load_running(void) {
    DIR *dir = opendir("/proc");
    if (dir == NULL) return 0;
    struct dirent *entry;
    int found = 0;
    int scanned = 0;
    while (!found && (entry = readdir(dir)) != NULL && scanned < 8192) {
        char *end = NULL;
        const long pid = strtol(entry->d_name, &end, 10);
        if (pid <= 0 || end == NULL || *end) continue;
        ++scanned;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char cmdline[256];
        const ssize_t count = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (count <= 0) continue;
        cmdline[count] = '\0';
        for (ssize_t i = 0; i < count; ++i) if (!cmdline[i]) cmdline[i] = ' ';
        if (strstr(cmdline, "ksud") != NULL && strstr(cmdline, "late-load") != NULL) found = 1;
    }
    closedir(dir);
    return found;
}

/*
 * Reference: while (late_load_running()) sleep(1);
 *
 * ksud late-load double-forks (utils::daemonize): the child run_ctx() waits for
 * exits as soon as the daemon has detached, so its exit status says nothing
 * about the work that is still running. Wait for the detached daemon to finish,
 * bounded so a hung module script cannot keep this helper alive for ever.
 */
static int wait_for_late_load(int seconds) {
    int waited = 0;
    while (waited < seconds && late_load_running()) {
        sleep(1);
        ++waited;
    }
    return waited;
}

/*
 * Reference adopt_zygote_env(): the kernel helper inherits the module's minimal
 * environment, so the Android runtime variables are taken from the live zygote.
 * The reference asks "pidof zygote64 zygote"; scanning /proc for the same
 * process names avoids depending on a shell and on PATH before PATH exists.
 * The lowest pid wins, which is the first pid pidof would print.
 */
static pid_t find_zygote(void) {
    DIR *dir = opendir("/proc");
    if (dir == NULL) return -1;
    struct dirent *entry;
    pid_t sixty_four = -1;
    pid_t thirty_two = -1;
    while ((entry = readdir(dir)) != NULL) {
        char *end = NULL;
        const long pid = strtol(entry->d_name, &end, 10);
        if (pid <= 0 || end == NULL || *end) continue;
        char path[64];
        char comm[32];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        const ssize_t count = read(fd, comm, sizeof(comm) - 1);
        close(fd);
        if (count <= 0) continue;
        comm[count] = '\0';
        char *newline = strchr(comm, '\n');
        if (newline != NULL) *newline = '\0';
        if (!strcmp(comm, "zygote64")) {
            if (sixty_four < 0 || (pid_t)pid < sixty_four) sixty_four = (pid_t)pid;
        } else if (!strcmp(comm, "zygote")) {
            if (thirty_two < 0 || (pid_t)pid < thirty_two) thirty_two = (pid_t)pid;
        }
    }
    closedir(dir);
    return sixty_four >= 0 ? sixty_four : thirty_two;
}

/*
 * Copies the zygote environment into this process with putenv(). This is the
 * environment init gives every Android runtime and the kernel helper has none of
 * it, so the consumer - which starts app_process64 - otherwise depends on the
 * two ART variables the App publishes separately. Non-fatal, exactly like the
 * reference: the attempt continues without it.
 */
static int adopt_zygote_env(void) {
    const pid_t zygote = find_zygote();
    if (zygote <= 0) return -1;
    char path[48];
    snprintf(path, sizeof(path), "/proc/%d/environ", (int)zygote);
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    static char environment[16384];
    const ssize_t count = read(fd, environment, sizeof(environment) - 1);
    const int saved = errno;
    close(fd);
    errno = saved;
    if (count <= 0) return -1;
    environment[count] = '\0';
    /* A full buffer means the last entry may have been cut in half; it is
     * skipped rather than adopted with a wrong value. */
    const int truncated = count == (ssize_t)sizeof(environment) - 1;
    int adopted = 0;
    for (ssize_t offset = 0; offset < count; ) {
        const char *entry = environment + offset;
        const size_t remaining = (size_t)(count - offset);
        const void *nul = memchr(entry, '\0', remaining);
        const size_t length = nul != NULL ? (size_t)((const char *)nul - entry) : remaining;
        /* putenv() keeps the pointer, so only complete "name=value" entries in
         * the static buffer are handed over. */
        const int complete = nul != NULL || !truncated;
        if (complete && length > 0 && entry[0] != '=' && memchr(entry, '=', length) != NULL &&
            putenv((char *)entry) == 0) ++adopted;
        offset += (ssize_t)length + 1;
    }
    log_line("maplesu-dirtyfrag: zygote env pid=%d bytes=%d adopted=%d\n",
             (int)zygote, (int)count, adopted);
    return adopted > 0 ? 0 : -1;
}

/*
 * Reference parity (DirtyFragX bootstrap.c): before any userspace program runs, the
 * writable block devices that carry system/vendor metadata are switched read-only
 * with BLKROSET. Without it the kernel can still flush the dirty pages the exploit
 * created straight to the block device, which corrupts the filesystem and reboots
 * the device - exactly the instability MapleSU showed after dispatch.
 */
#define MAPLESU_BLKROSET 0x125d

static int should_ro(const char *name) {
    const size_t len = strlen(name);
    if (!strcmp(name, "super")) return 1;
    if (!strcmp(name, "misc")) return 1;
    if (!strcmp(name, "steady")) return 1;
    if (len >= 2 && name[len - 2] == '_' && (name[len - 1] == 'a' || name[len - 1] == 'b')) return 1;
    return 0;
}

static int set_partitions_ro(void) {
    DIR *dir = opendir("/dev/block/by-name");
    if (!dir) return -1;
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!should_ro(ent->d_name)) continue;
        char path[160];
        snprintf(path, sizeof(path), "/dev/block/by-name/%s", ent->d_name);
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
            int on = 1;
            ioctl(fd, MAPLESU_BLKROSET, &on);
        }
        close(fd);
    }
    closedir(dir);
    return 0;
}

static int write_byte(const char *path, char value) {
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const ssize_t written = write(fd, &value, 1);
    const int saved = errno;
    close(fd);    errno = saved;
    return written == 1 ? 0 : -1;
}

static int read_byte(const char *path) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char value = 0;
    const ssize_t got = read(fd, &value, 1);
    close(fd);
    if (got != 1) return -1;
    return value == '0' ? 0 : value == '1' ? 1 : -1;
}

/*
 * The same read through a descriptor opened earlier (design §5.1 step 11/12a):
 * after the enforcement restore this process is denied app-data lookups, so the only
 * safe way to read selinuxfs again is through descriptors that already exist.
 *
 * One read per descriptor, and no lseek: selinuxfs attributes answer from the file
 * position, and whether `enforce` supports seeking is a kernel detail this design does
 * not need to depend on. Every readback therefore gets its own pre-opened descriptor
 * (four of them, see the pre-open step) - the design's "second fd to avoid the
 * read-cursor problem", just carried to its conclusion because the baseline rung needs
 * a third read and the parent's post-unload check a fourth.
 */
static int read_byte_fd(int fd) {
    char value = 0;
    if (fd < 0) return -1;
    if (read(fd, &value, 1) != 1) return -1;
    return value == '0' ? 0 : value == '1' ? 1 : -1;
}

/*
 * DirtyFragX milestone markers. The reference bootstrap writes exactly this set,
 * in exactly this order: dfm1..dfm6 for the steps it reaches, dfme0..dfme2 for
 * the fatal ones, dfmw0..dfmw1 for the non-fatal ones. Both the native stage's
 * result table and the App's progress reporting key off the names and the order,
 * never off the payload, so the names are kept even though the payload differs:
 * this bootstrap reads the MapleSU attempt document instead of ksud preferences
 * and, by default, hands the attempt to the MapleSU root consumer instead of
 * ksud. The reference's KernelSU handoff exists only as the opt-in
 * MAPLESU_USE_KSU control route. The step each name stands for is documented at
 * its touch site.
 *
 * A marker is a diagnostic, never a precondition: a failed touch is ignored, as
 * it is upstream (there /dev may already exist with a hostile owner).
 */
static void touch(const char *path) {
    const int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
    if (fd >= 0) close(fd);
}

/*
 * The milestone that reports why this attempt is ending.  emergency_teardown
 * keeps it: the native stage polls /dev every 10 ms and prints the matching
 * line, so erasing it here would turn every privileged failure into a silent
 * timeout.  The stage consumes it after printing (and the next attempt's
 * stage-start hygiene removes any survivor), so it never outlives the
 * observation window.
 */
static const char *g_failure_marker;

/*
 * S09: one bounded teardown for the failure paths that happen before (or instead
 * of) the consumer. It mirrors the consumer's ordering exactly, because the
 * ordering is what makes the restore safe:
 *   1. wait for the native stage's disarm proof (bounded; the stage keeps
 *      restoring the file pages independently of this process);
 *   2. remove the stage markers;
 *   3. KEEP the re-entry guard, whatever the proof says (step-4 D1/C6). Removing
 *      it re-arms init's one-shot hook, which re-runs dfroot_init() inside the
 *      already-restored window and panicked this kernel (DEV-88). The consumer has
 *      done the same since 2026-10-28 ("guard kept for this boot"); this was the
 *      last code path that could still remove it;
 *   4. write the entry policy back and read it back;
 *   5. record the outcome in the attempt directory for the App's verdict.
 */
static int emergency_teardown(int code, const char *reason, const char *enforce_field) {
    const char target = entry_enforcing(enforce_field);
    log_line("maplesu-dirtyfrag: teardown start code=%d reason=%s\n", code, reason);
    const int stage_running = access("/dev/dfm0", F_OK) == 0;
    int disarmed = 0;
    for (int i = 0; stage_running && i < 400; ++i) {
        if (access(MAPLESU_DISARM, F_OK) == 0) { disarmed = 1; break; }
        usleep(50000);
    }
    int markers = 0;
    static const char *const marker_paths[] = {
        "/dev/dfm0", "/dev/dfm1", "/dev/dfm2", "/dev/dfm3", "/dev/dfm4", "/dev/dfm5",
        "/dev/dfm6", "/dev/dfme0", "/dev/dfme1", "/dev/dfme2", "/dev/dfmw0", "/dev/dfmw1"};
    for (size_t i = 0; i < sizeof(marker_paths) / sizeof(marker_paths[0]); ++i) {
        /* The reason marker is the one marker this teardown must not remove. */
        if (g_failure_marker != NULL && !strcmp(marker_paths[i], g_failure_marker)) continue;
        if (unlink(marker_paths[i]) == 0) continue;
        if (errno != ENOENT && access(marker_paths[i], F_OK) == 0) ++markers;
    }
    /*
     * TR-3 / C6 / DEV-88: the re-entry guard is kept for the rest of the boot.
     *
     * Removing it re-arms init's one-shot hook, which re-runs dfroot_init inside the
     * restored window and panicked this kernel (DEV-88). The consumer has said so
     * since 2026-10-28 (root_consumer.cpp "guard kept for this boot"), and this is
     * the last code path that could still remove it. `disarmed` keeps its own
     * meaning - the handshake that says the native stage really finished - it just
     * no longer authorises an unlink.
     */
    if (disarmed) unlink(MAPLESU_DISARM);
    if (access("/dev/df", F_OK) == 0) {
        log_line("maplesu-dirtyfrag: teardown guard kept for this boot\n");
    } else {
        /* Absent already: somebody else removed it. That is residue this teardown
         * must not hide - it is exactly the state that re-arms the chain. */
        ++markers;
        log_line("maplesu-dirtyfrag: teardown guard missing\n");
    }
    const int wrote = write_byte("/sys/fs/selinux/enforce", target);
    const int readback = read_byte("/sys/fs/selinux/enforce");
    const int failures = (stage_running && !disarmed) || markers != 0 || wrote != 0 ||
        readback != (target - '0') ? 1 : 0;
    log_line("maplesu-dirtyfrag: teardown disarmed=%d markers=%d enforcing=%d failures=%d\n",
             disarmed, markers, readback, failures);
    const int record = open(MAPLESU_ATTEMPT_DIRECTORY "/" MAPLESU_TEARDOWN,
                            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (record >= 0) {
        char line[128];
        const int size = snprintf(line, sizeof(line), "failures=%d enforcing=%d disarmed=%d markers=%d\n",
                                  failures, readback, disarmed, markers);
        if (size > 0) (void)write(record, line, (size_t)size);
        close(record);
    }
    return code;
}

/*
 * Publishes the milestone that reports why this attempt is ending, then runs the
 * same bounded teardown. The reference bootstrap returns right after its error
 * marker; this one still has a transient to restore, but it keeps the marker so
 * the failure becomes a named line in the stage's output instead of a timeout.
 */
static int fail_with(const char *marker, int code, const char *reason,
                     const char *enforce_field) {
    g_failure_marker = marker;
    touch(marker);
    return emergency_teardown(code, reason, enforce_field);
}

/*
 * Opt-in reference handoff: give the escalation to a staged KernelSU daemon.
 *
 * KernelSU is a control experiment here - it proved the exploit itself works on
 * this device - so this is not the product route and only runs with
 * MAPLESU_USE_KSU. The sequence is the reference one, including the two steps
 * our earlier version was missing:
 *   - switch to u:r:init:s0 while SELinux is still permissive, because after the
 *     module loads only init may enter u:r:ksu:s0;
 *   - wait for the detached daemon to finish instead of trusting the exit status
 *     of the process ksud double-forks away from.
 * The consumer is never exec'd here; that is the point of the handoff.
 */
/*
 * Normal (KernelSU) route, exactly the reference sequence.
 *
 * The original stage-1 branch was implemented but unreachable for a while: nothing
 * wrote MAPLESU_USE_KSU until the App did. It has two callers now:
 *   - stage-1's attempt-document branch (main), kept for the exploit route;
 *   - the P1 marker-gated branch at the top of umh_main(), because the module
 *     dispatches `<CE>/bs --umh ...` and main() returns there before the document
 *     is ever opened. Both hand in the App-staged daemon, never a guessed path.
 *
 * Normal (KernelSU) route, exactly the reference sequence, and three things the
 * reference leaves implicit are made explicit:
 *   - a missing/unusable installed ksud is a named failure, not a silent 0;
 *   - the restore facts are written before the soft reboot takes this process away,
 *     so the App can gate DAEMON_READY on them instead of on hope;
 *   - success emits its own `ksu:` verdict, so a Normal run can never be read as an
 *     Ultra success by the log parser.
 */
static int ksu_finish(void) {
    /* A successful KSU late-load ends enforcing even if its entry was permissive. */
    const char target = '1';
    const int wrote = read_byte("/sys/fs/selinux/enforce") == 1 ? 0 :
        write_byte("/sys/fs/selinux/enforce", target);
    const int readback = read_byte("/sys/fs/selinux/enforce");
    const int failures = (wrote != 0 || readback != (target - '0')) ? 1 : 0;
    const int record = open(MAPLESU_ATTEMPT_DIRECTORY "/" MAPLESU_TEARDOWN,
                            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (record >= 0) {
        char line[128];
        const int size = snprintf(line, sizeof(line),
                                  "failures=%d enforcing=%d disarmed=0 markers=0\n",
                                  failures, readback);
        if (size > 0) (void)write(record, line, (size_t)size);
        close(record);
    }
    log_line("maplesu-dirtyfrag: ksu restore failures=%d enforcing=%d\n", failures, readback);
    return failures;
}

static int ksu_handoff(const char *daemon, const char *enforce_field) {
    log_line("maplesu-dirtyfrag: ksu handoff daemon=%s\n", daemon);
    const int init = set_current_domain("u:r:init:s0");
    if (init != 0) log_line("maplesu-dirtyfrag: ksu init domain failed errno=%d\n", errno);
    else log_line("maplesu-dirtyfrag: ksu init domain set\n");
    touch("/dev/dfm5");
    char *load_argv[] = {(char *)daemon, "late-load", "--package-name",
                         MAPLESU_KSU_PACKAGE, NULL};
    setenv("MAPLESU_JAILBREAK_SELINUX_HIDE",
           read_byte(MAPLESU_ATTEMPT_DIRECTORY "/jailbreak-selinux-hide-request") == 0 ? "0" : "1", 1);
    const int load = run_ctx(NULL, load_argv);
    log_line("maplesu-dirtyfrag: ksu late-load rc=%d\n", load);
    if (load != 0) {
        log_line("maplesu-dirtyfrag: ksu: FAILED MAPLESU_KSU_LATE_LOAD_FAILED\n");
        return fail_with("/dev/dfme2", 76, "su daemon late-load failed", enforce_field);
    }
    /* dfm6 means "the daemon accepted late-load", not "the module is loaded": the
     * bounded wait below is what observes the work itself. */
    touch("/dev/dfm6");
    const int waited = wait_for_late_load(MAPLESU_LATE_LOAD_SECONDS);
    const int still_running = late_load_running();
    log_line("maplesu-dirtyfrag: ksu late-load waited=%ds running=%d\n", waited, still_running);
    if (still_running) {
        log_line("maplesu-dirtyfrag: ksu: FAILED MAPLESU_KSU_LATE_LOAD_TIMEOUT\n");
        return fail_with("/dev/dfme2", 76, "su daemon late-load timed out", enforce_field);
    }
    /*
     * ksud installs itself while late-loading. Without that install there is no
     * daemon to soft-reboot into and no superuser service for the manager, so this
     * is a failure - the reference logs nothing and continues, which reads as success.
     */
    if (access(MAPLESU_KSUD_INSTALLED, X_OK) != 0) {
        log_line("maplesu-dirtyfrag: ksu: FAILED MAPLESU_KSU_KSUSD_MISSING\n");
        return fail_with("/dev/dfme2", 76, "su daemon not installed after late-load",
                         enforce_field);
    }
    /* Persist restoration before returning to the manager's real-SU proof. */
    if (ksu_finish() != 0) {
        log_line("maplesu-dirtyfrag: ksu: FAILED MAPLESU_KSU_RESTORE_UNVERIFIED\n");
        return fail_with("/dev/dfme2", 76, "selinux restore unverified", enforce_field);
    }
    log_line("maplesu-dirtyfrag: ksu: loaded\n");
    /* The manager owns the requested soft reboot after it proves and publishes SU. */
    return 0;
}

/*
 * ============================================================================
 * In-kernel root (IR) route
 * ============================================================================
 * Manual section 4.2: exploit -> kernel-domain root helper -> load OUR module
 * (maplesu_ir.ko, finit_module) -> the module verifies every original byte and
 * patches kernel text -> restore the entry policy -> soft reboot. After the soft
 * reboot the kernel still carries the patches and MapleSU's normal mode takes
 * over; no boot image, partition, or second stage is written at any point.
 *
 * Two facts decide the loading contract, and both are measured from the target
 * image rather than assumed (manual U1/U2):
 *   - CONFIG_MODULE_FORCE_LOAD is not set, so MODULE_INIT_IGNORE_VERMAGIC cannot
 *     work: try_to_force_load() returns -ENOEXEC unconditionally. The module
 *     therefore carries the exact vermagic string and is loaded with flags=0.
 *   - check_modstruct_version() demands a module_layout CRC it will not get. The
 *     module ships a `__versions` section with no `module_layout` name, which
 *     makes check_version() warn once and accept it; that is the same path the
 *     vendor modules take with a zero-length section.
 * Nothing here needs ADB, an external SU manager, or a second app.
 */

static unsigned int ir_le16(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static unsigned long long ir_le32(const unsigned char *p) {
    return (unsigned long long)p[0] | ((unsigned long long)p[1] << 8) |
           ((unsigned long long)p[2] << 16) | ((unsigned long long)p[3] << 24);
}

static unsigned long long ir_le64(const unsigned char *p) {
    return ir_le32(p) | (ir_le32(p + 4) << 32);
}

/*
 * One staged input, validated the same way the attempt document is: regular file,
 * owned by the attempting user, no group/world bits, single link, bounded size.
 * Anything else is refused instead of being handed to the kernel.
 */
static int ir_read_staged(int dirfd, const char *name, unsigned char *buffer,
                          size_t capacity, size_t *size, int *verified_fd) {
    if (verified_fd != NULL) *verified_fd = -1;
    const int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat status = {0};
    struct stat home = {0};
    ssize_t count = -1;
    int result = -1;
    if (!fstat(fd, &status) && !fstat(dirfd, &home) && S_ISREG(status.st_mode) &&
        status.st_uid == home.st_uid && !(status.st_mode & 0077) && status.st_nlink == 1 &&
        status.st_size > 0 && (size_t)status.st_size < capacity) {
        size_t done = 0;
        while (done < (size_t)status.st_size) {
            count = read(fd, buffer + done, (size_t)status.st_size - done);
            if (count <= 0) break;
            done += (size_t)count;
        }
        if (done == (size_t)status.st_size) {
            *size = done;
            result = 0;
        }
    }
    /* A loader keeps the descriptor whose bytes it validated. Other callers
     * transfer no descriptor and retain the original close-on-return behavior. */
    if (result == 0 && verified_fd != NULL) *verified_fd = fd;
    else close(fd);
    return result;
}

/*
 * The ELF preconditions every module image must satisfy before it is handed to the
 * kernel: ELF64, little endian, ET_REL, AArch64, 64-byte section headers. Extracted
 * from the .ir_spec lookup below so the step-3 stage-2 slot (hook_stage2) reuses the
 * same judgement instead of writing a second one (design §4.2).
 */
static int ir_elf_precheck(const unsigned char *elf, size_t size) {
    if (size < 64 || memcmp(elf, "\177" "ELF", 4) != 0 || elf[4] != 2 || elf[5] != 1)
        return -1;
    if (ir_le16(elf + 16) != 1 /* ET_REL */ || ir_le16(elf + 18) != 183 /* AArch64 */)
        return -1;
    if (ir_le16(elf + 58) != 64) return -1;
    return 0;
}

/*
 * Locate `.ir_spec` in the staged module. The App does not have to know the
 * offset: the module publishes it in its own section table, which is what makes
 * "one module, one spec per release" safe.
 */
static int ir_find_spec_section(const unsigned char *elf, size_t size,
                                size_t *offset, size_t *length) {
    if (ir_elf_precheck(elf, size) != 0) return -1;
    const unsigned long long shoff = ir_le64(elf + 40);
    const unsigned int shnum = ir_le16(elf + 60);
    const unsigned int shstrndx = ir_le16(elf + 62);
    if (shnum == 0 || shstrndx >= shnum) return -1;
    if (shoff > size || (unsigned long long)shnum * 64ULL > size - shoff) return -1;
    const unsigned char *headers = elf + shoff;
    const unsigned char *strings = headers + (size_t)shstrndx * 64;
    const unsigned long long stroff = ir_le64(strings + 24);
    const unsigned long long strsize = ir_le64(strings + 32);
    if (stroff > size || strsize > size - stroff) return -1;
    for (unsigned int i = 0; i < shnum; ++i) {
        const unsigned char *header = headers + (size_t)i * 64;
        const unsigned long long name = ir_le32(header);
        const unsigned long long sh_offset = ir_le64(header + 24);
        const unsigned long long sh_size = ir_le64(header + 32);
        if (name >= strsize) continue;
        const char *candidate = (const char *)(elf + stroff + name);
        const size_t remaining = (size_t)(strsize - name);
        if (strncmp(candidate, MAPLESU_IR_SECTION, remaining) != 0) continue;
        if (sh_offset > size || sh_size > size - sh_offset) return -1;
        *offset = (size_t)sh_offset;
        *length = (size_t)sh_size;
        return 0;
    }
    return -1;
}

/* Is our module live? Read-only, and it is the only readiness signal that does
 * not ask the kernel to do anything on our behalf. */
static int ir_module_present(void) {
    const int fd = open("/proc/modules", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buffer[8192];
    ssize_t count;
    int found = 0;
    do { count = read(fd, buffer, sizeof(buffer) - 1); } while (count < 0 && errno == EINTR);
    close(fd);
    if (count <= 0) return 0;
    buffer[count] = '\0';
    const size_t name_length = sizeof(MAPLESU_IR_MODULE_NAME) - 1;
    for (char *line = buffer; line != NULL && *line != '\0'; ) {
        char *next = strchr(line, '\n');
        if (!strncmp(line, MAPLESU_IR_MODULE_NAME, name_length) &&
            line[name_length] == ' ') found = 1;
        line = next != NULL ? next + 1 : NULL;
    }
    return found;
}

/* The pre-entry policy the App observed, restored and read back. S1 contract:
 * we never claim a policy we did not measure, and we never leave a widened one. */
static int ir_restore_policy(const char *enforce_field) {
    const char target = entry_enforcing(enforce_field);
    const int wrote = write_byte("/sys/fs/selinux/enforce", target);
    const int readback = read_byte("/sys/fs/selinux/enforce");
    log_line("maplesu-dirtyfrag: ir: policy wrote=%d readback=%d target=%d\n",
             wrote, readback, target - '0');
    return readback == (target - '0') ? 0 : -1;
}

/*
 * Every IR failure publishes exactly one stable token, and none of them soft
 * reboot: the device stays up, the entry policy is restored, and the user can
 * retry with a fixed spec (manual D5). The token is what the App's verdict keys
 * off, so it must not change shape.
 */
static int ir_fail(const char *marker, int code, const char *token,
                   const char *detail, const char *enforce_field) {
    log_line("maplesu-dirtyfrag: ir: FAILED %s %s\n", token, detail != NULL ? detail : "");
    return fail_with(marker, code, token, enforce_field);
}

/*
 * Diagnostic probe (bring-up only).
 *
 * This kernel denies dmesg to us and ENOEXEC covers a dozen different loader
 * checks, so the only way to separate "our ELF is refused" from "every module is
 * refused here" is to try several candidates inside one attempt. Each candidate is
 * a bare init_module call: a failure changes no kernel state, and a success
 * unloads itself if its own init returns non-zero.
 *
 * The directory is staged by hand outside any product path (app-private dir), and
 * the outcome is one log line per candidate.
 */
/* One explicit canary: the module's loader contract with none of its code.
 * Staged by the App with the attempt, so it cannot go missing between attempts
 * the way a hand-made directory did. */
/*
 * The loader prints why it refused a module, and this process holds CAP_SYSLOG
 * (init_cred) even though adb shell does not. Copying the tail of the ring buffer
 * into our own log is the only way to see the reason, because dmesg is denied to
 * every unprivileged reader on this build.
 */
/*
 * The most recent ring-buffer window this process dumped, kept verbatim so the
 * errno->token classifier below can look for the module's *own* classified printk
 * without asking the kernel a second time (design §7.1). Bounded to the same 1600
 * bytes the dump prints, and empty until a dump succeeds: an unreadable channel must
 * leave the loader-layer token in place, never invent a specific cause.
 */
#define MAPLESU_KLOG_TAIL_MAX 1601
/* One full ring-buffer read window. The IR dump and the L3 ARM confirmation share
 * this bound, so the two read the same evidence through the same code path. */
#define MAPLESU_KLOG_READ_MAX (96 * 1024)
static char g_klog_tail[MAPLESU_KLOG_TAIL_MAX];
static size_t g_klog_tail_length;

static int klog_tail_contains(const char *needle) {
    if (g_klog_tail_length == 0) return 0;
    return strstr(g_klog_tail, needle) != NULL;
}

/*
 * Classify a failed init_module()/finit_module() into exactly one stable token.
 *
 * Layer 1 is the loader, whose mapping predates D-2 and must not change shape: the
 * App's `MAPLESU_IR_*` verdict keys off it. Layer 2 is the handover: -ENODEV now means
 * "the helper was not exec'd" as well as "no symbols", so when the module's own
 * classified printk is in the dump taken for this failure, its meaning wins. The
 * override only fires on evidence in the dump; there is no guesswork about which of
 * the two meanings an errno "probably" had.
 */
static const char *ir_errno_token(int errno_value) {
    const char *token = "MAPLESU_IR_LOAD_FAILED";
    if (errno_value == EKEYREJECTED) token = "MAPLESU_IR_ORIG_MISMATCH";
    else if (errno_value == EOPNOTSUPP) token = "MAPLESU_IR_SPEC_INVALID";
    else if (errno_value == ENODEV) token = "MAPLESU_IR_NO_SYMBOLS";
    else if (errno_value == EIO) token = "MAPLESU_IR_APPLY_FAILED";
    if (klog_tail_contains("kallsyms_lookup_name not found") ||
        klog_tail_contains("kprobe resolved no address") ||
        klog_tail_contains("fallback cannot hand over"))
        return "MAPLESU_HANDOVER_NO_UMH";
    if (klog_tail_contains("selinux_state not found"))
        return "MAPLESU_HANDOVER_NO_SELINUX";
    if (klog_tail_contains("umh setup returned NULL"))
        return "MAPLESU_HANDOVER_NO_MEMORY";
    if (klog_tail_contains("helper exec failed"))
        return "MAPLESU_HANDOVER_NO_EXEC";
    return token;
}

/*
 * One bounded read of the whole ring buffer through the same "copy, never clear"
 * channel the IR probes use (READ_ALL is non-destructive). `capacity` includes the
 * terminator: the kernel copies the *newest* bytes that fit, and this function
 * NUL-terminates them so every caller can scan the result as text. Returns the
 * syscall's own byte count - > 0 means the kernel answered and *length is the number
 * of bytes in `out`; <= 0 means no readable ring buffer (errno is left by the syscall
 * for the caller's log line). No allocation happens here: the caller owns its buffer.
 *
 * L3 (ABI v2) reuses this for the ARM confirmation's before/after samples; the IR
 * probes reuse it for the same dump they always did.
 */
static long klog_read_all(char *out, size_t capacity, size_t *length) {
    if (out == NULL || capacity < 2 || capacity > (size_t)INT_MAX) return -1;
    *length = 0;
    const long count = (long)syscall(MAPLESU_NR_SYSLOG, MAPLESU_SYSLOG_READ_ALL,
                                     out, (int)(capacity - 1));
    if (count <= 0) return count;
    size_t size = (size_t)count;
    if (size >= capacity) size = capacity - 1;
    out[size] = '\0';
    *length = size;
    return count;
}

/*
 * L3 (ABI v2): the v2 module does not put the token in its ARM line
 * (`maplesu_l3: armed owner=%u pool=%u`). The filter stays as defence in depth for an
 * older module that printed `suToken=%016llx`: the token's only sanctioned carrier is
 * the two evidence records in the App's directory, so a dumped line carrying it is
 * replaced whole - the surrounding klog context stays readable, the secret does not.
 * `strncmp` is already a dependency; a byte-exact `memmem` would add a new one for no
 * gain.
 */
static int klog_line_contains_token(const char *line, size_t length) {
    static const char needle[] = "suToken=";
    const size_t needle_length = sizeof(needle) - 1;

    if (length < needle_length) return 0;
    for (size_t i = 0; i + needle_length <= length; ++i) {
        if (strncmp(line + i, needle, needle_length) == 0) return 1;
    }
    return 0;
}

static void ir_dump_kernel_log(const char *label) {
    char *buffer = malloc(MAPLESU_KLOG_READ_MAX);
    size_t count = 0;
    if (buffer == NULL) return;
    const long rc = klog_read_all(buffer, MAPLESU_KLOG_READ_MAX, &count);
    const int saved = errno;
    if (rc <= 0) {
        g_klog_tail_length = 0;
        g_klog_tail[0] = '\0';
        log_line("maplesu-dirtyfrag: klog %s unreadable rc=%ld errno=%d\n",
                 label, rc, saved);
    } else {
        size_t begin = count > 1600 ? count - 1600 : 0;
        /* Start at a line boundary so the dump is readable. */
        while (begin < count && buffer[begin] != '\n') ++begin;
        if (begin < count) ++begin;
        g_klog_tail_length = count - begin;
        if (g_klog_tail_length >= sizeof(g_klog_tail))
            g_klog_tail_length = sizeof(g_klog_tail) - 1;
        memcpy(g_klog_tail, buffer + begin, g_klog_tail_length);
        g_klog_tail[g_klog_tail_length] = '\0';
        log_line("maplesu-dirtyfrag: klog %s bytes=%ld\n", label, rc);
        log_line("maplesu-dirtyfrag: klog >>>\n");
        for (size_t i = begin; i < count; ) {
            size_t end = i;
            while (end < count && buffer[end] != '\n') ++end;
            if (end > i) {
                if (klog_line_contains_token(buffer + i, end - i))
                    log_line("maplesu-dirtyfrag: klog | <redacted: L3 su token>\n");
                else
                    log_line("maplesu-dirtyfrag: klog | %.*s\n", (int)(end - i),
                             buffer + i);
            }
            i = end + 1;
        }
        log_line("maplesu-dirtyfrag: klog <<<\n");
    }
    free(buffer);
}

static void ir_dump_kernel_log(const char *label);

static int ir_find_spec_section(const unsigned char *elf, size_t size,
                                size_t *offset, size_t *length);

/* Copy the staged spec into the image's .ir_spec section, zero padded. */
static int ir_inject_spec(unsigned char *module, size_t module_size,
                          const char *spec, size_t spec_size) {
    size_t offset = 0, length = 0;
    if (ir_find_spec_section(module, module_size, &offset, &length) != 0) return -1;
    if (spec_size + 1 > length) return -1;
    memset(module + offset, 0, length);
    memcpy(module + offset, spec, spec_size);
    return 0;
}

static void ir_probe_file(const char *path, const char *label) {
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        log_line("maplesu-dirtyfrag: probe %s open errno=%d\n", label, errno);
        return;
    }
    struct stat status = {0};
    unsigned char *image = NULL;
    if (!fstat(fd, &status) && S_ISREG(status.st_mode) && status.st_size > 0 &&
        status.st_size < MAPLESU_IR_MODULE_LIMIT) {
        image = malloc((size_t)status.st_size);
    }
    if (image == NULL) {
        close(fd);
        log_line("maplesu-dirtyfrag: probe %s rejected size=%ld\n", label,
                 (long)status.st_size);
        return;
    }
    ssize_t got = 0;
    size_t done = 0;
    while (done < (size_t)status.st_size) {
        got = read(fd, image + done, (size_t)status.st_size - done);
        if (got <= 0) break;
        done += (size_t)got;
    }
    close(fd);
    if (done == (size_t)status.st_size) {
        int injected = -1;
        if (access(MAPLESU_IR_PROBE_WITH_SPEC, F_OK) == 0) {
            char spec[MAPLESU_IR_SPEC_LIMIT];
            size_t spec_size = 0;
            const int spec_fd = open(MAPLESU_ATTEMPT_DIRECTORY "/ir.spec",
                                     O_RDONLY | O_CLOEXEC);
            if (spec_fd >= 0) {
                const ssize_t got_spec = read(spec_fd, spec, sizeof(spec));
                close(spec_fd);
                if (got_spec > 0) spec_size = (size_t)got_spec;
            }
            injected = spec_size > 0 ? ir_inject_spec(image, done, spec, spec_size) : -1;
            log_line("maplesu-dirtyfrag: probe %s spec=%d injected=%d\n",
                     label, (int)spec_size, injected);
        }
        const int rc = (int)syscall(MAPLESU_NR_INIT_MODULE, image, (unsigned long)done, "");
        log_line("maplesu-dirtyfrag: probe %s bytes=%d rc=%d errno=%d\n",
                 label, (int)done, rc, rc == 0 ? 0 : errno);
        if (rc != 0) ir_dump_kernel_log(label);
    } else {
        log_line("maplesu-dirtyfrag: probe %s short read=%d/%d\n",
                 label, (int)done, (int)status.st_size);
    }
    free(image);
}

/*
 * Probe every staged candidate. Each one goes through ir_probe_file, so the
 * spec-injection marker applies to staged variants too - duplicating the read and
 * load logic here is what made the first staged run silently skip injection.
 */
static void ir_probe_staged(void) {
    const char *directory = MAPLESU_ATTEMPT_DIRECTORY "/probe";
    DIR *dir = opendir(directory);
    if (dir == NULL) {
        log_line("maplesu-dirtyfrag: probe dir unreadable errno=%d\n", errno);
        return;
    }
    struct dirent *entry;
    int tested = 0;
    while ((entry = readdir(dir)) != NULL && tested < 8) {
        const size_t length = strlen(entry->d_name);
        if (length < 4 || strcmp(entry->d_name + length - 3, ".ko") != 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        ir_probe_file(path, entry->d_name);
        ++tested;
    }
    closedir(dir);
    log_line("maplesu-dirtyfrag: probe done tested=%d\n", tested);
}

/*
 * The privileged helper holds CAP_SYSLOG, so it can read the real _text address
 * from /proc/kallsyms and hand it to the module as #kbase=. That removes the
 * VBAR_EL1 derivation on any build where kallsyms is readable.
 */
static int ir_resolve_text(unsigned long long *out) {
    const int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    static char buffer[16384];
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (count <= 0) return -1;
    buffer[count] = 0;
    for (char *line = buffer; line != NULL && *line != 0; ) {
        char *next = strchr(line, 10);
        if (next != NULL) *next = 0;
        unsigned long long address = 0;
        char name[128];
        if (sscanf(line, "%llx %*c %127s", &address, name) == 2 &&
            !strcmp(name, "_text") && address != 0) {
            *out = address;
            return 0;
        }
        line = next != NULL ? next + 1 : NULL;
    }
    return -1;
}


static int install_ir(const char *enforce_field) {
    unsigned char *module = NULL;
    char spec[MAPLESU_IR_SPEC_LIMIT];
    size_t module_size = 0, spec_size = 0, section_offset = 0, section_length = 0;
    int result = 0;

    log_line("maplesu-dirtyfrag: ir: start\n");
    const int dirfd = open(MAPLESU_ATTEMPT_DIRECTORY, O_RDONLY | O_DIRECTORY |
                           O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0)
        return ir_fail("/dev/dfme2", 80, "MAPLESU_IR_STAGE_MISSING", "attempt dir", enforce_field);
    struct stat home;
    if (fstat(dirfd, &home) || !S_ISDIR(home.st_mode) || home.st_uid < 10000 ||
        home.st_uid >= 100000 || (home.st_mode & 0077)) {
        close(dirfd);
        return ir_fail("/dev/dfme2", 80, "MAPLESU_IR_STAGE_MISSING", "attempt dir rejected",
                       enforce_field);
    }
    if (ir_read_staged(dirfd, MAPLESU_IR_SPEC_FILE, (unsigned char *)spec,
                       sizeof(spec), &spec_size, NULL) != 0) {
        close(dirfd);
        return ir_fail("/dev/dfme2", 81, "MAPLESU_IR_SPEC_INVALID", "spec unavailable",
                       enforce_field);
    }
    module = malloc(MAPLESU_IR_MODULE_LIMIT);
    if (module == NULL) {
        close(dirfd);
        return ir_fail("/dev/dfme2", 82, "MAPLESU_IR_STAGE_MISSING", "no memory", enforce_field);
    }
    if (ir_read_staged(dirfd, MAPLESU_IR_MODULE_FILE, module,
                       MAPLESU_IR_MODULE_LIMIT, &module_size, NULL) != 0) {
        free(module);
        close(dirfd);
        return ir_fail("/dev/dfme2", 81, "MAPLESU_IR_STAGE_MISSING", "module unavailable",
                       enforce_field);
    }
    close(dirfd);

    /*
     * Exact release match before anything is loaded (manual C10 / requirement 5).
     * The App already refuses a release it has no spec for; repeating it here means
     * a stale spec staged next to a fresh kernel can never be applied, and the
     * failure carries the release the device actually runs.
     */
    struct utsname uts;
    if (uname(&uts) != 0) {
        free(module);
        return ir_fail("/dev/dfme2", 82, "MAPLESU_IR_SPEC_INVALID", "uname", enforce_field);
    }
    const char *declared = NULL;
    if (spec_size > 8 && !strncmp(spec, "#kernel=", 8)) {
        declared = spec + 8;
    }
    if (declared == NULL) {
        free(module);
        return ir_fail("/dev/dfme2", 83, "MAPLESU_IR_SPEC_INVALID", "no #kernel line",
                       enforce_field);
    }
    /* A spec authored on Windows may carry CRLF. The release ends at either
     * terminator; leaving the \r in would compare it against the NUL and make every
     * release look unsupported, which is exactly what happened on device once. */
    size_t declared_length = strcspn(declared, "\n");
    if (declared_length > 0 && declared[declared_length - 1] == '\r') --declared_length;
    if (declared_length == 0 || declared_length >= (size_t)sizeof(uts.release) ||
        strncmp(declared, uts.release, declared_length) != 0 || uts.release[declared_length] != '\0') {
        log_line("maplesu-dirtyfrag: ir: spec release=%.*s device release=%s\n",
                 (int)(declared_length > 96 ? 96 : declared_length), declared, uts.release);
        free(module);
        return ir_fail("/dev/dfme2", 83, "MAPLESU_IR_UNSUPPORTED", uts.release, enforce_field);
    }
    log_line("maplesu-dirtyfrag: ir: release=%s spec=%dB module=%dB\n",
             uts.release, (int)spec_size, (int)module_size);
    /* Append the measured base. The spec always ends with a newline and the
     * section is far larger than any spec, so there is room to add one line. */
    {
        unsigned long long text = 0;
        if (ir_resolve_text(&text) == 0) {
            const int appended = snprintf(spec + spec_size, sizeof(spec) - spec_size,
                                          "#kbase=0x%llx\n", text);
            if (appended > 0 && (size_t)appended < sizeof(spec) - spec_size) {
                spec_size += (size_t)appended;
                log_line("maplesu-dirtyfrag: ir: kbase=0x%llx from kallsyms\n", text);
            }
        } else {
            log_line("maplesu-dirtyfrag: ir: kallsyms unreadable, module derives base\n");
        }
    }
    /*
     * Bring-up only: the canary first (module contract, no code), then any
     * hand-staged candidates. Both are no-ops in a product run.
     *
     * DEV-163: the "is a canary image staged" answer is taken HERE, before the
     * probe, while the handover window is still permissive. This process runs as
     * u:r:kernel:s0 uid 0 (the module exec'd it as kernel-domain root); the canary
     * helper restores enforcing=1 from inside the probe, and from that instant this
     * domain is denied app-data lookups. On attempt #1 the post-probe
     * access(MAPLESU_IR_CANARY, F_OK) was itself denied (EACCES - the very next log
     * line, `probe dir unreadable errno=13`, is the same denial), so the one run
     * whose kernel lines matter produced no `klog canary-after` block at all.
     * Deciding before the probe keeps the dump unconditional on a canary run and
     * still absent in a product run (nothing staged, so the flag is 0).
     */
    const int canary_staged = (access(MAPLESU_IR_CANARY, F_OK) == 0);
    if (canary_staged) log_line("maplesu-dirtyfrag: ir: canary staged=1\n");
    ir_probe_file(MAPLESU_IR_CANARY, "canary");
    /*
     * Bring-up only (DEV-157 / DEV-163), and only after the module's own printks
     * exist: the canary module returns 0 on a successful handover, while
     * ir_probe_file() dumps the ring buffer only when a probe returns non-zero, so
     * this is the success-path dump. It runs on both rc == 0 and rc != 0 - and it
     * never re-tests the path (no second access()), because the answer is the flag
     * computed above. The failure path keeps its own dump inside ir_probe_file(),
     * so a failed probe shows two blocks under two labels; a product run stages no
     * canary image and never dumps. If the ring buffer cannot be read under the
     * restored policy, ir_dump_kernel_log() emits
     * `klog canary-after unreadable rc=... errno=...` and nothing else: that is an
     * explicit "no kernel evidence" marker, not a silent skip.
     */
    if (canary_staged) ir_dump_kernel_log("canary-after");
    ir_probe_staged();

    /* The module's own section table says where the spec goes. */
    if (ir_find_spec_section(module, module_size, &section_offset, &section_length) != 0) {
        free(module);
        return ir_fail("/dev/dfme2", 84, "MAPLESU_IR_MODULE_INVALID", "no " MAPLESU_IR_SECTION,
                       enforce_field);
    }
    if (spec_size + 1 > section_length) {
        free(module);
        return ir_fail("/dev/dfme2", 84, "MAPLESU_IR_SPEC_TOO_LARGE", MAPLESU_IR_SECTION,
                       enforce_field);
    }
    /* Zero the whole section first: the module stops at the first NUL, so a
     * shorter spec cannot inherit trailing bytes from the built-in placeholder. */
    memset(module + section_offset, 0, section_length);
    memcpy(module + section_offset, spec, spec_size);

    /*
     * Load straight from the buffer we already hold. `init_module` takes
     * (image, len, args) and copies from userspace, so there is no file, no memfd
     * and no file-position question in the path at all. flags=0 is still right: the
     * module carries the exact vermagic and a __versions section.
     */
    log_line("maplesu-dirtyfrag: ir: image magic=%02x%02x%02x%02x bytes=%d\n",
             module[0], module[1], module[2], module[3], (int)module_size);
    result = (int)syscall(MAPLESU_NR_INIT_MODULE, module, module_size, "");
    const int load_error = errno;
    free(module);

    if (result != 0) {
        char detail[48];
        snprintf(detail, sizeof(detail), "errno=%d", load_error);
        log_line("maplesu-dirtyfrag: ir: finit_module rc=%d errno=%d\n", result, load_error);
        /*
         * Step-3 (§7.1): dump the ring buffer *for this failure* before choosing the
         * token, so a module-side classification (D-2's five returns) can override the
         * loader-layer meaning of the same errno. The dump is bounded and best effort;
         * an unreadable channel leaves the loader token in place.
         */
        ir_dump_kernel_log("ir-load-failed");
        const char *token = ir_errno_token(load_error);
        return ir_fail("/dev/dfme2", 86, token, detail, enforce_field);
    }
    /*
     * fd 0 result means the patches were verified and applied. Confirm the module
     * is really live: /proc/modules is the read-only readiness marker the
     * post-reboot takeover will look for, so a load that cannot be observed there
     * is not counted as success.
     */
    if (!ir_module_present()) {
        return ir_fail("/dev/dfme2", 87, "MAPLESU_IR_NOT_READY", "not in /proc/modules",
                       enforce_field);
    }
    log_line("maplesu-dirtyfrag: ir: loaded name=%s\n", MAPLESU_IR_MODULE_NAME);

    /* S1: the policy goes back before anything else runs, then the kernel is kept
     * and only userspace is restarted (manual C7, soft reboot). */
    (void)ir_restore_policy(enforce_field);
    /*
     * W0 decision experiment: with this marker the privileged side stops here, so
     * the caller can start an ART probe in the patched-but-not-rebooted kernel and
     * observe whether the device survives. The verdict decides W4 (soft-reboot
     * takeover vs the native-daemon alternative in appendix B).
     */
    if (access(MAPLESU_IR_NO_REBOOT, F_OK) == 0) {
        log_line("maplesu-dirtyfrag: ir: NO_REBOOT staying in this boot\n");
        log_line("maplesu-dirtyfrag: ir: ARTPROBE_READY module=%s\n", MAPLESU_IR_MODULE_NAME);
        return 0;
    }
    (void)set_exec_domain("u:r:shell:s0");
    touch("/dev/dfm5");
    touch("/dev/dfm6");
    char *reboot_argv[] = {"/system/bin/sh", "-c",
        "setprop sys.powerctl reboot,soft_reboot", NULL};
    execv(reboot_argv[0], reboot_argv);
    const int saved = errno;
    (void)unlink("/dev/dfm6");
    log_line("maplesu-dirtyfrag: ir: soft reboot exec failed errno=%d\n", saved);
    return ir_fail("/dev/dfme2", 88, "MAPLESU_IR_REBOOT_FAILED", "soft reboot exec",
                   enforce_field);
}

/*
 * ============================================================================
 * UMH mode implementation (design §2, §4, §5, §6)
 * ============================================================================
 * Read the design section by section; the comments below point at the steps of
 * §5.1 so a reviewer can walk the order without guessing.
 */
struct hook_request {
    char entry;            /* '0'|'1' from --entry-enforcing; '\0' when invalid */
    const char *stage2;    /* NULL -> sibling of argv[0] */
    const char *daemon;    /* NULL -> sibling of argv[0] */
    const char *helper;    /* argv[0] */
    int valid;             /* 0 once a token has been recorded for a bad parse */
};

struct hook_state {
    int dirfd;
    int from_ghostlock;    /* existing root; no bootstrap module to unload */
    /* st_uid / st_gid of the validated attempt directory (step-4 D4/MF-2): the
     * daemon slot's owner check and the attestation socket's chown() both need the
     * App's uid, never getuid() - the helper is uid 0, so getuid() would only ever
     * admit {0,1000} and reject the App-owned <CE>/bs. */
    unsigned int dir_uid;
    unsigned int dir_gid;
    int enforce_before;    /* 0/1 observed at entry; -1 unreadable */
    char want_final;       /* '0'|'1', or '\0' when the target is unknown */
    /* Step-4 D2: what the App's env file said, and the provenance label that travels
     * with the decision into the evidence (restore.source, design §3.4/G-10). */
    int env_ok;
    int env_expected;      /* 0/1, or -1 when the env carried no value */
    char env_source[12];   /* observed | baseline | unknown */
    char restore_source[12]; /* observed | baseline | kernel | unknown */
    char attempt[MAPLESU_HOOK_SMALL_MAX];
    char entry_argv;       /* '0'|'1' from --entry-enforcing: the kernel's inherited
                            * observation, kept separate from the target (design §3.4:
                            * status.enforcingAtLease must stay the inherited value) */
    int write_fd;
    int read_fd_a;
    int read_fd_b;
    int read_fd_c;
    int read_fd_d;
    int ev_fd;
    int child_fd;
    int kmsg_fd;
    char helper[PATH_MAX];
    char boot_id[MAPLESU_HOOK_SMALL_MAX];
    char domain[MAPLESU_HOOK_SMALL_MAX];
    char stage2_path[PATH_MAX];
    char stage2_state[24];
    char stage2_name[80];
    int stage2_rc;
    int stage2_errno;
    char daemon_path[PATH_MAX];
    char daemon_state[24];
    long daemon_pid;
    int wrote;             /* did this restore routine write selinuxfs? */
    int readback_pre;
    int readback_final;     /* parent's own read after the unload child (no new lookup) */
    int failures;
    const char *token;
    const char *restore_origin;
    const char *unload_state;   /* DONE | FAILED | PENDING */
    /* L3 (ABI v2). `su_gate` is ARMED only when prctl() returned 0 *and* the module's
     * ARM acknowledgement was observed afterwards; `su_token_hex` is cleared on every
     * other outcome, so the writers can never advertise a token the kernel did not
     * commit. `su_gate_reason` says why the gate is UNAVAILABLE (B1/Y2) and stays
     * empty while ARMED. None of the three is read by hook_verdict(): the L3 leg is
     * evidence only and cannot turn a working handover into FAILED. */
    char su_token_hex[MAPLESU_L3_TOKEN_DIGITS + 1];  /* "%016llx" while ARMED */
    char su_gate[12];                               /* ARMED | UNAVAILABLE */
    char su_gate_reason[32];                        /* one MAPLESU_L3_REASON_* */
    int su_arm_rc;
    int su_arm_errno;
};

/* The attestation worker's own state. Deliberately separate from hook_state: this
 * process is a *different* exec of the same binary, and it must not inherit the
 * helper's stage-1 privileges or its decisions (design §3.2 step 5). */
struct attest_state {
    int dirfd;
    int record_fd;
    int enforce_fd;
    unsigned int dir_uid;
    unsigned int dir_gid;
    long starttime;        /* /proc/self/stat field 22: same-pid reuse detection only */
    char attempt[MAPLESU_HOOK_SMALL_MAX];
    char boot_id[MAPLESU_HOOK_SMALL_MAX];
    char domain[MAPLESU_HOOK_SMALL_MAX];
    /* L3 (ABI v2): the ARM token the helper committed, read from MAPLESU_SU_TOKEN in
     * this worker's own environment (B1: never argv). Empty means the gate is
     * UNAVAILABLE; the worker never invents one. `su_reason` is the helper's
     * suGateReason, re-validated against the fixed list before it is echoed. */
    char su_token[MAPLESU_L3_TOKEN_DIGITS + 1];
    char su_reason[32];
    char socket_path[PATH_MAX];
    int pool[MAPLESU_ATTEST_POOL];
    int pool_used;
};

/* Strict shape for the two optional path overrides: absolute, printable, and free of
 * the characters an unescaped JSON string could not carry. A hostile caller is not
 * the threat model (only root can exec this), but a malformed path must be refused
 * instead of producing evidence that cannot be parsed. */
static int hook_path_ok(const char *path) {
    if (path == NULL || path[0] != '/') return 0;
    const size_t length = strlen(path);
    if (length < 2 || length >= PATH_MAX) return 0;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char ch = (unsigned char)path[i];
        if (ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\\') return 0;
    }
    return 1;
}

/* D3-1: the mode is selected by argv only, never by "is the attempt document
 * there". The exploit route passes no arguments at all, so this cannot collide. */
static int umh_mode_requested(int argc, char **argv) {
    if (argc <= 1 || argv == NULL) return 0;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == NULL) continue;
        if (!strcmp(argv[i], "--umh") || !strcmp(argv[i], "--entry-enforcing")) return 1;
    }
    return 0;
}

/*
 * Parse the frozen argv contract (design §2.1). Writes nothing: a bad parse is a
 * token, not a side effect. `--umh` and `--entry-enforcing <0|1>` are both required;
 * `--stage2 <path>` and `--daemon <path>` are optional. Anything else is refused
 * rather than ignored, because an argument this mode does not understand is a
 * caller that expected different semantics.
 */
static int hook_parse_argv(int argc, char **argv, struct hook_request *request) {
    int seen_umh = 0, seen_entry = 0, seen_stage2 = 0, seen_daemon = 0;

    memset(request, 0, sizeof(*request));
    request->valid = 1;
    request->helper = (argc > 0 && argv != NULL && argv[0] != NULL) ? argv[0] : "";
    if (request->helper[0] != '/' || strrchr(request->helper, '/') == NULL) {
        request->valid = 0;
        return -1;
    }
    for (int i = 1; i < argc; ++i) {
        const char *token = argv[i];
        if (token == NULL) { request->valid = 0; return -1; }
        if (!strcmp(token, "--umh")) {
            if (seen_umh) { request->valid = 0; return -1; }
            seen_umh = 1;
            continue;
        }
        if (!strcmp(token, "--entry-enforcing")) {
            if (seen_entry || i + 1 >= argc) { request->valid = 0; return -1; }
            const char *value = argv[++i];
            if (value == NULL || value[0] == '\0' || value[1] != '\0' ||
                (value[0] != '0' && value[0] != '1')) {
                /* design §2.1: fail closed, no selinuxfs write, L2 only */
                request->valid = 0;
                return -1;
            }
            request->entry = value[0];
            seen_entry = 1;
            continue;
        }
        if (!strcmp(token, "--stage2") || !strcmp(token, "--daemon")) {
            const int stage2 = !strcmp(token, "--stage2");
            if ((stage2 && seen_stage2) || (!stage2 && seen_daemon) || i + 1 >= argc) {
                request->valid = 0;
                return -1;
            }
            const char *value = argv[++i];
            if (!hook_path_ok(value)) { request->valid = 0; return -1; }
            if (stage2) { request->stage2 = value; seen_stage2 = 1; }
            else { request->daemon = value; seen_daemon = 1; }
            continue;
        }
        /* Unknown token: refuse. The contract has four tokens; a fifth one means the
         * caller and this helper disagree about the contract. */
        request->valid = 0;
        return -1;
    }
    if (!seen_umh || !seen_entry) { request->valid = 0; return -1; }
    return 0;
}

/* First line of a small text file (boot_id, SELinux domain). Used before the
 * restore, so the lookup is still allowed; after the restore only pre-opened
 * descriptors are used, which is why nothing calls this later in the sequence. */
static int hook_read_small(const char *path, char *buffer, size_t capacity) {
    if (capacity == 0) return -1;
    buffer[0] = '\0';
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    while (used + 1 < capacity) {
        const ssize_t got = read(fd, buffer + used, capacity - 1 - used);
        if (got <= 0) break;
        used += (size_t)got;
    }
    close(fd);
    buffer[used] = '\0';
    for (size_t i = 0; i < used; ++i) {
        if (buffer[i] == '\n' || buffer[i] == '\r') { buffer[i] = '\0'; break; }
    }
    return buffer[0] != '\0' ? 0 : -1;
}

/* Record the first failure token and count it. One failure, one token (design §5.3):
 * the first named condition is the one the verdict is about. */
static void hook_fail(struct hook_state *state, const char *token) {
    if (state->token == NULL) state->token = token;
    ++state->failures;
}

static void hook_set_state(char *field, size_t capacity, const char *value) {
    snprintf(field, capacity, "%s", value);
}

/*
 * ============================================================================
 * L3 (ABI v2): the token, the ARM call, its second confirmation, and the two
 * evidence fields
 * ============================================================================
 * Ordering is the whole contract: hook_stage2() calls hook_arm_l3() only after
 * finit_module() reported LOADED/ALREADY_RESIDENT, and that call site sits before the
 * restore, so the gate is armed while the window that allowed the module load is still
 * open. Nothing in this block may fail the handover: a missing module, an ARM the
 * kernel did not acknowledge, or a denied call leaves DAEMON_READY exactly as it was.
 */

/* 16 lowercase hex digits: the frozen JSON spelling of the 64-bit token. */
static int hook_l3_token_arg_ok(const char *value) {
    if (value == NULL || strlen(value) != MAPLESU_L3_TOKEN_DIGITS) return 0;
    for (size_t i = 0; i < MAPLESU_L3_TOKEN_DIGITS; ++i) {
        const char ch = value[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return 0;
    }
    return 1;
}

/* The worker echoes suGateReason only after matching one of the fixed codes the helper
 * can produce (B1). Fixed codes need no JSON escaping; arbitrary caller text would. */
static int hook_l3_reason_ok(const char *value) {
    static const char *const known[] = {
        MAPLESU_L3_REASON_NOT_EXERCISED, MAPLESU_L3_REASON_INVALID,
        MAPLESU_L3_REASON_LOAD_FAILED, MAPLESU_L3_REASON_ARM_REJECTED,
        MAPLESU_L3_REASON_WINDOW_CLOSED, MAPLESU_L3_REASON_ARM_NOT_OBSERVED,
        MAPLESU_L3_REASON_KLOG_UNAVAILABLE,
    };
    if (value == NULL) return 0;
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); ++i)
        if (!strcmp(value, known[i])) return 1;
    return 0;
}

static void hook_l3_token_hex(unsigned long long token, char *out, size_t capacity) {
    snprintf(out, capacity, "%016llx", token);
}

/* Deterministic fallback, only when /dev/urandom could not supply eight bytes:
 * boot_id + CLOCK_REALTIME + pid, FNV-1a mixed. Weak by design, still per-attempt and
 * never printed; the ABI only needs a 64-bit value the kernel and this App share. */
static unsigned long long hook_l3_fallback_token(const char *boot_id) {
    struct timespec now = {0, 0};
    unsigned long long mix = 1469598103934665603ULL;   /* FNV-1a 64 offset basis */
    const char *cursor = boot_id != NULL ? boot_id : "";

    for (; *cursor != '\0'; ++cursor) {
        mix ^= (unsigned long long)(unsigned char)*cursor;
        mix *= 1099511628211ULL;                        /* FNV-1a 64 prime */
    }
    (void)syscall(MAPLESU_NR_CLOCK_GETTIME, MAPLESU_CLOCK_REALTIME, &now);
    mix ^= (unsigned long long)now.tv_sec;
    mix *= 1099511628211ULL;
    mix ^= (unsigned long long)now.tv_nsec;
    mix *= 1099511628211ULL;
    mix ^= (unsigned long long)(unsigned)getpid();
    mix *= 1099511628211ULL;
    /* The ABI treats 0 as "no token"; a mix that lands on 0 is replaced, not retried. */
    return mix != 0 ? mix : 1ULL;
}

/* 0 = eight bytes from /dev/urandom, 1 = the boot_id/time/pid fallback. Neither writes
 * a file: the token's only durable copy is the two evidence records in the App dir. */
static int hook_l3_make_token(const struct hook_state *state, unsigned long long *token) {
    unsigned char bytes[8];
    size_t used = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

    if (fd >= 0) {
        while (used < sizeof(bytes)) {
            const ssize_t got = read(fd, bytes + used, sizeof(bytes) - used);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) break;
            used += (size_t)got;
        }
        close(fd);
    }
    if (used == sizeof(bytes)) {
        unsigned long long value = 0;
        memcpy(&value, bytes, sizeof(value));
        if (value != 0) {
            *token = value;
            return 0;
        }
    }
    *token = hook_l3_fallback_token(state->boot_id);
    return 1;
}

/* One JSON fragment for both records. A token is emitted only when the gate word is
 * ARMED *and* a token exists; any other combination is the fail-closed UNAVAILABLE
 * form, so a half-written state can never look like a usable gate. The optional
 * `reason` is emitted only on the UNAVAILABLE form (B1): an ARMED record keeps exactly
 * the two frozen fields, and an empty reason keeps the step-4-era spelling. */
static int hook_l3_su_json(char *out, size_t capacity, const char *gate,
                           const char *token_hex, const char *reason) {
    const int armed = gate != NULL && !strcmp(gate, MAPLESU_L3_GATE_ARMED) &&
                      token_hex != NULL && token_hex[0] != '\0';
    if (armed)
        return snprintf(out, capacity, "\"suToken\":\"%s\",\"suGate\":\"%s\"",
                        token_hex, MAPLESU_L3_GATE_ARMED);
    if (reason != NULL && reason[0] != '\0')
        return snprintf(out, capacity,
                        "\"suGate\":\"%s\",\"suGateReason\":\"%s\"",
                        MAPLESU_L3_GATE_UNAVAILABLE, reason);
    return snprintf(out, capacity, "\"suGate\":\"%s\"", MAPLESU_L3_GATE_UNAVAILABLE);
}

/*
 * ABI v2's ARM tuple, in one place so the host harness can assert the parameter order
 * without a kernel: option is PR_SET_DUMPABLE itself, arg2 is the op (0 = ARM), arg3
 * and arg4 are the token's low and high halves (the module rebuilds
 * (arg4 << 32) | arg3), and arg5 is the owner uid the SU branch later compares
 * against. The token lives on this stack frame and in the two evidence records only.
 */
static void hook_l3_arm_arguments(unsigned long long token, unsigned int owner_uid,
                                  long arguments[5]) {
    arguments[0] = (long)MAPLESU_L3_PR_SET_DUMPABLE;
    arguments[1] = (long)MAPLESU_L3_OP_ARM;
    arguments[2] = (long)(unsigned long)(token & 0xffffffffULL);
    arguments[3] = (long)(unsigned long)(token >> 32);
    arguments[4] = (long)owner_uid;
}

/* The module's ARM acknowledgement for *this* attempt's owner. The trailing space is
 * part of the format: it terminates the uid, so `owner=1012` can never match inside
 * `owner=10123`, and a different app uid can never satisfy this attempt. */
static void hook_l3_arm_marker(char *out, size_t capacity, unsigned int owner_uid) {
    snprintf(out, capacity, MAPLESU_L3_ARM_MARKER_FMT, owner_uid);
}

/* Non-overlapping occurrences of one exact string in a NUL-terminated window. The
 * confirmation compares two of these counts, so only monotonicity under append matters;
 * a printk line cannot overlap itself. */
static size_t klog_count_occurrences(const char *text, const char *needle) {
    const size_t needle_length = needle != NULL ? strlen(needle) : 0;
    size_t count = 0;
    const char *cursor = text;

    if (text == NULL || needle_length == 0) return 0;
    while ((cursor = strstr(cursor, needle)) != NULL) {
        ++count;
        cursor += needle_length;
    }
    return count;
}

/* One bounded sample of the ring buffer's marker count. 0 = the kernel answered and
 * *count is valid; -1 = no readable buffer (or no memory): the caller fails closed.
 * READ_ALL copies, so this observation never consumes another reader's evidence. */
static int hook_l3_count_marker(const char *marker, size_t *count) {
    char *buffer = malloc(MAPLESU_KLOG_READ_MAX);
    size_t length = 0;

    if (buffer == NULL) return -1;
    const long rc = klog_read_all(buffer, MAPLESU_KLOG_READ_MAX, &length);
    if (rc <= 0) {
        free(buffer);
        return -1;
    }
    *count = klog_count_occurrences(buffer, marker);
    free(buffer);
    return 0;
}

/*
 * The ABI v2 success criterion as a pure decision, so the host can drive it: rc == 0
 * is necessary, and the module's acknowledgement must have *appeared* between the two
 * samples. Comparing counts, not existence, is what rejects a stale line from an
 * earlier attempt in the same boot. Returns NULL when ARMED, else the reason to
 * publish: an unreadable ring buffer is KLOG_UNAVAILABLE; a readable one that did not
 * grow is ARM_NOT_OBSERVED. A window that *shrank* (the ring buffer wrapped between
 * the two samples) lands on the same fail-closed answer: this helper cannot prove the
 * line is new, so it must not claim the gate.
 */
static const char *hook_l3_arm_confirm(int readable, size_t before, size_t after) {
    if (!readable) return MAPLESU_L3_REASON_KLOG_UNAVAILABLE;
    if (after <= before) return MAPLESU_L3_REASON_ARM_NOT_OBSERVED;
    return NULL;
}

/*
 * ARM, once, from the helper's kernel domain. The call is the ABI's first op and the
 * only new privileged action this task adds; every outcome is evidence only.
 *
 * The helper is spawned by the module through call_usermodehelper, so it inherits the
 * kernel's (empty) seccomp state, not the App's - this prctl cannot be filtered here.
 *
 * ABI v2 ordering: the marker count is sampled before the call and again after it, so
 * the confirmation is "the module acknowledged *this* ARM", not "some old line
 * exists". Both samples are taken with the window still open, i.e. before the restore.
 */
static void hook_arm_l3(struct hook_state *state) {
    unsigned long long token = 0;
    long arguments[5];
    char marker[MAPLESU_L3_MARKER_MAX];
    size_t before = 0;
    size_t after = 0;
    int readable;
    int source;
    long rc;
    int saved;
    const char *unconfirmed;

    state->su_token_hex[0] = '\0';
    state->su_arm_rc = -1;
    state->su_arm_errno = 0;
    hook_set_state(state->su_gate, sizeof(state->su_gate), MAPLESU_L3_GATE_UNAVAILABLE);
    /* Provisional reason: this call only runs once the stage-2 image is resident, so
     * an unarmed gate at the end of it means the kernel refused the ARM itself, or
     * never acknowledged it; the confirmation below replaces this with the exact code
     * whenever it has one. */
    hook_set_state(state->su_gate_reason, sizeof(state->su_gate_reason),
                   MAPLESU_L3_REASON_ARM_REJECTED);

    source = hook_l3_make_token(state, &token);
    hook_l3_arm_marker(marker, sizeof(marker), state->dir_uid);
    /* Baseline first. A failed read is not fatal here: the decision below turns it
     * into KLOG_UNAVAILABLE, i.e. fail closed, exactly like a failed second read. */
    readable = hook_l3_count_marker(marker, &before) == 0;

    hook_l3_arm_arguments(token, state->dir_uid, arguments);
    log_line("maplesu-hook: l3 arm begin suGate=UNAVAILABLE source=%s owner=%u\n",
             state->from_ghostlock == 2 ? "maplesu_93260" : state->from_ghostlock ? "ghostlock" : "dirtyfrag", state->dir_uid);
    errno = 0;
    rc = syscall(SYS_prctl, arguments[0], arguments[1], arguments[2], arguments[3],
                 arguments[4]);
    saved = rc == 0 ? 0 : errno;
    state->su_arm_rc = (int)rc;
    state->su_arm_errno = saved;
    if (rc == 0) {
        /*
         * ABI v2: the kernel's own PR_SET_DUMPABLE returns 0 for arg2 in {0, 1}, so
         * rc == 0 is necessary but never sufficient. Only the module's own line,
         * carrying this attempt's owner uid, proves the gate was armed.
         */
        if (hook_l3_count_marker(marker, &after) != 0) readable = 0;
        unconfirmed = hook_l3_arm_confirm(readable, before, after);
        if (unconfirmed == NULL) {
            hook_l3_token_hex(token, state->su_token_hex, sizeof(state->su_token_hex));
            hook_set_state(state->su_gate, sizeof(state->su_gate),
                           MAPLESU_L3_GATE_ARMED);
            /* ARMED carries no reason: the two frozen fields are the whole record. */
            state->su_gate_reason[0] = '\0';
            /* suGate is the only thing this line may say: the token never reaches a log. */
            log_line("maplesu-hook: l3 arm source=%s suGate=ARMED confirmed=%d\n",
                     source == 0 ? "urandom" : "fallback", (int)(after - before));
            return;
        }
        hook_set_state(state->su_gate_reason, sizeof(state->su_gate_reason),
                       unconfirmed);
    }
    /* No hook_fail(): ARM is optional evidence, and a token the kernel did not confirm
     * must not be published. errno and the two counts are kept for the log line and
     * the host test; the token itself never reaches either. */
    state->su_token_hex[0] = '\0';
    log_line("maplesu-hook: l3 arm rc=%ld errno=%d suGate=UNAVAILABLE reason=%s "
             "markers=%zu/%zu\n",
             rc, saved, state->su_gate_reason, before, after);
}

/* `<dirname(argv[0])>/<name>`, the default sibling layout of §4.1/§4.3. */
static void hook_sibling(const char *helper, const char *name, char *out,
                         size_t capacity) {
    const char *slash = strrchr(helper, '/');
    if (slash == NULL) {
        out[0] = '\0';
        return;
    }
    snprintf(out, capacity, "%.*s/%s", (int)(slash - helper), helper, name);
}

/*
 * ============================================================================
 * Step-4 (D2): the pre-entry baseline, and where the target comes from
 * ============================================================================
 * The module can only ever observe 0 (dfroot wrote 0 before it loaded), so argv is a
 * *correlation* fact, not a target. The target comes from the one subject that was
 * alive before the window opened: the App. It writes `<DE>/maplesu-hook-env` with a
 * target plus its provenance, and this process reads it exactly once, through the
 * already-validated directory descriptor, inside the window.
 */
static void hook_read_env(struct hook_state *state, const struct stat *home) {
    char buffer[MAPLESU_HOOK_ENV_MAX + 64];
    char attempt[MAPLESU_HOOK_SMALL_MAX];
    char source[12];
    char *fields[5];
    char *cursor;
    char *space;
    struct stat status;
    ssize_t count;
    size_t used;
    int expected;
    int fd;

    state->env_ok = 0;
    state->env_expected = -1;
    hook_set_state(state->env_source, sizeof(state->env_source), "unknown");
    hook_set_state(attempt, sizeof(attempt), "");
    hook_set_state(source, sizeof(source), "?");
    expected = -1;
    buffer[0] = '\0';

    /* Relative to the validated dirfd: the only path resolution this file does for
     * the env, and it happens while the window is still open. O_NOFOLLOW plus the
     * hard-link count below is the same discipline the attempt document and
     * ir_read_staged use. */
    fd = openat(state->dirfd, MAPLESU_HOOK_ENV_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) goto rejected;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != home->st_uid || status.st_nlink != 1 ||
        (status.st_mode & 0077) != 0 || status.st_size <= 0 ||
        status.st_size > MAPLESU_HOOK_ENV_MAX) {
        close(fd);
        goto rejected;
    }
    do {
        count = read(fd, buffer, sizeof(buffer) - 1);
    } while (count < 0 && errno == EINTR);
    close(fd);
    if (count <= 0 || count != (ssize_t)status.st_size) goto rejected;
    buffer[count] = '\0';
    used = (size_t)count;
    if (used > 0 && buffer[used - 1] == '\n') buffer[--used] = '\0';
    if (used == 0) goto rejected;
    /* No control byte anywhere: one printable line, nothing to negotiate about. */
    for (size_t i = 0; i < used; ++i) {
        const unsigned char ch = (unsigned char)buffer[i];
        if (ch < 0x20 || ch == 0x7f) goto rejected;
    }
    /* Five single-space separated key=value tokens, in the frozen order. */
    memset(fields, 0, sizeof(fields));
    cursor = buffer;
    for (int i = 0; i < 5; ++i) {
        fields[i] = cursor;
        if (i == 4) break;
        space = strchr(cursor, ' ');
        if (space == NULL) goto rejected;
        *space = '\0';
        cursor = space + 1;
    }
    if (strchr(fields[4], ' ') != NULL) goto rejected;
    /* The schema is frozen at "maplesu.hook.env.v1"; MAPLESU_HOOK_ENV_SCHEMA is the
     * single place that literal is written, so the App and this parser cannot drift. */
    if (strncmp(fields[0], "schema=", 7) != 0 ||
        strcmp(fields[0] + 7, MAPLESU_HOOK_ENV_SCHEMA) != 0) goto rejected;
    /* Binding: byte-identical to the boot_id this process read for itself, so an env
     * left over from an earlier boot can never select a target in this one. */
    if (strncmp(fields[1], "boot=", 5) != 0 ||
        strcmp(fields[1] + 5, state->boot_id) != 0) goto rejected;
    if (strncmp(fields[2], "attempt=", 8) != 0) goto rejected;
    if (strlen(fields[2] + 8) != 36) goto rejected;
    for (int i = 0; i < 36; ++i) {
        const char ch = fields[2][8 + i];
        const int hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        if (!hex && ch != '-') goto rejected;
    }
    hook_set_state(attempt, sizeof(attempt), fields[2] + 8);
    if (!strcmp(fields[3], "expected=-1")) expected = -1;
    else if (!strcmp(fields[3], "expected=0")) expected = 0;
    else if (!strcmp(fields[3], "expected=1")) expected = 1;
    else goto rejected;
    if (!strcmp(fields[4], "source=observed"))
        hook_set_state(source, sizeof(source), "observed");
    else if (!strcmp(fields[4], "source=baseline"))
        hook_set_state(source, sizeof(source), "baseline");
    else if (!strcmp(fields[4], "source=unknown"))
        hook_set_state(source, sizeof(source), "unknown");
    else goto rejected;

    state->env_ok = 1;
    state->env_expected = expected;
    hook_set_state(state->env_source, sizeof(state->env_source), source);
    hook_set_state(state->attempt, sizeof(state->attempt), attempt);
    log_line("maplesu-hook: env ok=1 expected=%d source=%s attempt=%s\n",
             expected, source, attempt);
    return;

rejected:
    /* Non-fatal but decisive: with no bound env there is no target, and the decision
     * table below leaves selinuxfs alone. Never guess a value here. */
    log_line("maplesu-hook: env ok=0 expected=-1 source=? attempt=?\n");
}

/*
 * The target decision (step-4 D2, design §2.1.3). This is a *total* function: the
 * table has a row for every reachable combination of (enforce_before, env), and the
 * default at the top *is* the fallback - an unlisted combination writes nothing,
 * reports FAILED/unknown and carries MA_HOOK_ENV_INVALID. There is no "maybe guess".
 *
 * Label honesty (MF-10): KERNEL_SAVED is used only when enforce_before == 1, because
 * only then is the value the kernel's own live byte that this process never moved.
 * When enforce_before == 0 the App's reading or documented baseline is BASELINE, and
 * its provenance travels separately in restore.source.
 */
static void hook_decide_target(struct hook_state *state, const struct hook_request *request) {
    state->want_final = '\0';
    state->restore_origin = "FAILED";
    hook_set_state(state->restore_source, sizeof(state->restore_source), "unknown");

    /*
     * The short circuit C5 depends on: a window that never opened is never written.
     * This branch contains no write and ends in a return, so no env value can reach a
     * selinuxfs write through it.
     */
    if (state->enforce_before == 1) {
        state->want_final = '1';
        state->restore_origin = "KERNEL_SAVED";
        hook_set_state(state->restore_source, sizeof(state->restore_source), "kernel");
        if (state->env_ok && state->env_expected == 0)
            log_line("maplesu-hook: env conflict baseline=0 kernel=1 "
                     "token=MA_HOOK_BASELINE_CONFLICT\n");
        return;
    }
    /* argv is only correlation evidence now, so record it next to the decision. */
    if (state->enforce_before != 0) {
        log_line("maplesu-hook: target unknown (window closed, argv_entry=%c)\n",
                 request->entry != '\0' ? request->entry : '?');
        hook_fail(state, "MA_HOOK_WINDOW_CLOSED");
        return;
    }
    log_line("maplesu-hook: target from env argv_entry=%c env_expected=%d\n",
             request->entry != '\0' ? request->entry : '?', state->env_expected);
    if (!state->env_ok) {
        hook_fail(state, "MA_HOOK_ENV_INVALID");
        return;
    }
    if (state->env_expected != 0 && state->env_expected != 1) {
        hook_fail(state, "MA_HOOK_BASELINE_MISSING");
        return;
    }
    if (strcmp(state->env_source, "observed") != 0 &&
        strcmp(state->env_source, "baseline") != 0) {
        /* "unknown" (or anything this build does not define) is not a provenance the
         * evidence may claim, so it cannot select a target either. */
        hook_fail(state, "MA_HOOK_ENV_INVALID");
        return;
    }
    state->want_final = state->env_expected == 0 ? '0' : '1';
    state->restore_origin = "BASELINE";
    hook_set_state(state->restore_source, sizeof(state->restore_source),
                   state->env_source);
}

/*
 * ============================================================================
 * Step-4 (D4): `bs --attest`, the daemon slot's occupant
 * ============================================================================
 * The same binary in a third mode (design §3.2). It proves three things the App cannot
 * prove for itself: a live uid-0 process exists (kernel SO_PEERCRED ucred, both
 * directions), it belongs to this attempt and this boot, and it reads the policy back
 * independently (a second reader) through descriptors it opened inside the window.
 *
 * What it must never do is the same list UMH mode keeps: no /dev/dfm* milestone, no
 * unlink, no attempt document, no emergency_teardown, no domain switch.
 */
static int attest_mode_requested(int argc, char **argv) {
    if (argc <= 1 || argv == NULL) return 0;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == NULL) continue;
        if (!strcmp(argv[i], MAPLESU_HOOK_ATTEST_TOKEN)) return 1;
    }
    return 0;
}

/* Two paths share a directory once both are canonicalised: the daemon slot may live
 * anywhere inside the package directory, but never outside it (R5). */
static int hook_same_directory(const char *canonical, const char *helper) {
    char left[PATH_MAX];
    char right[PATH_MAX];
    char resolved[PATH_MAX];
    const char *slash;

    if (canonical == NULL || helper == NULL || canonical[0] != '/' || helper[0] != '/')
        return 0;
    if (realpath(helper, resolved) == NULL) return 0;
    slash = strrchr(canonical, '/');
    if (slash == NULL || slash == canonical) return 0;
    snprintf(left, sizeof(left), "%.*s", (int)(slash - canonical), canonical);
    slash = strrchr(resolved, '/');
    if (slash == NULL || slash == resolved) return 0;
    snprintf(right, sizeof(right), "%.*s", (int)(slash - resolved), resolved);
    return strcmp(left, right) == 0;
}

/* One connection: the kernel tells us who connected, and only the App that owns the
 * attempt directory is answered (design §3.2 step 4). */
static void attest_serve(int fd, struct attest_state *state) {
    struct ucred peer;
    socklen_t length = sizeof(peer);
    char hello[128];
    char nonce[80];
    char reply[512];
    ssize_t count;
    size_t used = 0;
    size_t index = 0;
    int enforcing = -1;
    int size;

    memset(&peer, 0, sizeof(peer));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0) {
        log_line("maplesu-hook: attest client credentials errno=%d\n", errno);
        close(fd);
        return;
    }
    log_line("maplesu-hook: attest client uid=%d pid=%d\n", (int)peer.uid, (int)peer.pid);
    if ((unsigned int)peer.uid != state->dir_uid) {
        /* Not the owner of this attempt directory: answer nothing at all. */
        log_line("maplesu-hook: attest client rejected uid=%d\n", (int)peer.uid);
        close(fd);
        return;
    }
    while (used + 1 < sizeof(hello)) {
        count = read(fd, hello + used, sizeof(hello) - 1 - used);
        if (count <= 0) break;
        used += (size_t)count;
        if (memchr(hello, '\n', used) != NULL) break;
    }
    hello[used] = '\0';
    nonce[0] = '\0';
    if (strncmp(hello, "hello ", 6) == 0) {
        while (hello[6 + index] != '\0' && hello[6 + index] != '\n' &&
               index + 1 < sizeof(nonce)) {
            nonce[index] = hello[6 + index];
            ++index;
        }
        nonce[index] = '\0';
    }
    if (nonce[0] == '\0') {
        log_line("maplesu-hook: attest hello rejected\n");
        close(fd);
        return;
    }
    /* One readback per connection, from a descriptor opened inside the window: no
     * path lookup happens here, which is what makes the second reader survive the
     * restore to enforcing (R-D2). */
    if (state->pool_used < MAPLESU_ATTEST_POOL) {
        enforcing = read_byte_fd(state->pool[state->pool_used]);
        ++state->pool_used;
    } else {
        enforcing = read_byte(MAPLESU_ENFORCE_PATH);
    }
    size = snprintf(reply, sizeof(reply),
                    "{\"schema\":\"%s\",\"nonce\":\"%s\",\"pid\":%d,\"domain\":\"%s\","
                    "\"bootId\":\"%s\",\"attempt\":\"%s\",\"starttime\":%ld,"
                    "\"enforcing\":%s}\n",
                    MAPLESU_HOOK_ATTEST_SCHEMA, nonce, (int)getpid(), state->domain,
                    state->boot_id, state->attempt, state->starttime,
                    enforcing < 0 ? "null" : (enforcing == 1 ? "1" : "0"));
    if (size > 0) {
        const size_t length_out = (size_t)size < sizeof(reply) ? (size_t)size
                                                               : sizeof(reply) - 1;
        (void)write(fd, reply, length_out);
    }
    close(fd);
}

/*
 * R-D1: one bounded, validated SELinux context read. The kernel returns the context as
 * a NUL-terminated string whose reported size includes that NUL; anything that is not a
 * plain `u:object_r:...` label, or that carries a control byte, is refused rather than
 * copied onto a file. `size` is the caller's buffer capacity (never larger than
 * MAPLESU_ATTEST_LABEL_MAX), so the read cannot grow with the filesystem's answer.
 */
static int attest_read_label(const char *path, char *label, size_t size) {
    ssize_t length;
    size_t used;

    if (path == NULL || label == NULL || size < 2 || size > MAPLESU_ATTEST_LABEL_MAX) {
        errno = EINVAL;
        return -1;
    }
    memset(label, 0, size);
    length = lgetxattr(path, MAPLESU_SELINUX_XATTR, label, size - 1);
    if (length <= 0) return -1;
    label[size - 1] = '\0';
    used = strlen(label);
    if (used == 0 || strncmp(label, "u:object_r:", 11) != 0) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < used; ++i) {
        const unsigned char byte = (unsigned char)label[i];
        if (byte < 0x20 || byte == 0x7f) {
            errno = EINVAL;
            return -1;
        }
    }
    return (int)used;
}

/*
 * R-D1: copy the App data directory's SELinux context onto the just-bound socket.
 *
 * Why this is the fix: the socket's *type* comes from its parent directory and is
 * already right (`app_data_file`), but its *MLS level* comes from the creating domain -
 * this worker runs as `u:r:kernel:s0`, which has no categories, so the inode ends up at
 * `app_data_file:s0` while the App is at `untrusted_app:s0:c225,c257,c512,c768`. Two
 * different kernel decisions then depend on that level:
 *   - `sock_file getattr` (a `File.exists()` false, so the App never calls connect()), and
 *   - `unix_stream_socket connectto`, whose MLS constraint requires the client's and the
 *     socket's levels to be *equal* (`l1 eq l2`); the App's dominance over s0 is not
 *     enough here - which is exactly why it could *read* the uncategorised JSONs but
 *     never reach the accept queue.
 * Setting the inode's context to the directory's own level makes l1 == l2, and turns the
 * socket into the same object the App would have created itself, so only the ordinary
 * app-data policy path is used - no new policy decision is introduced.
 *
 * Fail-closed and bounded: one stack buffer, one read, one write, no allocation, and
 * every failure is a log line. Callers continue to listen()/accept()/exit 0 regardless,
 * which is what keeps the handover (F1) independent of this mitigation.
 */
static void attest_copy_socket_label(const char *socket_path) {
    char label[MAPLESU_ATTEST_LABEL_MAX];
    /* Observed, not asserted: a copy that lands after the restore is a policy denial
     * the log has to explain, not a crash. read_byte() opens and closes one fd. */
    const int enforcing = read_byte(MAPLESU_ENFORCE_PATH);
    int rc = -1;
    int saved;
    int length;

    errno = 0;
    length = attest_read_label(MAPLESU_ATTEMPT_DIRECTORY, label, sizeof(label));
    if (length <= 0) {
        saved = errno;
        log_line("maplesu-hook: attest socket label copy rc=%d errno=%d enforcing=%d\n",
                 -1, saved, enforcing);
        return;
    }
    errno = 0;
    rc = setxattr(socket_path, MAPLESU_SELINUX_XATTR, label, (size_t)length + 1U, 0);
    saved = rc == 0 ? 0 : errno;
    log_line("maplesu-hook: attest socket label copy rc=%d errno=%d enforcing=%d\n",
             rc == 0 ? 0 : -1, saved, enforcing);
}

/*
 * Rewrite the daemon record with the policy value observed *after* the restore.
 *
 * The socket handshake is the strong evidence (the App reads a kernel-filled ucred off
 * the connection), but it depends on SELinux letting one of the two directions through,
 * and neither direction is guaranteed: the App may not connect to a socket this kernel
 * worker created, and this worker connecting to the App's socket can still trip the MLS
 * category constraint. This file is the fallback: it is created by uid 0, its owner
 * cannot be forged by the App, and it states the boot, the attempt and the restored
 * value. It is weaker evidence and the App labels it as such - never as a ucred.
 */
/* Open before fork: exec success alone does not mean the worker has reached its
 * first app-data lookup before the helper restores enforcement. */
static int attest_prepare_descriptors(int *record_fd, int *enforce_fd) {
    struct stat status;
    *record_fd = open(MAPLESU_HOOK_DAEMON_DOC,
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    *enforce_fd = -1;
    if (*record_fd < 0) return -1;
    if (fstat(*record_fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != 0 || status.st_nlink != 1 || fchmod(*record_fd, 0644) != 0)
        goto failed;
    *enforce_fd = open(MAPLESU_ENFORCE_PATH, O_RDONLY | O_CLOEXEC);
    if (*enforce_fd >= 0) return 0;
failed:
    close(*record_fd);
    *record_fd = -1;
    return -1;
}

static int attest_inherit_fd(const char *variable, int fd) {
    char value[24];
    if (fd < 3 || fcntl(fd, F_SETFD, 0) != 0) return -1;
    snprintf(value, sizeof(value), "%d", fd);
    return setenv(variable, value, 1);
}

static int attest_claim_fd(const char *variable) {
    const char *value = getenv(variable);
    char *end = NULL;
    long fd;
    if (value == NULL || value[0] == '\0') return -1;
    errno = 0;
    fd = strtol(value, &end, 10);
    if (errno != 0 || *end != '\0' || fd < 3 || fd > INT_MAX) return -1;
    if (fcntl((int)fd, F_SETFD, FD_CLOEXEC) != 0) return -1;
    (void)unsetenv(variable);
    return (int)fd;
}

static void attest_write_final(const struct attest_state *state, int enforcing_final)
{
    char document[MAPLESU_HOOK_JSON_MAX];
    char su_fields[96];
    const int fd = state->record_fd;
    int size;

    if (fd < 0 || enforcing_final != 1) {
        log_line("maplesu-hook: attest final unavailable fd=%d enforcing=%d\n",
                 fd, enforcing_final);
        return;
    }
    /* L3 (ABI v2): the worker repeats the helper's gate word, token and (B1) the
     * UNAVAILABLE reason in its own root-owned record. The token only ever comes from
     * MAPLESU_SU_TOKEN in this worker's environment, re-validated when it was read;
     * the worker cannot invent one. */
    hook_l3_su_json(su_fields, sizeof(su_fields),
                    state->su_token[0] != '\0' ? MAPLESU_L3_GATE_ARMED
                                               : MAPLESU_L3_GATE_UNAVAILABLE,
                    state->su_token, state->su_reason);
    size = snprintf(document, sizeof(document),
                    "{\"schema\":\"%s\",\"pid\":%d,\"uid\":%d,\"domain\":\"%s\","
                    "\"bootId\":\"%s\",\"attempt\":\"%s\",\"socket\":\"%s\","
                    "\"starttime\":%ld,\"enforcingFinal\":%d,%s}\n",
                    MAPLESU_HOOK_ATTEST_SCHEMA, (int)getpid(), (int)getuid(),
                    state->domain, state->boot_id, state->attempt, state->socket_path,
                    state->starttime, enforcing_final, su_fields);
    /* The helper created an empty O_EXCL file before fork. This is its first
     * write: truncating here would request inode write permission again after
     * enforcement is restored, despite the descriptor already being open. */
    if (size <= 0 || size >= (int)sizeof(document) ||
        write(fd, document, (size_t)size) != size || fsync(fd) != 0) {
        log_line("maplesu-hook: attest final write failed errno=%d\n", errno);
        return;
    }
    log_line("maplesu-hook: attest final enforcing=%d\n", enforcing_final);
}

static int attest_main(int argc, char **argv) {
    struct attest_state state;
    struct stat home;
    struct sockaddr_un address;
    char socket_name[MAPLESU_HOOK_SMALL_MAX];
    char document[MAPLESU_HOOK_JSON_MAX];
    char su_fields[96];
    char stat_line[256];
    char *attempt = NULL;
    char *boot = NULL;
    const char *env_token;
    const char *env_reason;
    int seen_attest = 0;
    int served = 0;
    int server = -1;
    int document_fd = -1;
    int enforcing_initial = -1;
    int size;

    memset(&state, 0, sizeof(state));
    memset(&address, 0, sizeof(address));
    state.dirfd = -1;
    state.record_fd = -1;
    state.enforce_fd = -1;
    state.starttime = 0;
    for (int i = 0; i < MAPLESU_ATTEST_POOL; ++i) state.pool[i] = -1;

    for (int i = 1; i < argc; ++i) {
        const char *token = argv[i];
        const char *value;
        int want_boot;
        if (token == NULL) return 64;
        if (!strcmp(token, MAPLESU_HOOK_ATTEST_TOKEN)) {
            if (seen_attest) return 64;
            seen_attest = 1;
            continue;
        }
        if (!strcmp(token, "--attempt") || !strcmp(token, "--boot")) {
            want_boot = !strcmp(token, "--boot");
            if ((want_boot && boot != NULL) || (!want_boot && attempt != NULL) ||
                i + 1 >= argc) return 64;
            value = argv[++i];
            if (value == NULL || value[0] == '\0' ||
                strlen(value) >= MAPLESU_HOOK_SMALL_MAX) return 64;
            for (const char *ch = value; *ch != '\0'; ++ch) {
                const unsigned char byte = (unsigned char)*ch;
                /* No separator, quote, escape or control byte: the value is echoed
                 * into JSON and concatenated into a path. */
                if (byte < 0x20 || byte == 0x7f || byte == '"' || byte == '\\' ||
                    byte == '/') return 64;
            }
            if (want_boot) boot = (char *)value;
            else attempt = (char *)value;
            continue;
        }
        /* L3 (B1): the token is *not* an argv token any more. It arrives through the
         * environment, read below; an argv flag carrying it would be world-readable
         * in /proc/<pid>/cmdline for the worker's whole lifetime. */
        return 64;
    }
    if (!seen_attest || attempt == NULL || boot == NULL) return 64;
    /*
     * L3 (B1): the helper hands the token over in the environment (the L3 block at the
     * top of this file explains why). Reading it here - before any evidence is written -
     * keeps the worker's own record consistent with the helper's. A value that is not
     * the exact 16-lowercase-hex spelling is refused and the gate stays UNAVAILABLE:
     * the worker never invents a token and never echoes a malformed one.
     */
    env_token = getenv(MAPLESU_L3_ENV_TOKEN);
    env_reason = getenv(MAPLESU_L3_ENV_REASON);

    state.dirfd = attest_claim_fd(MAPLESU_ATTEST_ENV_DIR_FD);
    state.record_fd = attest_claim_fd(MAPLESU_ATTEST_ENV_RECORD_FD);
    state.enforce_fd = attest_claim_fd(MAPLESU_ATTEST_ENV_ENFORCE_FD);
    if (state.dirfd < 0 || state.record_fd < 0 || state.enforce_fd < 0) return 65;
    struct stat record;
    if (fstat(state.record_fd, &record) != 0 || !S_ISREG(record.st_mode) ||
        record.st_uid != 0 || record.st_nlink != 1 || (record.st_mode & 0777) != 0644 ||
        (fcntl(state.record_fd, F_GETFL) & O_ACCMODE) != O_WRONLY ||
        (fcntl(state.enforce_fd, F_GETFL) & O_ACCMODE) != O_RDONLY) return 65;
    if (fstat(state.dirfd, &home) != 0 || !S_ISDIR(home.st_mode) ||
        home.st_uid < 10000 || home.st_uid >= 100000 || (home.st_mode & 0077) != 0) {
        close(state.dirfd);
        return 65;
    }
    state.dir_uid = (unsigned int)home.st_uid;
    state.dir_gid = (unsigned int)home.st_gid;
    hook_set_state(state.attempt, sizeof(state.attempt), attempt);
    hook_set_state(state.boot_id, sizeof(state.boot_id), boot);
    hook_set_state(state.su_token, sizeof(state.su_token), "");
    if (env_token != NULL) {
        if (hook_l3_token_arg_ok(env_token))
            hook_set_state(state.su_token, sizeof(state.su_token), env_token);
        else
            log_line("maplesu-hook: attest l3 token rejected\n");
    }
    /* A reason is only meaningful while the gate is UNAVAILABLE: an ARMED worker keeps
     * exactly the two frozen fields. Anything that is not one of the helper's fixed
     * codes is reported as NOT_ARMED rather than echoed. */
    hook_set_state(state.su_reason, sizeof(state.su_reason), "");
    if (state.su_token[0] == '\0')
        hook_set_state(state.su_reason, sizeof(state.su_reason),
                       hook_l3_reason_ok(env_reason) ? env_reason
                                                     : MAPLESU_L3_REASON_NOT_ARMED);
    log_line("maplesu-hook: attest l3 gate=%s reason=%s\n",
             state.su_token[0] != '\0' ? MAPLESU_L3_GATE_ARMED
                                       : MAPLESU_L3_GATE_UNAVAILABLE,
             state.su_reason[0] != '\0' ? state.su_reason : "-");
    (void)hook_read_small(MAPLESU_CURRENT_DOMAIN_PATH, state.domain,
                          sizeof(state.domain));
    /* Same-pid reuse detection only (design §3.1): the kernel ucred is the identity,
     * this number just distinguishes two processes that happened to share a pid. */
    if (hook_read_small("/proc/self/stat", stat_line, sizeof(stat_line)) == 0) {
        char *close_paren = strrchr(stat_line, ')');
        if (close_paren != NULL) {
            const char *cursor = close_paren + 1;
            for (int field = 3; field <= 22 && *cursor != '\0'; ++field) {
                while (*cursor == ' ') ++cursor;
                if (field == 22) {
                    state.starttime = strtol(cursor, NULL, 10);
                    break;
                }
                while (*cursor != ' ' && *cursor != '\0') ++cursor;
            }
        }
    }

    snprintf(socket_name, sizeof(socket_name), MAPLESU_HOOK_DAEMON_SOCK_FMT, attempt);
    snprintf(state.socket_path, sizeof(state.socket_path), "%s%s",
             MAPLESU_ATTEMPT_DIRECTORY, socket_name);
    log_line("maplesu-hook: attest worker pid=%d uid=%d socket=%s attempt=%s\n",
             (int)getpid(), (int)getuid(), state.socket_path, attempt);

    /*
     * Reverse direction (device fact, DEV-174): an AF_UNIX socket's SID is fixed when
     * bind() runs, taken from the creating process's own sid. Relabelling the inode
     * afterwards - which this worker does, and which succeeds - does not change the
     * socket's sid, so an untrusted_app can never connect to a socket this kernel
     * worker created: the kernel refuses connectto with tcontext=u:r:kernel:s0.
     *
     * So the App listens and this worker connects. The App still gets the kernel-filled
     * ucred of the connector (the F2 evidence), and no SELinux policy change is needed.
     * Binding stays as the fallback for a run where nobody is listening.
     */
    {
        int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (client >= 0) {
            struct sockaddr_un peer;
            int connected = -1;

            memset(&peer, 0, sizeof(peer));
            peer.sun_family = AF_UNIX;
            /*
             * sun_path is 108 bytes on Linux while socket_path is PATH_MAX, so the copy
             * needs its own bound: this runs with kernel credentials and a stack
             * overflow here would be the worst possible place for one.
             */
            if (strlen(state.socket_path) >= sizeof(peer.sun_path)) {
                log_line("maplesu-hook: attest reverse path too long");
                close(client);
                client = -1;
            }
            if (client >= 0)
                memcpy(peer.sun_path, state.socket_path, strlen(state.socket_path) + 1);
            /*
             * The App starts listening when it can *claim* - that is, after the restore,
             * because the claim's whole point is a worker that reads enforcing == 1. A
             * worker that gave up in two seconds would report the value from inside the
             * window instead, which is 0 by construction and would look like a failed
             * restore.
             */
            /*
             * Report the policy *after* the restore, not from inside the window: the
             * worker starts while SELinux is permissive, and a claim that reads 0 there
             * would look like a failed restore. Polling is enough - the helper restores
             * as its last act, and no lock is shared between the two processes.
             */
            for (int waited = 0; waited < 2400; ++waited) {
                char value = 0;
                if (pread(state.enforce_fd, &value, 1, 0) == 1 && value == '1') break;
                usleep(50000); /* 50 ms x 2400 = 120 s */
            }
            /* The restored value goes on disk either way: if the handshake below is
             * refused by SELinux, this is the only channel left. */
            /* pread above leaves this one-shot descriptor at offset zero. */
            attest_write_final(&state, read_byte_fd(state.enforce_fd));
            for (int tries = 0; tries < 3000; ++tries) {
                connected = connect(client, (const struct sockaddr *)&peer,
                                    sizeof(peer));
                if (connected == 0) break;
                if (tries == 0)
                    log_line("maplesu-hook: attest reverse waiting for the App");
                usleep(50000); /* 50 ms x 3000 = 150 s */
            }
            if (connected == 0) {
                /*
                 * Wait for the caller's hello so the value below is read after it asked,
                 * but never indefinitely: a peer that connects and says nothing would
                 * otherwise park this process forever, and it is the process that has to
                 * unload the module.
                 */
                char hello[128];
                struct timeval hello_timeout;

                hello_timeout.tv_sec = 5;
                hello_timeout.tv_usec = 0;
                (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &hello_timeout,
                                 sizeof(hello_timeout));
                (void)read(client, hello, sizeof(hello) - 1);
                const int enforcing_now = read_byte("/sys/fs/selinux/enforce");
                char line[512];
                const int length = snprintf(
                    line, sizeof(line),
                    "{\"schema\":\"%s\",\"pid\":%d,\"uid\":%d,\"domain\":\"%s\","
                    "\"boot\":\"%s\",\"attempt\":\"%s\",\"starttime\":%ld,"
                    "\"enforcing\":%d}\n",
                    MAPLESU_HOOK_ATTEST_SCHEMA, (int)getpid(), (int)getuid(),
                    state.domain, boot, attempt, (long)state.starttime,
                    enforcing_now);

                if (length > 0 && write(client, line, (size_t)length) == length)
                    log_line("maplesu-hook: attest reverse connect ok attempt=%s\n",
                             attempt);
                else
                    log_line("maplesu-hook: attest reverse write failed errno=%d\n",
                             errno);
                close(client);
                return 0;
            }
            log_line("maplesu-hook: attest reverse connect unavailable errno=%d\n", errno);
            close(client);
        }
    }

    server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) {
        log_line("maplesu-hook: attest socket failed errno=%d\n", errno);
        return 66;
    }
    if (strlen(state.socket_path) >= sizeof(address.sun_path)) {
        log_line("maplesu-hook: attest path too long\n");
        close(server);
        return 66;
    }
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", state.socket_path);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) {
        log_line("maplesu-hook: attest bind failed errno=%d path=%s\n", errno,
                 state.socket_path);
        close(server);
        return 66;
    }
    /* The App must be able to connect() to its own attempt directory's socket, so the
     * inode belongs to the App and carries no group/other bits. The directory itself is
     * 0700, so nothing outside this uid can even see the name. */
    if (chmod(state.socket_path, 0600) != 0)
        log_line("maplesu-hook: attest chmod failed errno=%d\n", errno);
    if (chown(state.socket_path, (uid_t)state.dir_uid, (gid_t)state.dir_gid) != 0)
        log_line("maplesu-hook: attest chown failed errno=%d\n", errno);
    /*
     * R-D1 mitigation, immediately after the inode exists and before anything can
     * connect to it: give the socket the App's own SELinux context (see
     * attest_copy_socket_label). Fail-closed by construction - it returns void and
     * every failure is only a log line, so bind/chmod/chown/listen/handover are
     * untouched when the operation is refused (EOPNOTSUPP, EPERM, window already
     * closed, …).
     */
    attest_copy_socket_label(state.socket_path);
    if (listen(server, 4) != 0) {
        log_line("maplesu-hook: attest listen failed errno=%d\n", errno);
        close(server);
        return 66;
    }
    /* Read-back, not assertion: the effective label is what the next device run has to
     * show, so a failed copy is visible as `label=` without categories (or `label=?`)
     * in exactly one bounded line. */
    {
        char ready_label[MAPLESU_ATTEST_LABEL_MAX];
        if (attest_read_label(state.socket_path, ready_label, sizeof(ready_label)) > 0)
            log_line("maplesu-hook: attest socket ready label=%s\n", ready_label);
        else
            log_line("maplesu-hook: attest socket ready label=? errno=%d\n", errno);
    }
    /* The second reader's structural guarantee: every reply reads a descriptor opened
     * here, while the window is open, so no lookup happens under enforcing. */
    for (int i = 0; i < MAPLESU_ATTEST_POOL; ++i)
        state.pool[i] = open(MAPLESU_ENFORCE_PATH, O_RDONLY | O_CLOEXEC);
    enforcing_initial = read_byte(MAPLESU_ENFORCE_PATH);

    document_fd = state.record_fd;
    if (document_fd >= 0 && ftruncate(document_fd, 0) == 0 &&
        lseek(document_fd, 0, SEEK_SET) >= 0) {
        /* L3 (ABI v2): same fields as attest_write_final(), so whichever of the two
         * daemon-record writes lands last still carries the gate word, token and the
         * UNAVAILABLE reason. */
        hook_l3_su_json(su_fields, sizeof(su_fields),
                        state.su_token[0] != '\0' ? MAPLESU_L3_GATE_ARMED
                                                  : MAPLESU_L3_GATE_UNAVAILABLE,
                        state.su_token, state.su_reason);
        size = snprintf(document, sizeof(document),
                        "{\"schema\":\"%s\",\"pid\":%d,\"uid\":%d,\"domain\":\"%s\","
                        "\"bootId\":\"%s\",\"attempt\":\"%s\",\"socket\":\"%s\","
                        "\"starttime\":%ld,\"enforcingInitial\":%s%s,%s}\n",
                        MAPLESU_HOOK_ATTEST_SCHEMA, (int)getpid(), (int)getuid(),
                        state.domain, state.boot_id, state.attempt, state.socket_path,
                        state.starttime,
                        enforcing_initial < 0 ? "null"
                                              : (enforcing_initial == 1 ? "1" : "0"),
                        /* This write happens after attest_write_final() and would
                         * otherwise clobber the restored value it recorded. */
                        enforcing_initial == 1 ? ",\"enforcingFinal\":1" : "",
                        su_fields);
        if (size >= (int)sizeof(document))
            log_line("maplesu-hook: attest document truncated size=%d limit=%d\n", size,
                     (int)sizeof(document));
        if (size > 0) {
            const size_t length_out = (size_t)size < sizeof(document)
                                          ? (size_t)size : sizeof(document) - 1;
            (void)write(document_fd, document, length_out);
            (void)fsync(document_fd);
        }
        close(document_fd);
    } else {
        log_line("maplesu-hook: attest document failed errno=%d\n", errno);
    }

    for (served = 0; served < MAPLESU_ATTEST_SERVES; ++served) {
        const int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) { --served; continue; }
            log_line("maplesu-hook: attest accept rc=%d errno=%d served=%d\n", -1, errno,
                     served);
            break;
        }
        attest_serve(client, &state);
    }
    close(server);
    log_line("maplesu-hook: attest done served=%d\n", served);
    /* No unlink: UMH/attest mode never removes a file. The socket name carries this
     * attempt's prefix, so a survivor can never collide with the next attempt; the App
     * removes its own directory's stale ones (design §3.5 item 24). */
    return 0;
}

/* Read new kernel records independently while the loader may be blocked. The
 * pre-opened cursor starts at the end, and log_line fsyncs its existing sinks.
 * This is a bounded observer: it neither retries nor cancels the module load. */
static pid_t hook_stage2_watch_start(int *stop_fd) {
    int control[2];
    *stop_fd = -1;
    const int input = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input < 0) {
        log_line("maplesu-hook: stage2 watch unavailable errno=%d\n", errno);
        return -1;
    }
    if (lseek(input, 0, SEEK_END) < 0 || pipe2(control, O_CLOEXEC | O_NONBLOCK)) {
        const int error = errno;
        close(input);
        log_line("maplesu-hook: stage2 watch setup failed errno=%d\n", error);
        return -1;
    }
    const pid_t parent = getpid();
    const pid_t child = fork();
    if (child < 0) {
        const int error = errno;
        close(input);
        close(control[0]);
        close(control[1]);
        log_line("maplesu-hook: stage2 watch fork failed errno=%d\n", error);
        return -1;
    }
    if (child == 0) {
        close(control[1]);
        struct pollfd watched[2] = {{input, POLLIN, 0}, {control[0], POLLIN, 0}};
        struct timespec started, now;
        unsigned int scanned = 0;
        int fault = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &started)) _exit(0);
        log_line("maplesu-hook: stage2 watch active\n");
        while (scanned < 256U * 1024U && getppid() == parent) {
            if (clock_gettime(CLOCK_MONOTONIC, &now) ||
                now.tv_sec - started.tv_sec >= 120) break;
            watched[0].revents = watched[1].revents = 0;
            if (poll(watched, 2, 100) < 0 && errno != EINTR) break;
            /* Drain after the stop signal as well: init's final record may have
             * arrived together with the successful syscall return. */
            for (unsigned int batch = 0; batch < 32 && scanned < 256U * 1024U; ++batch) {
                char record[8192];
                const ssize_t size = read(input, record, sizeof(record) - 1);
                if (size < 0 && (errno == EPIPE || errno == EINTR)) continue;
                if (size <= 0) break;
                scanned += (unsigned int)size;
                record[size] = '\0';
                if (klog_line_contains_token(record, (size_t)size)) continue;
                if (strstr(record, "Kernel panic") || strstr(record, "BUG:") ||
                    strstr(record, "Oops:") || strstr(record, "CFI failure")) fault = 1;
                if (fault || strstr(record, "maplesu_l3") ||
                    strstr(record, "version magic") || strstr(record, "Unknown symbol") ||
                    strstr(record, "Call trace:"))
                    log_line("maplesu-hook: stage2 kernel %.*s\n", (int)size, record);
            }
            if (watched[1].revents) break;
        }
        close(input);
        close(control[0]);
        _exit(0);
    }
    close(input);
    close(control[0]);
    *stop_fd = control[1];
    return child;
}

static void hook_stage2_watch_stop(pid_t child, int stop_fd) {
    if (child <= 0) return;
    /* The read end can disappear at the deadline; closing is also a stop signal
     * and avoids a write/SIGPIPE race with the bounded observer. */
    if (stop_fd >= 0) close(stop_fd);
    for (unsigned int attempt = 0; attempt < 10; ++attempt) {
        const pid_t result = waitpid(child, NULL, WNOHANG);
        if (result == child || (result < 0 && errno != EINTR)) return;
        usleep(20000);
    }
    log_line("maplesu-hook: stage2 watch reap pending\n");
}

/*
 * Stage-2 slot (design §4.2). Validation reuses the staged-input judgement and the
 * ELF preconditions above instead of a second rule set; loading happens strictly
 * inside the permissive window because the kernel's module-reading path is not
 * proven under enforcing for this domain. Step-3 never stages this file, so the
 * expected outcome is NOT_EXERCISED (§9 A5) - the LOADED branch is the documented
 * L3 blind spot (R11) and is not exercised by the step-3 device run.
 */
static void hook_stage2(struct hook_state *state) {
    unsigned char *image = NULL;
    size_t size = 0;
    struct stat status = {0};
    int fd = -1;

    hook_set_state(state->stage2_state, sizeof(state->stage2_state), "NOT_EXERCISED");
    if (state->enforce_before != 0) {
        /* No window, no kernel-side load and no ARM: name the reason, leave the
         * verdict to the restore rungs that actually failed. */
        hook_set_state(state->su_gate_reason, sizeof(state->su_gate_reason),
                       MAPLESU_L3_REASON_WINDOW_CLOSED);
        return;
    }

    fd = openat(state->dirfd, MAPLESU_STAGE2_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;                        /* absent -> NOT_EXERCISED, the normal end */
    close(fd);
    fd = -1;
    image = malloc(MAPLESU_IR_MODULE_LIMIT);
    if (image == NULL) {
        hook_set_state(state->stage2_state, sizeof(state->stage2_state), "INVALID");
        hook_set_state(state->su_gate_reason, sizeof(state->su_gate_reason),
                       MAPLESU_L3_REASON_INVALID);
        hook_fail(state, "MA_HOOK_STAGE2_INVALID");
        return;
    }
    if (ir_read_staged(state->dirfd, MAPLESU_STAGE2_NAME, image,
                       MAPLESU_IR_MODULE_LIMIT, &size, &fd) != 0 ||
        ir_elf_precheck(image, size) != 0) {
        if (fd >= 0) close(fd);
        hook_set_state(state->stage2_state, sizeof(state->stage2_state), "INVALID");
        hook_set_state(state->su_gate_reason, sizeof(state->su_gate_reason),
                       MAPLESU_L3_REASON_INVALID);
        hook_fail(state, "MA_HOOK_STAGE2_INVALID");
        free(image);
        return;
    }
    /* Keep the reader's descriptor: reopening by name could load a different
     * same-sized inode after validation. Check its final size without reopening. */
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        (size_t)status.st_size != size) {
        if (fd >= 0) close(fd);
        hook_set_state(state->stage2_state, sizeof(state->stage2_state), "INVALID");
        hook_set_state(state->su_gate_reason, sizeof(state->su_gate_reason),
                       MAPLESU_L3_REASON_INVALID);
        hook_fail(state, "MA_HOOK_STAGE2_INVALID");
        free(image);
        return;
    }
    /* Ghostlock Normal's late-loader uses init_module on a checked buffer.
     * Match that transport for its Ultra source instead of submitting an App
     * data inode from the inherited root worker. The L3 image and all following
     * ARM/daemon/restore operations stay shared. DirtyFrag's real UMH and the
     * proven 93260 path retain finit_module with flags=0. No load retry: a
     * rejected image must reach the existing restore and failure reporting. */
    const int from_buffer = state->from_ghostlock == 1;
    log_line("maplesu-hook: stage2 loader=%s transport=%s\n",
             from_buffer ? "init_module" : "finit_module", from_buffer ? "buffer" : "file");
    log_line("maplesu-hook: stage2 load begin source=%s bytes=%zu\n",
             state->from_ghostlock == 2 ? "maplesu_93260" : state->from_ghostlock ? "ghostlock" : "dirtyfrag", size);
    int watch_stop = -1;
    const pid_t watch = from_buffer ? hook_stage2_watch_start(&watch_stop) : -1;
    const int rc = from_buffer
        ? (int)syscall(MAPLESU_NR_INIT_MODULE, image, size, "")
        : (int)syscall(MAPLESU_NR_FINIT_MODULE, fd, "", 0);
    const int error = rc == 0 ? 0 : errno;
    log_line("maplesu-hook: stage2 load exit rc=%d errno=%d\n", rc, error);
    hook_stage2_watch_stop(watch, watch_stop);
    close(fd);
    free(image);
    state->stage2_rc = rc;
    state->stage2_errno = error;
    /*
     * -EEXIST means the module is already resident under this name. That is the normal
     * case once the stager injects OUR module: the kernel already holds it, so the
     * handover target is exactly the module this step wanted to load. Treating it as a
     * failure failed a run whose kernel half had in fact succeeded.
     */
    if (rc == 0 || error == 17) {
        hook_set_state(state->stage2_state, sizeof(state->stage2_state),
                       rc == 0 ? "LOADED" : "ALREADY_RESIDENT");
        /* The module's own name comes from /proc/modules, not from a guess. */
        const int modules = open("/proc/modules", O_RDONLY | O_CLOEXEC);
        if (modules >= 0) {
            char buffer[4096];
            const ssize_t count = read(modules, buffer, sizeof(buffer) - 1);
            close(modules);
            if (count > 0) {
                buffer[count] = '\0';
                for (char *line = buffer; line != NULL && *line; ) {
                    char *next = strchr(line, '\n');
                    if (strncmp(line, MAPLESU_HOOK_MODULE_NAME " ", 13) != 0) {
                        size_t length = 0;
                        while (line[length] != '\0' && line[length] != ' ' &&
                               length + 1 < sizeof(state->stage2_name)) ++length;
                        if (length > 0) {
                            memcpy(state->stage2_name, line, length);
                            state->stage2_name[length] = '\0';
                            break;
                        }
                    }
                    line = next == NULL ? NULL : next + 1;
                }
            }
        }
        /*
         * L3 (ABI v2): ARM only now that the stage-2 image is resident (LOADED or
         * ALREADY_RESIDENT), and therefore before the restore below closes the window.
         * A failure is recorded in suGate/su_arm_errno, never raised as hook_fail():
         * DAEMON_READY does not depend on the L3 module (it lands separately), so a
         * kernel without it must produce the exact same verdict as today.
         */
        hook_arm_l3(state);
    } else {
        /*
         * B1: the stage-2 slot is the L3 slot, so the kernel refusing this image is an
         * L3-only fact. This branch deliberately calls neither hook_fail() nor moves the
         * failure count or the verdict token: the handover verdict and the exit code
         * stay exactly what the restore/unload rungs said, and the App reads the cause
         * from stage2.state + suGateReason instead of losing a working DAEMON_READY.
         */
        hook_set_state(state->stage2_state, sizeof(state->stage2_state), "LOAD_FAILED");
        hook_set_state(state->su_gate_reason, sizeof(state->su_gate_reason),
                       MAPLESU_L3_REASON_LOAD_FAILED);
        hook_set_state(state->su_gate, sizeof(state->su_gate),
                       MAPLESU_L3_GATE_UNAVAILABLE);
        /* The token name stays the greppable diagnostic of §5.3 - it is a condition,
         * not a verdict: it never reaches hook_fail() or the JSON `token` field. */
        log_line("maplesu-hook: stage2 state=LOAD_FAILED rc=%d errno=%d "
                 "suGate=UNAVAILABLE reason=%s token=MA_HOOK_STAGE2_LOAD_FAILED\n",
                 rc, error, MAPLESU_L3_REASON_LOAD_FAILED);
        /* The kernel's reason, through the same bounded dump the rest of this file uses. */
        ir_dump_kernel_log("hook-stage2");
    }
}

/*
 * Daemon slot (design §4.3, step-4 §3.2). Same shape as the consumer validation in
 * main(), minus the `/data/app/` prefix: a step-4 daemon may live in the App's private
 * directory. The fork+exec happens inside the window for the same reason as stage-2,
 * and the CLOEXEC pipe is how the parent learns whether exec succeeded (EOF = success).
 *
 * Step-4 (MF-2): the owner check is the *attempt directory's* uid, never getuid().
 * This process is uid 0, so `getuid()` would only ever admit {0,1000} and reject the
 * App-owned `<CE>/bs` that the module itself execs - a guaranteed
 * MA_HOOK_DAEMON_INVALID. `dir_uid` comes from the fstat() of a directory that already
 * passed S_ISDIR + uid in [10000,100000) + mode&0077 == 0, and the set stays
 * {0, 1000, dir_uid}: the same discipline as ir_read_staged's "the staged file belongs
 * to the directory's owner". It grants nothing new, because that same App already
 * controls the content of `<CE>/bs`.
 */
static void hook_daemon(struct hook_state *state) {
    struct stat status = {0};
    char canonical[PATH_MAX];
    char socket_name[MAPLESU_HOOK_SMALL_MAX];
    int pipe_fds[2];
    int record_fd = -1;
    int enforce_fd = -1;

    hook_set_state(state->daemon_state, sizeof(state->daemon_state), "NOT_EXERCISED");
    state->daemon_pid = -1;
    if (state->enforce_before != 0) return;
    if (access(state->daemon_path, F_OK) != 0) return;
    if (state->attempt[0] == '\0') {
        /* No attempt binding means no socket name, so a worker could not answer for
         * this attempt even if it started. Leave the slot NOT_EXERCISED and say why. */
        log_line("maplesu-hook: daemon skipped (no attempt binding)\n");
        return;
    }
    if (realpath(state->daemon_path, canonical) == NULL ||
        !hook_same_directory(canonical, state->helper) ||
        stat(canonical, &status) != 0 || !S_ISREG(status.st_mode) ||
        !(status.st_uid == 0 || status.st_uid == 1000 ||
          status.st_uid == (uid_t)state->dir_uid) ||
        (status.st_mode & 0022) || access(canonical, X_OK) != 0) {
        hook_set_state(state->daemon_state, sizeof(state->daemon_state), "INVALID");
        hook_fail(state, "MA_HOOK_DAEMON_INVALID");
        return;
    }
    /* L3 (ABI v2/B1): the token reaches the worker only when the worker *is* this same
     * binary. A `--daemon <path>` override is somebody else's program: handing it a
     * secret it does not know about would be pointless, and that program writes its own
     * record without knowing L3 anyway. The token crosses the exec boundary through the
     * environment (the L3 block at the top of this file says why argv is wrong), and
     * only for this default occupant. */
    char helper_canonical[PATH_MAX];
    const int same_binary = realpath(state->helper, helper_canonical) != NULL &&
                            strcmp(helper_canonical, canonical) == 0;
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        hook_set_state(state->daemon_state, sizeof(state->daemon_state), "INVALID");
        hook_fail(state, "MA_HOOK_DAEMON_INVALID");
        return;
    }
    if (same_binary && attest_prepare_descriptors(&record_fd, &enforce_fd) != 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        hook_set_state(state->daemon_state, sizeof(state->daemon_state), "INVALID");
        hook_fail(state, "MA_HOOK_DAEMON_INVALID");
        return;
    }
    const pid_t child = fork();
    if (child == 0) {
        close(pipe_fds[0]);
        (void)setsid();
        /*
         * L3 (B1): the token leaves through the environment, never argv. argv is
         * /proc/<pid>/cmdline (0444, readable by every app for this worker's whole
         * life); environ is 0400 root-owned and additionally gated by the kernel's
         * ptrace check, so no app uid can read it. setenv() copies the value, so the
         * entry outlives this frame and lives only as long as the exec'd worker.
         */
        if (same_binary) {
            if (attest_inherit_fd(MAPLESU_ATTEST_ENV_RECORD_FD, record_fd) != 0 ||
                attest_inherit_fd(MAPLESU_ATTEST_ENV_ENFORCE_FD, enforce_fd) != 0 ||
                attest_inherit_fd(MAPLESU_ATTEST_ENV_DIR_FD, state->dirfd) != 0) {
                const int error = errno;
                (void)write(pipe_fds[1], &error, sizeof(error));
                _exit(127);
            }
            const char *variable = MAPLESU_L3_ENV_REASON;
            const char *value = state->su_gate_reason;
            if (state->su_token_hex[0] != '\0') {
                variable = MAPLESU_L3_ENV_TOKEN;
                value = state->su_token_hex;
            }
            if (value[0] != '\0' && setenv(variable, value, 1) != 0)
                log_line("maplesu-hook: l3 env rc=%d errno=%d\n", -1, errno);
        }
        /* One binary, a third mode: the same `bs` becomes the attestation worker, so
         * no new asset, path or packaging entry is needed (design §3.2/D4-8). */
        char *argv[7];
        int slot = 0;
        argv[slot++] = state->daemon_path;
        argv[slot++] = (char *)MAPLESU_HOOK_ATTEST_TOKEN;
        argv[slot++] = (char *)"--attempt";
        argv[slot++] = state->attempt;
        argv[slot++] = (char *)"--boot";
        argv[slot++] = state->boot_id;
        argv[slot] = NULL;
        execv(argv[0], argv);
        const int error = errno;
        (void)write(pipe_fds[1], &error, sizeof(error));
        _exit(127);
    }
    close(pipe_fds[1]);
    if (record_fd >= 0) close(record_fd);
    if (enforce_fd >= 0) close(enforce_fd);
    if (child < 0) {
        close(pipe_fds[0]);
        hook_set_state(state->daemon_state, sizeof(state->daemon_state), "INVALID");
        hook_fail(state, "MA_HOOK_DAEMON_INVALID");
    } else {
        int error = 0;
        const ssize_t got = read(pipe_fds[0], &error, sizeof(error));
        close(pipe_fds[0]);
        if (got > 0) {
            hook_set_state(state->daemon_state, sizeof(state->daemon_state), "EXEC_FAILED");
            hook_fail(state, "MA_HOOK_DAEMON_EXEC_FAILED");
        } else {
            hook_set_state(state->daemon_state, sizeof(state->daemon_state), "STARTED");
            state->daemon_pid = (long)child;
            /* The socket name carries the attempt prefix, so a survivor from an earlier
             * attempt can never collide with this one (UMH/attest mode may not unlink). */
            snprintf(socket_name, sizeof(socket_name), MAPLESU_HOOK_DAEMON_SOCK_FMT,
                     state->attempt);
            log_line("maplesu-hook: attest socket=%s%s attempt=%s\n",
                     MAPLESU_ATTEMPT_DIRECTORY, socket_name, state->attempt);
        }
    }
}

/*
 * The unload child (design §6, §5.1 step 12a; step-4 §2.4). Runs in a forked copy so
 * the parent can exit and release module_mutex even if UMH_WAIT_EXEC turns out to wait
 * for this process (R12): delete_module() needs the same mutex init_module() holds.
 *
 * Step-4 makes this the **only** writer of selinuxfs in the whole handover, and it
 * writes **after** the unload:
 *
 *   delete_module (bounded retry) -> post = readback  [= the kernel's own cleanup value]
 *     -> post == want          : record "preexisting by external", do not write
 *     -> otherwise (want >= 0) : one write of want, one readback
 *
 * Writing before the unload is what made step-3's "restore" a false success: the
 * module's cleanup_module() then overwrote it with the value the module inherited
 * (necessarily 0 in the dfroot chain). Writing once, last, and only in the child is
 * what makes the restore the final privileged action with no swing back.
 */
static int hook_unload_child(struct hook_state *state) {
    int rc = -1, error = 0, attempts = 0, gone = 0;
    char document[MAPLESU_HOOK_JSON_MAX];
    const int want = state->want_final == '1' ? 1 : state->want_final == '0' ? 0 : -1;

    if (state->from_ghostlock) {
        rc = 0;
        log_line("maplesu-hook: unload skipped source=%s\n",
                 state->from_ghostlock == 2 ? "maplesu_93260" : "ghostlock");
    } else {
        for (attempts = 1; attempts <= MAPLESU_DELETE_ATTEMPTS; ++attempts) {
            rc = (int)syscall(MAPLESU_NR_DELETE_MODULE, MAPLESU_HOOK_MODULE_NAME, O_NONBLOCK);
            error = rc == 0 ? 0 : errno;
            if (rc == 0 || (error != EWOULDBLOCK && error != EBUSY)) break;
            usleep(MAPLESU_DELETE_RETRY_USEC);
        }
    }
    /* ENOENT means it is already gone, which is the state this step exists to reach. */
    gone = (rc == 0 || error == ENOENT) ? 1 : 0;
    log_line("maplesu-hook: unload name=%s rc=%d errno=%d attempts=%d\n",
             MAPLESU_HOOK_MODULE_NAME, rc, error, attempts);

    int post_unload = read_byte_fd(state->read_fd_b);
    int final = post_unload;
    const char *origin = "FAILED";
    int failures = 0;
    int wrote = 0;
    if (want < 0) {
        /* No target was established: nothing to verify, nothing to write. */
        failures = 1;
    } else if (post_unload == want) {
        /* Somebody else already put the target there - stage-1's teardown (which uses
         * the documented baseline) or a kernel rung. Record the competition instead of
         * writing a second time; the value is right, the write is not needed (R-D9). */
        log_line("maplesu-hook: restore preexisting=%d by=external\n", post_unload);
        origin = "BASELINE";
        final = post_unload;
    } else if (state->write_fd >= 0) {
        const char target = want != 0 ? '1' : '0';
        wrote = write(state->write_fd, &target, 1) == 1 ? 1 : 0;
        if (wrote) state->wrote = 1;
        final = read_byte_fd(state->read_fd_c);
        origin = "BASELINE";
        if (final != want) failures = 1;
    } else {
        /* No writable descriptor and the value is wrong: never claim a restore. */
        failures = 1;
    }
    if (!gone) failures = 1;
    log_line("maplesu-hook: readback post_unload=%d\n", post_unload);
    /* L4 (design §5.2): the final readback is still not the target. The child's record
     * and this line are the only place that conclusion can come from - the parent
     * already exited its restore rung, so the token is named here. */
    if (failures != 0) {
        state->token = "MA_HOOK_RESTORE_FAILED";
        log_line("maplesu-hook: restore target=%c origin=%s readback_final=%d wrote=%d "
                 "token=MA_HOOK_RESTORE_FAILED\n",
                 state->want_final != '\0' ? state->want_final : '?', origin, final,
                 wrote);
    } else {
        log_line("maplesu-hook: restore target=%c origin=%s readback_final=%d wrote=%d\n",
                 state->want_final != '\0' ? state->want_final : '?', origin, final,
                 wrote);
    }

    /* Best effort: catch the kernel's own `cleanup restored enforce=` /
     * `cleanup skipped (window inherited)` line. It is dumped *after* the write, so a
     * denied read under enforcing cannot delay the restore itself (R-D4). */
    ir_dump_kernel_log("hook-post-unload");

    const int count = snprintf(document, sizeof(document),
        "{\"schema\":\"maplesu.hook.unload.v1\",\"rc\":%d,\"errno\":%d,"
        "\"attempts\":%d,\"skipped\":%d,\"readbackPostUnload\":%d,\"readbackFinal\":%d,"
        "\"origin\":\"%s\",\"wrote\":%d,\"failures\":%d}\n",
        rc, error, attempts, state->from_ghostlock, post_unload, final, origin, wrote, failures);
    if (state->child_fd >= 0 && count > 0) {
        (void)write(state->child_fd, document,
                    (size_t)(count < (int)sizeof(document) ? count
                                                           : (int)sizeof(document) - 1));
        (void)fsync(state->child_fd);
    }
    return (gone && failures == 0) ? 0 : 1;
}

/* Bounded parent wait (design §5.1 step 12b, §6: <= 1500 ms). */
static int hook_wait_child(pid_t child) {
    for (int waited = 0; waited <= MAPLESU_UNLOAD_WAIT_MS;
         waited += MAPLESU_UNLOAD_POLL_USEC / 1000) {
        int status = 0;
        const pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return 1;   /* killed or signalled: not a verified unload */
        }
        if (got < 0 && errno != EINTR) return 1;
        usleep(MAPLESU_UNLOAD_POLL_USEC);
    }
    return -1;          /* still running: PENDING, never success */
}

static const char *hook_json_char(char value) {
    return value == '0' ? "\"0\"" : value == '1' ? "\"1\"" : "null";
}

/* A number, or JSON null when it was never observed. */
static const char *hook_json_int(int value, char *scratch, size_t capacity) {
    if (value < 0) return "null";
    snprintf(scratch, capacity, "%d", value);
    return scratch;
}

static const char *hook_verdict(const struct hook_state *state) {
    const int want = state->want_final == '1' ? 1 : state->want_final == '0' ? 0 : -1;
    /* B1: LOAD_FAILED means the kernel refused the optional L3 module - never a
     * handover failure, and hook_stage2() raises no token for it any more. INVALID is
     * different: the stager handed over bytes that are not a loadable module image at
     * all, which is a staging defect this verdict must still surface. */
    const int stage2_failed = !strcmp(state->stage2_state, "INVALID");
    const int daemon_failed = !strcmp(state->daemon_state, "INVALID") ||
                              !strcmp(state->daemon_state, "EXEC_FAILED");
    /* The pre-unload readback is pure observation now (the child is the only writer),
     * so it can never decide the verdict: a PENDING unload has not read anything yet. */
    if (want < 0) return "FAILED";
    if (state->readback_final >= 0 && state->readback_final != want) return "FAILED";
    if (stage2_failed) return "FAILED";
    /*
     * Step-4 D4-12: a daemon-slot failure is DEGRADED, not FAILED. The attestation
     * worker is the *second* proof (F2/F3); the restore evidence (F1) is this file, and
     * downgrading it to FAILED would make the device's recovery unreadable exactly when
     * the App needs to report it. DAEMON_READY is refused by the App's attestation
     * check instead, and the token (MA_HOOK_DAEMON_*) still names the cause.
     */
    if (daemon_failed) return "DEGRADED";
    if (strcmp(state->unload_state, "DONE") != 0 || state->enforce_before != 0)
        return "DEGRADED";
    return "OK";
}

/*
 * One write + fsync of the parent's own observations (design §5.4). The child's
 * record is separate on purpose: the parent cannot know the child's errno, and the
 * merge rules in the App would otherwise have to guess.
 */
static void hook_write_main_json(struct hook_state *state) {
    char document[MAPLESU_HOOK_JSON_MAX];
    char before[16], stage2_rc[16], stage2_errno[16], daemon_pid[16], readback[16];
    char name_field[96];
    /* Step-4 (D2/G-10): the attempt field stops being hard-coded null, and the argv it
     * records is the kernel's inherited observation (`request.entry`), never the
     * target - otherwise status.enforcingAtLease would silently become the goal. */
    char attempt_field[MAPLESU_HOOK_SMALL_MAX + 2];
    const char *verdict = hook_verdict(state);
    struct timespec now = {0, 0};
    (void)syscall(MAPLESU_NR_CLOCK_GETTIME, MAPLESU_CLOCK_REALTIME, &now);

    if (state->stage2_name[0] != '\0')
        snprintf(name_field, sizeof(name_field), "\"%s\"", state->stage2_name);
    else
        snprintf(name_field, sizeof(name_field), "null");
    if (state->attempt[0] != '\0')
        snprintf(attempt_field, sizeof(attempt_field), "\"%s\"", state->attempt);
    else
        snprintf(attempt_field, sizeof(attempt_field), "null");
    const char *token = state->token == NULL ? "null" : state->token;
    char token_field[64];
    if (state->token == NULL) snprintf(token_field, sizeof(token_field), "null");
    else snprintf(token_field, sizeof(token_field), "\"%s\"", token);
    /* L3 (ABI v2): suToken is present only while ARMED; suGate is always present, so
     * the App can tell "the module answered" from "there is no L3 module yet". */
    char su_fields[96];
    hook_l3_su_json(su_fields, sizeof(su_fields), state->su_gate, state->su_token_hex,
                    state->su_gate_reason);

    const int count = snprintf(document, sizeof(document),
        "{\"schema\":\"maplesu.hook.v1\",\"mode\":\"umh\",\"helper\":\"%s\","
        "\"helperPid\":%d,\"uid\":%d,\"domain\":\"%s\",\"bootId\":\"%s\","
        "\"attempt\":%s,\"entry\":{\"argv\":%s,\"origin\":\"%s\"},"
        "\"window\":{\"enforceBefore\":%s,\"open\":%d},"
        "\"stage2\":{\"state\":\"%s\",\"path\":\"%s\",\"rc\":%s,\"errno\":%s,"
        "\"name\":%s},"
        "\"daemon\":{\"state\":\"%s\",\"path\":\"%s\",\"pid\":%s},"
        "\"restore\":{\"wantFinal\":%s,\"target\":%s,\"wrote\":%d,"
        "\"readbackPreUnload\":%s,\"origin\":\"%s\",\"source\":\"%s\","
        "\"failures\":%d},"
        "\"unload\":{\"name\":\"%s\",\"state\":\"%s\"},"
        "\"klog\":{\"preRestore\":\"hook-pre-restore\","
        "\"postUnload\":\"hook-post-unload\"},"
        "\"verdict\":\"%s\",\"token\":%s,%s,\"ts\":%ld}\n",
        state->helper, (int)getpid(), (int)getuid(), state->domain,
        state->boot_id[0] != '\0' ? state->boot_id : "?",
        attempt_field,
        hook_json_char(state->entry_argv),
        state->from_ghostlock == 2 ? "maplesu_93260" : state->from_ghostlock ? "ghostlock" : "kernel-saved",
        hook_json_int(state->enforce_before, before, sizeof(before)),
        state->enforce_before == 0 ? 1 : 0,
        state->stage2_state, state->stage2_path,
        hook_json_int(state->stage2_rc, stage2_rc, sizeof(stage2_rc)),
        hook_json_int(state->stage2_rc < 0 ? -1 : state->stage2_errno,
                      stage2_errno, sizeof(stage2_errno)),
        name_field,
        state->daemon_state, state->daemon_path,
        hook_json_int(state->daemon_pid < 0 ? -1 : (int)state->daemon_pid,
                      daemon_pid, sizeof(daemon_pid)),
        hook_json_char(state->want_final), hook_json_char(state->want_final),
        state->wrote,
        hook_json_int(state->readback_pre, readback, sizeof(readback)),
        state->restore_origin, state->restore_source, state->failures,
        MAPLESU_HOOK_MODULE_NAME, state->unload_state,
        verdict, token_field, su_fields, (long)now.tv_sec);
    if (count >= (int)sizeof(document))
        log_line("maplesu-hook: evidence truncated size=%d limit=%d\n", count,
                 (int)sizeof(document));
    if (state->ev_fd >= 0 && count > 0) {
        (void)write(state->ev_fd, document,
                    (size_t)(count < (int)sizeof(document) ? count
                                                           : (int)sizeof(document) - 1));
        (void)fsync(state->ev_fd);
    }
    log_line("maplesu-hook: verdict=%s stage2=%s daemon=%s unload=%s token=%s "
             "failures=%d\n",
             verdict, state->stage2_state, state->daemon_state, state->unload_state,
             token, state->failures);

    /* Best-effort ring-buffer marker, the same sink shape the step-2 helper uses. The
     * provider log above is the durable channel; this one only helps a live observer. */
    if (state->kmsg_fd >= 0) {
        char marker[160];
        const int size = snprintf(marker, sizeof(marker),
                                  "<6>maplesu-hook: verdict=%s token=%s\n",
                                  verdict, token);
        if (size > 0)
            (void)write(state->kmsg_fd, marker,
                        (size_t)(size < (int)sizeof(marker) ? size
                                                            : (int)sizeof(marker) - 1));
    }
}

/*
 * The whole UMH mode. Order is design §5.1 steps 1-15; every comment names the step.
 */
static int umh_main(int argc, char **argv, int from_ghostlock,
                    struct hook_state *observed) {
    struct hook_request request;
    struct hook_state state;
    pid_t child;
    int child_code;

    memset(&state, 0, sizeof(state));
    state.from_ghostlock = from_ghostlock;
    state.dirfd = state.write_fd = state.read_fd_a = state.read_fd_b = -1;
    state.read_fd_c = state.read_fd_d = -1;
    state.ev_fd = state.child_fd = state.kmsg_fd = -1;
    state.enforce_before = -1;
    state.env_expected = -1;
    state.stage2_rc = -1;
    state.readback_pre = -1;
    state.readback_final = -1;
    state.daemon_pid = -1;
    state.unload_state = "PENDING";
    state.restore_origin = "FAILED";
    hook_set_state(state.restore_source, sizeof(state.restore_source), "unknown");
    hook_set_state(state.env_source, sizeof(state.env_source), "unknown");
    hook_set_state(state.stage2_state, sizeof(state.stage2_state), "NOT_EXERCISED");
    hook_set_state(state.daemon_state, sizeof(state.daemon_state), "NOT_EXERCISED");
    /* L3 (ABI v2/B1): UNAVAILABLE is the default and "no L3 module was staged" is the
     * default reason; hook_arm_l3() flips the gate only after rc == 0 *and* the module's
     * ARM acknowledgement was observed. */
    hook_set_state(state.su_gate, sizeof(state.su_gate), MAPLESU_L3_GATE_UNAVAILABLE);
    hook_set_state(state.su_gate_reason, sizeof(state.su_gate_reason),
                   MAPLESU_L3_REASON_NOT_EXERCISED);

    /* Step 1: argv only. A bad parse is recorded, never acted on. */
    const int parsed = hook_parse_argv(argc, argv, &request);
    if (parsed != 0) hook_fail(&state, "MA_HOOK_BAD_ARGV");
    if (request.helper != NULL && request.helper[0] != '\0')
        hook_set_state(state.helper, sizeof(state.helper), request.helper);

    /*
     * P1 (2026-10-31): the opt-in KernelSU route in UMH mode.
     *
     * main() dispatches here *before* the attempt document is opened, so stage-1's
     * use-ksu branch near the end of main() can never run when the module execs
     * `<CE>/bs --umh --entry-enforcing <0|1>`. The App still stages the daemon and
     * writes MAPLESU_USE_KSU for a KernelSU attempt; without this branch the marker is
     * dead in the only mode the module ever starts, and the daemon is never handed the
     * kernel (the observed P1 failure: `use-ksu` present, `ksuLines=[]`).
     *
     * This mode has no eighth attempt field to carry the path, so the App-owned staging
     * target is the constant (DirtyfragAttempt.stageKernelSuDaemon()).
     *
     * It must stay before the first hook descriptor, log line and ARM: the handoff
     * succeeds by soft-rebooting and fails through its own fail_with()/teardown, so no
     * part of the UMH sequence may have started when it returns. The marker is the only
     * new input: absent, the short-circuit is one access() and every line below is the
     * pre-P1 code. An invalid argv has no entry value to hand over and also falls
     * through, to the existing fail-closed MA_HOOK_BAD_ARGV path.
     */
    if (!from_ghostlock) {
        if (parsed == 0 && access(MAPLESU_USE_KSU, F_OK) == 0) {
            if (access(MAPLESU_CE_KSUD, X_OK) == 0) {
                const char ksu_entry[2] = {request.entry, '\0'};
                return ksu_handoff(MAPLESU_CE_KSUD, ksu_entry);
            }
            log_line("maplesu-dirtyfrag: use-ksu requested without a staged daemon\n");
        }
    }

    /* Step 2: the entry observation, and the evidence of who/where this is. */
    (void)hook_read_small(MAPLESU_CURRENT_DOMAIN_PATH, state.domain,
                          sizeof(state.domain));
    (void)hook_read_small(MAPLESU_BOOT_ID_PATH, state.boot_id, sizeof(state.boot_id));
    log_line("maplesu-hook: mode=umh pid=%d uid=%d euid=%d gid=%d egid=%d domain=%s\n",
             (int)getpid(), (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid(),
             state.domain[0] ? state.domain : "?");
    if (getuid() || geteuid() || getgid() || getegid()) {
        /* No privilege means no writable sink at all: log and leave. */
        hook_fail(&state, "MA_HOOK_NOT_PRIVILEGED");
        log_line("maplesu-hook: verdict=FAILED stage2=NOT_EXERCISED "
                 "daemon=NOT_EXERCISED unload=PENDING token=MA_HOOK_NOT_PRIVILEGED "
                 "failures=1\n");
        if (observed != NULL) *observed = state;
        return 70;
    }
    if (parsed != 0)
        log_line("maplesu-hook: argv rejected token=MA_HOOK_BAD_ARGV\n");

    /* Step 3: the attempt directory (device-protected), same checks as stage-1. */
    state.dirfd = open(MAPLESU_ATTEMPT_DIRECTORY,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (state.dirfd < 0) {
        hook_fail(&state, "MA_HOOK_DIR_REJECTED");
        log_line("maplesu-hook: attempt dir unavailable errno=%d\n", errno);
        if (observed != NULL) *observed = state;
        return 71;
    }
    struct stat home;
    if (fstat(state.dirfd, &home) || !S_ISDIR(home.st_mode) || home.st_uid < 10000 ||
        home.st_uid >= 100000 || (home.st_mode & 0077)) {
        close(state.dirfd);
        hook_fail(&state, "MA_HOOK_DIR_REJECTED");
        log_line("maplesu-hook: attempt dir rejected\n");
        if (observed != NULL) *observed = state;
        return 71;
    }
    /* The validated directory's owner is the only uid the daemon slot and the
     * attestation socket may belong to (step-4 MF-2). */
    state.dir_uid = (unsigned int)home.st_uid;
    state.dir_gid = (unsigned int)home.st_gid;

    /* Step 3.5 (step-4 D2): the pre-entry baseline the App wrote, read once through the
     * descriptor above. Nothing below re-opens or re-stats it. */
    hook_read_env(&state, &home);

    /* Step 4: what the kernel observed. This process always reads 0 here when the
     * window is open; the *target* now comes from the env, so the two facts stay
     * separate and `entry.argv` keeps carrying the inherited observation. */
    state.enforce_before = read_byte(MAPLESU_ENFORCE_PATH);
    log_line("maplesu-hook: window enforce_before=%d open=%d\n",
             state.enforce_before, state.enforce_before == 0 ? 1 : 0);
    if (state.enforce_before != 0) hook_fail(&state, "MA_HOOK_WINDOW_CLOSED");
    if (parsed == 0) state.entry_argv = request.entry;

    /* Step 4.5 (step-4 §2.1.3): the total decision function. It is the only writer of
     * want_final, restore_origin and restore_source. */
    hook_decide_target(&state, &request);

    /* Step 5: every descriptor this process will need, opened while it still can.
     * Four separate read descriptors, one per readback (see read_byte_fd). */
    state.write_fd = open(MAPLESU_ENFORCE_PATH, O_WRONLY | O_CLOEXEC);
    state.read_fd_a = open(MAPLESU_ENFORCE_PATH, O_RDONLY | O_CLOEXEC);
    state.read_fd_b = open(MAPLESU_ENFORCE_PATH, O_RDONLY | O_CLOEXEC);
    state.read_fd_c = open(MAPLESU_ENFORCE_PATH, O_RDONLY | O_CLOEXEC);
    state.read_fd_d = open(MAPLESU_ENFORCE_PATH, O_RDONLY | O_CLOEXEC);
    state.kmsg_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    state.ev_fd = open(MAPLESU_HOOK_EVIDENCE,
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    /* Step-4 D3: the App has to be able to read these. Same discipline as open_logs()
     * (0644 + fchmod, proven readable by R3's provider log); a failure is non-fatal but
     * must be diagnosable, so it is logged instead of guessed at from the App side. */
    if (state.ev_fd >= 0 && fchmod(state.ev_fd, 0644) != 0)
        log_line("maplesu-hook: evidence mode=widened failed errno=%d\n", errno);
    state.child_fd = open(MAPLESU_HOOK_UNLOAD_EVIDENCE,
                          O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (state.child_fd >= 0 && fchmod(state.child_fd, 0644) != 0)
        log_line("maplesu-hook: evidence mode=widened failed errno=%d\n", errno);

    /* Step 6: the reference's BLKROSET pass, non-fatal (the exploit's dirty pages are
     * still in flight even when the module ran). */
    if (!from_ghostlock) {
        const int ro = set_partitions_ro();
        log_line("maplesu-hook: partitions-ro rc=%d\n", ro);
    }

    /* Steps 7/8: the optional slots, still inside the window. */
    if (parsed == 0) {
        if (request.stage2 != NULL)
            hook_set_state(state.stage2_path, sizeof(state.stage2_path), request.stage2);
        else
            hook_sibling(request.helper, MAPLESU_STAGE2_NAME, state.stage2_path,
                         sizeof(state.stage2_path));
        if (request.daemon != NULL)
            hook_set_state(state.daemon_path, sizeof(state.daemon_path), request.daemon);
        else
            /* Step-4 D4-8: the daemon slot's default occupant is this same binary
             * (argv[0] = <CE>/bs) in its --attest mode, so nothing new is staged,
             * packaged or resolved. `--daemon <path>` still overrides for L3. */
            hook_set_state(state.daemon_path, sizeof(state.daemon_path), request.helper);
        hook_stage2(&state);
        hook_daemon(&state);
    } else {
        /* No argv, no paths: the slots stay NOT_EXERCISED and are reported as such. */
        hook_set_state(state.stage2_path, sizeof(state.stage2_path), "");
        hook_set_state(state.daemon_path, sizeof(state.daemon_path), "");
    }
    /* Reported for every outcome, including NOT_EXERCISED: the acceptance reads these
     * two lines to prove the placeholders were evaluated and left alone (§9 A5). */
    log_line("maplesu-hook: stage2 state=%s path=%s rc=%d errno=%d\n",
             state.stage2_state, state.stage2_path, state.stage2_rc,
             state.stage2_errno);
    log_line("maplesu-hook: daemon state=%s path=%s pid=%ld\n",
             state.daemon_state, state.daemon_path, state.daemon_pid);

    /* Step 9: the module's own init printks, captured from inside the window. */
    ir_dump_kernel_log("hook-pre-restore");

    /*
     * Step 10: [removed by step-4 D4-3] The parent no longer writes selinuxfs. The
     * unload child is the only writer, and it writes *after* delete_module() - writing
     * before it is what the module's cleanup_module() then overwrote, which is exactly
     * how step-3's restore became a false success. Nothing here touches write_fd.
     */

    /* Step 11: readback #1, through a pre-opened descriptor. It is pure observation
     * now ("the value before the child's write"), so it can never decide the verdict
     * and it can never be confused with the target. */
    state.readback_pre = read_byte_fd(state.read_fd_a);
    log_line("maplesu-hook: restore want=%c origin=%s source=%s readback_pre=%d\n",
             state.want_final == '\0' ? '?' : state.want_final,
             state.restore_origin, state.restore_source, state.readback_pre);

    /* Step 12: fork the unload child (R12 mitigation) and wait for it, bounded. The
     * child's window (4000 ms) is deliberately longer than this wait (1500 ms): R12's
     * mitigation *is* "the parent exits, init_module returns and releases module_mutex,
     * then the child's retry succeeds", so PENDING is an expected outcome, not a
     * failure. */
    if (from_ghostlock) {
        /* No init_module caller holds module_mutex. Finish restoration before
         * returning to Ghostlock's restore script; do not leave a racing child. */
        child_code = hook_unload_child(&state);
        state.unload_state = child_code == 0 ? "DONE" : "FAILED";
        state.readback_final = read_byte_fd(state.read_fd_d);
        if (child_code > 0) hook_fail(&state, "MA_HOOK_RESTORE_FAILED");
    } else {
        child = fork();
        if (child == 0) {
            /* Child: the last privileged action of this handover. Nothing below runs in
             * the parent's timeline, so _exit and never return. */
            _exit(hook_unload_child(&state));
        }
    }
    if (!from_ghostlock && child < 0) {
        hook_fail(&state, "MA_HOOK_UNLOAD_BUSY");
        state.unload_state = "FAILED";
    } else if (!from_ghostlock) {
        const int wanted = state.want_final == '1' ? 1 : state.want_final == '0' ? 0 : -1;
        child_code = hook_wait_child(child);
        state.unload_state = child_code == 0 ? "DONE"
                              : child_code < 0 ? "PENDING" : "FAILED";
        /* Step 12c: the parent's own last observation, through a descriptor opened
         * inside the window (no path lookup happens after step 10). A child that did
         * not settle (PENDING) is not judged here: no read, no token, readback_final
         * stays -1 and the App's childSettled() rule settles it later. */
        if (child_code == 0) {
            state.readback_final = read_byte_fd(state.read_fd_d);
            if (wanted < 0 || state.readback_final != wanted)
                hook_fail(&state, "MA_HOOK_RESTORE_FAILED");
        } else if (child_code > 0) {
            state.readback_final = read_byte_fd(state.read_fd_d);
            if (wanted >= 0 && state.readback_final != wanted)
                hook_fail(&state, "MA_HOOK_RESTORE_FAILED");
            hook_fail(&state, "MA_HOOK_UNLOAD_BUSY");
        } else {
            /* PENDING: the child is still inside its retry window. */
            state.readback_final = -1;
        }
    }

    /* Step 13/14: one write of the parent's own facts, then one verdict line. */
    hook_write_main_json(&state);
    if (observed != NULL) *observed = state;

    /* Step 15: exit code = "the parent *observed* the target and the unload is DONE".
     * The pre-unload readback is deliberately not part of it (it is taken before the
     * only write), so a PENDING handover exits 2 - the honest "the parent did not
     * verify" - while the child's record still proves the restore. */
    const int want = state.want_final == '1' ? 1 : state.want_final == '0' ? 0 : -1;
    return (want >= 0 && state.readback_final == want &&
            !strcmp(state.unload_state, "DONE")) ? 0 : 2;
}

/*
 * Bounded seven-line per-attempt input. The App publishes it with an exclusive
 * create in its device-protected private directory; the kernel helper executes
 * this bootstrap with UID 0. Nothing here reads preferences, enumerates
 * packages or loads an external SU library, and the only partition action is the
 * reference's BLKROSET pass, which only ever clears the writable flag:
 *
 *   1 consumer executable   2 lease endpoint      3 nonce (hex)
 *   4 Manager UID           5 boot_id             6 provider name
 *   7 pre-entry enforcing value recorded by the App
 *   8 optional staged KernelSU daemon (opt-in control route only)
 *
 * The pre-entry policy is restored by the consumer once the lease is
 * authenticated, so this process never widens or narrows the transient window.
 */
/* ============================================================================
 * T8 (design §6.3): one binary, a fourth mode - `bs --handover`.
 *
 * The App's Ghostlock route runs this in a root context inside the permissive
 * window. It hands over the requested backend and then returns:
 *  - ultra : verify the KMI-selected L3, then reuse the existing root context for
 *            the shared helper's load/ARM/daemon and synchronous restoration;
 *  - normal: switch to u:r:init:s0 and `ksud late-load --package-name <manager>`.
 * Ultra needs no bootstrap module, partition ioctl or asynchronous unload child.
 * The caller verifies the restored value before dispatching its consumer.
 *
 * Everything below the "host-testable block" markers is pure: argv parsing, the
 * App-written env document, sha256, the evidence JSON and the module verification.
 * The helper / ksud / evidence-write half stays out of that block.
 * ========================================================================== */
/* --- handover host-testable block begin --- */
#define HANDOVER_ENV_SCHEMA "maplesu.handover.env.v1"
#define HANDOVER_ROOT_MODULE_NAME "maplesu_root.ko"
#define HANDOVER_ENV_MAX 512
#define HANDOVER_ID_MAX 64
#define HANDOVER_HEX 64
#define HANDOVER_MODULE_MAX (64L * 1024L * 1024L)

struct handover_request {
    int valid;
    int pre;                 /* 1 = --phase pre, 0 = post */
    int ultra;               /* 1 = --target ultra */
    int entry_enforcing;     /* 0/1, -1 = absent */
    int soft_reboot;
    const char *helper;
    const char *attempt;
    const char *boot;
    const char *root_module; /* optional, absolute */
    const char *stage2;      /* optional, absolute */
    const char *ksud;        /* optional, absolute */
};

struct handover_env {
    int valid;
    char schema[48];
    char attempt[HANDOVER_ID_MAX];
    char boot[HANDOVER_ID_MAX];
    char target[8];
    char root_sha256[HANDOVER_HEX + 1];
    char stage2_sha256[HANDOVER_HEX + 1];
    char provider[24];
};

struct handover_file {
    int ok;
    int error;               /* 0 ok; 1 open; 2 not-regular; 3 size; 4 magic; 5 digest; 6 read */
    long size;
    unsigned char sha256[32];
};

struct handover_result {
    int failed;
    int degraded;
    const char *token;
    const char *detail;
    const char *target;      /* "ultra" / "normal" */
    const char *kind;        /* "l3-gate" / "ksu-lkm" */
    const char *gate;        /* "ARMED" / "UNAVAILABLE" / "" */
    const char *stage2;      /* "LOADED" / "ALREADY_RESIDENT" / "LOAD_FAILED" / "" */
    const char *ksu;         /* "LATE_LOAD_OK" / "FAILED" / "" */
    int enforcing_before;
    int enforcing_final;
    int restore_failures;
    const char *provider;
};

static int handover_valid_id(const char *value) {
    if (value == NULL) return 0;
    const size_t length = strlen(value);
    if (length < 4 || length >= HANDOVER_ID_MAX) return 0;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char ch = (unsigned char)value[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.') continue;
        return 0;
    }
    return 1;
}

static int handover_hex_digit(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int handover_valid_hex64(const char *value) {
    if (value == NULL || strlen(value) != HANDOVER_HEX) return 0;
    for (int i = 0; i < HANDOVER_HEX; ++i) {
        if (handover_hex_digit((unsigned char)value[i]) < 0) return 0;
    }
    return 1;
}

/* FIPS 180-4 SHA-256, compact on purpose: the only use is a digest comparison. */
static const unsigned handover_k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

static void handover_sha256_block(unsigned h[8], const unsigned char block[64]) {
    unsigned w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((unsigned)block[i * 4] << 24) | ((unsigned)block[i * 4 + 1] << 16) |
               ((unsigned)block[i * 4 + 2] << 8) | (unsigned)block[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        const unsigned s0 = (w[i-15]>>7|w[i-15]<<25) ^ (w[i-15]>>18|w[i-15]<<14) ^ (w[i-15]>>3);
        const unsigned s1 = (w[i-2]>>17|w[i-2]<<15) ^ (w[i-2]>>19|w[i-2]<<13) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    unsigned a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; ++i) {
        const unsigned s1 = (e>>6|e<<26) ^ (e>>11|e<<21) ^ (e>>25|e<<7);
        const unsigned ch = (e & f) ^ ((~e) & g);
        const unsigned t1 = hh + s1 + ch + handover_k[i] + w[i];
        const unsigned s0 = (a>>2|a<<30) ^ (a>>13|a<<19) ^ (a>>22|a<<10);
        const unsigned maj = (a & b) ^ (a & c) ^ (b & c);
        const unsigned t2 = s0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

static void handover_sha256(const unsigned char *data, size_t length, unsigned char out[32]) {
    unsigned h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                     0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    unsigned char block[64];
    size_t offset = 0;
    while (offset + 64 <= length) {
        handover_sha256_block(h, data + offset);
        offset += 64;
    }
    const size_t rest = length - offset;
    memset(block, 0, sizeof(block));
    if (rest > 0) memcpy(block, data + offset, rest);
    block[rest] = 0x80;
    if (rest >= 56) {
        handover_sha256_block(h, block);
        memset(block, 0, sizeof(block));
    }
    const unsigned long long bits = (unsigned long long)length * 8u;
    for (int i = 0; i < 8; ++i) block[63 - i] = (unsigned char)(bits >> (8 * i));
    handover_sha256_block(h, block);
    for (int i = 0; i < 8; ++i) {
        out[i*4] = (unsigned char)(h[i] >> 24); out[i*4+1] = (unsigned char)(h[i] >> 16);
        out[i*4+2] = (unsigned char)(h[i] >> 8); out[i*4+3] = (unsigned char)h[i];
    }
}

static void handover_sha256_hex(const unsigned char digest[32], char out[HANDOVER_HEX + 1]) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i*2] = digits[(digest[i] >> 4) & 0x0f];
        out[i*2+1] = digits[digest[i] & 0x0f];
    }
    out[HANDOVER_HEX] = '\0';
}

static int handover_hex_equals(const unsigned char digest[32], const char *hex) {
    if (!handover_valid_hex64(hex)) return 0;
    for (int i = 0; i < 32; ++i) {
        const int high = handover_hex_digit((unsigned char)hex[i * 2]);
        const int low = handover_hex_digit((unsigned char)hex[i * 2 + 1]);
        if (digest[i] != (unsigned char)((high << 4) | low)) return 0;
    }
    return 1;
}

/*
 * argv contract (design §6.3). Required: --handover --target --phase --attempt
 * --boot --entry-enforcing. Optional: --root-module --stage2 --ksud --soft-reboot.
 * Unknown or duplicated tokens are refused: an argument this mode does not
 * understand is a caller that expected different semantics.
 */
static int handover_parse_argv(int argc, char **argv, struct handover_request *request) {
    int seen_target = 0, seen_phase = 0, seen_attempt = 0, seen_boot = 0;
    int seen_entry = 0, seen_handover = 0, seen_module = 0, seen_stage2 = 0, seen_ksud = 0;

    memset(request, 0, sizeof(*request));
    request->entry_enforcing = -1;
    request->valid = 1;
    request->helper = (argc > 0 && argv != NULL && argv[0] != NULL) ? argv[0] : "";
    if (request->helper[0] != '/' || strrchr(request->helper, '/') == NULL) {
        request->valid = 0;
        return -1;
    }
    for (int i = 1; i < argc; ++i) {
        const char *token = argv[i];
        if (token == NULL) { request->valid = 0; return -1; }
        if (!strcmp(token, "--handover")) {
            if (seen_handover) { request->valid = 0; return -1; }
            seen_handover = 1;
            continue;
        }
        const char *value = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!strcmp(token, "--target")) {
            if (seen_target || value == NULL) { request->valid = 0; return -1; }
            if (!strcmp(value, "ultra")) request->ultra = 1;
            else if (!strcmp(value, "normal")) request->ultra = 0;
            else { request->valid = 0; return -1; }
            seen_target = 1; ++i;
        } else if (!strcmp(token, "--phase")) {
            if (seen_phase || value == NULL) { request->valid = 0; return -1; }
            if (!strcmp(value, "pre")) request->pre = 1;
            else if (!strcmp(value, "post")) request->pre = 0;
            else { request->valid = 0; return -1; }
            seen_phase = 1; ++i;
        } else if (!strcmp(token, "--attempt")) {
            if (seen_attempt || !handover_valid_id(value)) { request->valid = 0; return -1; }
            request->attempt = value; seen_attempt = 1; ++i;
        } else if (!strcmp(token, "--boot")) {
            if (seen_boot || !handover_valid_id(value)) { request->valid = 0; return -1; }
            request->boot = value; seen_boot = 1; ++i;
        } else if (!strcmp(token, "--entry-enforcing")) {
            if (seen_entry || value == NULL || (value[0] != '0' && value[0] != '1') ||
                value[1] != '\0') { request->valid = 0; return -1; }
            request->entry_enforcing = value[0] - '0';
            seen_entry = 1; ++i;
        } else if (!strcmp(token, "--root-module")) {
            if (seen_module || value == NULL || value[0] != '/') { request->valid = 0; return -1; }
            request->root_module = value; seen_module = 1; ++i;
        } else if (!strcmp(token, "--stage2")) {
            if (seen_stage2 || value == NULL || value[0] != '/') { request->valid = 0; return -1; }
            request->stage2 = value; seen_stage2 = 1; ++i;
        } else if (!strcmp(token, "--ksud")) {
            if (seen_ksud || value == NULL || value[0] != '/') { request->valid = 0; return -1; }
            request->ksud = value; seen_ksud = 1; ++i;
        } else if (!strcmp(token, "--soft-reboot")) {
            if (request->soft_reboot) { request->valid = 0; return -1; }
            request->soft_reboot = 1;
        } else {
            request->valid = 0;
            return -1;
        }
    }
    if (!seen_handover || !seen_target || !seen_phase || !seen_attempt || !seen_boot ||
        !seen_entry) {
        request->valid = 0;
        return -1;
    }
    /* post never loads anything; a post that also passes a load path is a lie. */
    if (!request->pre && (request->root_module != NULL || request->stage2 != NULL)) {
        request->valid = 0;
        return -1;
    }
    return 0;
}

/*
 * `maplesu-handover-env` (App-written, before the window):
 *   schema=maplesu.handover.env.v1 boot=<id> attempt=<id> target=<ultra|normal>
 *   root_sha256=<64 hex> [stage2_sha256=<64 hex>]
 * Fixed order is not required; unknown keys are refused so a future schema cannot
 * be silently misread by this build.
 */
static int handover_env_parse(const char *text, struct handover_env *env) {
    memset(env, 0, sizeof(*env));
    snprintf(env->provider, sizeof(env->provider), "ghostlock");
    if (text == NULL) return -1;
    char copy[HANDOVER_ENV_MAX];
    const size_t length = strlen(text);
    if (length == 0 || length >= sizeof(copy)) return -1;
    memcpy(copy, text, length + 1);
    int seen_schema = 0, seen_boot = 0, seen_attempt = 0, seen_target = 0, seen_root = 0;
    int seen_provider = 0;
    char *cursor = copy;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') ++cursor;
        if (*cursor == '\0') break;
        char *token = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\r' && *cursor != '\n') ++cursor;
        if (*cursor != '\0') { *cursor = '\0'; ++cursor; }
        char *equals = strchr(token, '=');
        if (equals == NULL) return -1;
        *equals = '\0';
        const char *key = token;
        const char *value = equals + 1;
        if (!strcmp(key, "schema")) {
            if (strcmp(value, HANDOVER_ENV_SCHEMA)) return -1;
            snprintf(env->schema, sizeof(env->schema), "%s", value);
            seen_schema = 1;
        } else if (!strcmp(key, "boot")) {
            if (!handover_valid_id(value)) return -1;
            snprintf(env->boot, sizeof(env->boot), "%s", value);
            seen_boot = 1;
        } else if (!strcmp(key, "attempt")) {
            if (!handover_valid_id(value)) return -1;
            snprintf(env->attempt, sizeof(env->attempt), "%s", value);
            seen_attempt = 1;
        } else if (!strcmp(key, "target")) {
            if (strcmp(value, "ultra") && strcmp(value, "normal")) return -1;
            snprintf(env->target, sizeof(env->target), "%s", value);
            seen_target = 1;
        } else if (!strcmp(key, "root_sha256")) {
            if (!handover_valid_hex64(value)) return -1;
            snprintf(env->root_sha256, sizeof(env->root_sha256), "%s", value);
            seen_root = 1;
        } else if (!strcmp(key, "provider")) {
            if (seen_provider++ || (strcmp(value, "ghostlock") && strcmp(value, "maplesu_93260"))) return -1;
            snprintf(env->provider, sizeof(env->provider), "%s", value);
        } else if (!strcmp(key, "stage2_sha256")) {
            if (!handover_valid_hex64(value)) return -1;
            snprintf(env->stage2_sha256, sizeof(env->stage2_sha256), "%s", value);
        } else {
            return -1;
        }
    }
    if (!seen_schema || !seen_boot || !seen_attempt || !seen_target || !seen_root) return -1;
    env->valid = 1;
    return 0;
}

/* Open one staged file O_NOFOLLOW, require a regular ELF and the expected digest. */
static int handover_verify_file(int dirfd, const char *name, const char *want_sha256,
                                struct handover_file *out) {
    memset(out, 0, sizeof(*out));
    const int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { out->error = 1; return -1; }
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        out->error = 2; close(fd); return -1;
    }
    if (info.st_size <= 0 || info.st_size > HANDOVER_MODULE_MAX) {
        out->error = 3; close(fd); return -1;
    }
    unsigned char magic[4];
    if (read(fd, magic, sizeof(magic)) != (ssize_t)sizeof(magic) ||
        magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        out->error = 4; close(fd); return -1;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) { out->error = 6; close(fd); return -1; }
    /* size-bounded hash, chunked: the module is small but the bound is explicit. */
    unsigned char *buffer = NULL;
    const size_t size = (size_t)info.st_size;
    buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) { out->error = 6; close(fd); return -1; }
    size_t done = 0;
    while (done < size) {
        const ssize_t got = read(fd, buffer + done, size - done);
        if (got <= 0) { break; }
        done += (size_t)got;
    }
    close(fd);
    if (done != size) { free(buffer); out->error = 6; return -1; }
    handover_sha256(buffer, size, out->sha256);
    free(buffer);
    out->size = (long)size;
    if (want_sha256 != NULL && want_sha256[0] != '\0' && !handover_hex_equals(out->sha256, want_sha256)) {
        out->error = 5;
        return -1;
    }
    out->ok = 1;
    return 0;
}

static int handover_json_escape(char *out, size_t capacity, const char *value) {
    size_t used = 0;
    if (value == NULL) value = "";
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; ++cursor) {
        char piece[8];
        size_t piece_length = 0;
        if (*cursor == '"' || *cursor == '\\') {
            piece[0] = '\\'; piece[1] = (char)*cursor; piece_length = 2;
        } else if (*cursor < 0x20) {
            snprintf(piece, sizeof(piece), "\\u%04x", *cursor);
            piece_length = strlen(piece);
        } else {
            piece[0] = (char)*cursor; piece_length = 1;
        }
        if (used + piece_length + 1 >= capacity) return -1;
        memcpy(out + used, piece, piece_length);
        used += piece_length;
    }
    out[used] = '\0';
    return (int)used;
}

/* One schema, one file (design §6.3). Fields the caller did not observe stay empty. */
static int handover_format_json(char *out, size_t capacity, const struct handover_result *result,
                                const char *attempt, const char *boot) {
    char escaped_attempt[HANDOVER_ID_MAX * 2];
    char escaped_boot[HANDOVER_ID_MAX * 2];
    char escaped_detail[256];
    char escaped_token[96];
    if (handover_json_escape(escaped_attempt, sizeof(escaped_attempt), attempt) < 0 ||
        handover_json_escape(escaped_boot, sizeof(escaped_boot), boot) < 0 ||
        handover_json_escape(escaped_detail, sizeof(escaped_detail), result->detail) < 0 ||
        handover_json_escape(escaped_token, sizeof(escaped_token), result->token) < 0) {
        return -1;
    }
    const char *verdict = result->failed ? "FAILED" : (result->degraded ? "DEGRADED" : "OK");
    const int written = snprintf(out, capacity,
        "{\"schema\":\"maplesu.handover.v1\",\"attempt\":\"%s\",\"bootId\":\"%s\","
        "\"target\":\"%s\",\"provider\":\"%s\","
        "\"entry\":{\"enforcingBefore\":%d,\"domain\":\"u:r:kernel:s0\"},"
        "\"carrier\":{\"kind\":\"%s\",\"gate\":\"%s\",\"stage2\":\"%s\",\"ksu\":\"%s\","
        "\"kernelsuModule\":\"kernelsu\"},"
        "\"restore\":{\"enforcingFinal\":%d,\"failures\":%d},"
        "\"verdict\":\"%s\",\"token\":\"%s\",\"detail\":\"%s\"}\n",
        escaped_attempt, escaped_boot, result->target ? result->target : "",
        result->provider ? result->provider : "ghostlock",
        result->enforcing_before,
        result->kind ? result->kind : "", result->gate ? result->gate : "",
        result->stage2 ? result->stage2 : "", result->ksu ? result->ksu : "",
        result->enforcing_final, result->restore_failures,
        verdict, escaped_token, escaped_detail);
    if (written < 0 || (size_t)written >= capacity) return -1;
    return written;
}
/* --- handover host-testable block end --- */

#define MAPLESU_HANDOVER_EVIDENCE MAPLESU_ATTEMPT_DIRECTORY "/maplesu-handover.json"
#define MAPLESU_HANDOVER_ENV_NAME "maplesu-handover-env"
#define MAPLESU_HANDOVER_EXIT_USAGE 64
#define MAPLESU_HANDOVER_EXIT_LOAD 65
#define MAPLESU_HANDOVER_EXIT_KSU 66
#define MAPLESU_HANDOVER_EXIT_EVIDENCE 68
#define MAPLESU_HANDOVER_WAIT_SECONDS 20

static int handover_mode_requested(int argc, char **argv) {
    if (argc <= 1 || argv == NULL) return 0;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != NULL && !strcmp(argv[i], "--handover")) return 1;
    }
    return 0;
}

static int handover_read_text(const char *path, char *buffer, size_t capacity) {
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    const ssize_t got = read(fd, buffer, capacity - 1);
    close(fd);
    if (got <= 0) return -1;
    buffer[got] = '\0';
    return (int)got;
}

static int handover_read_env(struct handover_env *env) {
    char text[HANDOVER_ENV_MAX];
    if (handover_read_text(MAPLESU_ATTEMPT_DIRECTORY "/" MAPLESU_HANDOVER_ENV_NAME,
                           text, sizeof(text)) <= 0) {
        return -1;
    }
    return handover_env_parse(text, env);
}

static int handover_file_contains(const char *path, const char *needle) {
    char text[4096];
    if (needle == NULL || needle[0] == '\0') return 0;
    if (handover_read_text(path, text, sizeof(text)) <= 0) return 0;
    return strstr(text, needle) != NULL;
}

static int handover_gate_armed(const char *attempt, const char *boot) {
    char text[4096];
    if (handover_read_text(MAPLESU_HOOK_DAEMON_DOC, text, sizeof(text)) <= 0) return 0;
    if (attempt != NULL && strstr(text, attempt) == NULL) return 0;
    if (boot != NULL && strstr(text, boot) == NULL) return 0;
    return strstr(text, "\"suGate\":\"ARMED\"") != NULL ||
           strstr(text, "\"state\":\"ARMED\"") != NULL;
}

static int handover_module_loaded(const char *name) {
    char text[8192];
    if (handover_read_text("/proc/modules", text, sizeof(text)) <= 0) return 0;
    const size_t length = strlen(name);
    for (char *line = text; line != NULL && *line != '\0';) {
        if (!strncmp(line, name, length) && line[length] == ' ') return 1;
        char *next = strchr(line, '\n');
        if (next == NULL) break;
        line = next + 1;
    }
    return 0;
}

static int handover_enforcing_now(void) {
    char text[8];
    if (handover_read_text("/sys/fs/selinux/enforce", text, sizeof(text)) <= 0) return -1;
    return text[0] == '1' ? 1 : (text[0] == '0' ? 0 : -1);
}

static int handover_write_evidence_fd(int fd, const struct handover_result *result,
                                      const char *attempt, const char *boot) {
    char json[2048];
    if (handover_format_json(json, sizeof(json), result, attempt, boot) < 0) return -1;
    const size_t length = strlen(json);
    size_t used = 0;
    while (used < length) {
        const ssize_t written = write(fd, json + used, length - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        used += (size_t)written;
    }
    return fsync(fd);
}

static int handover_write_evidence(const struct handover_result *result,
                                   const char *attempt, const char *boot) {
    const int fd = open(MAPLESU_HANDOVER_EVIDENCE,
                        O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    (void)fchmod(fd, 0644); /* C12: evidence is readable by the manager */
    const int rc = handover_write_evidence_fd(fd, result, attempt, boot);
    close(fd);
    return rc;
}

static int handover_wait_for_carrier(int ultra, const char *attempt, const char *boot) {
    for (int waited = 0; waited < MAPLESU_HANDOVER_WAIT_SECONDS; ++waited) {
        if (ultra ? handover_gate_armed(attempt, boot)
                  : (handover_module_loaded("kernelsu") &&
                     access(MAPLESU_KSUD_INSTALLED, X_OK) == 0)) {
            return 1;
        }
        sleep(1);
    }
    return 0;
}

/*
 * pre: load the requested backend inside the window, then return. Ultra uses the
 * shared helper synchronously, including its restore evidence; Normal retains
 * KSU late-load. Neither branch reboots or touches /dev/dfm*.
 * post: runs after the restore; it only records what happened and, on request,
 * closes the window with a soft reboot.
 */
static int handover_main(int argc, char **argv) {
    struct handover_request request;
    if (handover_parse_argv(argc, argv, &request) != 0 || !request.valid) {
        log_line("maplesu-dirtyfrag: handover: refused argv\n");
        return MAPLESU_HANDOVER_EXIT_USAGE;
    }
    log_line("maplesu-dirtyfrag: handover target=%s phase=%s attempt=%.8s\n",
             request.ultra ? "ultra" : "normal", request.pre ? "pre" : "post",
             request.attempt);
    struct handover_env env;
    if (handover_read_env(&env) != 0 || !env.valid ||
        strcmp(env.attempt, request.attempt) != 0 || strcmp(env.boot, request.boot) != 0 ||
        strcmp(env.target, request.ultra ? "ultra" : "normal") != 0) {
        struct handover_result refused;
        memset(&refused, 0, sizeof(refused));
        refused.failed = 1;
        refused.token = "MAPLESU_HANDOVER_EVIDENCE_UNREADABLE";
        refused.detail = "maplesu-handover-env missing, malformed or bound elsewhere";
        refused.target = request.ultra ? "ultra" : "normal";
        refused.kind = request.ultra ? "l3-gate" : "ksu-lkm";
        refused.gate = "";
        refused.stage2 = "";
        refused.ksu = "";
        refused.enforcing_before = request.entry_enforcing;
        refused.enforcing_final = handover_enforcing_now();
        handover_write_evidence(&refused, request.attempt, request.boot);
        return MAPLESU_HANDOVER_EXIT_EVIDENCE;
    }

    struct handover_result result;
    memset(&result, 0, sizeof(result));
    result.target = request.ultra ? "ultra" : "normal";
    result.kind = request.ultra ? "l3-gate" : "ksu-lkm";
    result.gate = "";
    result.stage2 = request.ultra ? "NOT_EXERCISED" : "";
    result.ksu = "";
    result.enforcing_before = request.entry_enforcing;
    result.enforcing_final = handover_enforcing_now();
    result.restore_failures = 0;
    result.provider = env.provider;

    if (!strcmp(env.provider, "maplesu_93260") ||
        (request.pre && request.ultra && !strcmp(env.provider, "ghostlock"))) {
        /* Normalize the independent exec worker, never Ghostlock's parked raw
         * victim. Reuse the 93260 entry contract before the strict UMH ID check. */
        log_line("maplesu-handover: source=%s identity before uid=%d euid=%d gid=%d egid=%d\n",
                 env.provider, getuid(), geteuid(), getgid(), getegid());
        const char *identity_step = NULL;
        /* An inherited real UID of zero can regain the effective UID before
         * group operations that require effective root capabilities. */
        if (geteuid() != 0 && setresuid(0, 0, 0)) identity_step = "setresuid";
        else if (setgroups(0, NULL)) identity_step = "setgroups";
        else if (setresgid(0, 0, 0)) identity_step = "setresgid";
        else if (setresuid(0, 0, 0)) identity_step = "setresuid";
        const int identity_errno = identity_step != NULL ? errno : 0;
        if (identity_step == NULL && (getuid() || geteuid() || getgid() || getegid()))
            identity_step = "readback";
        if (identity_step != NULL) {
            log_line("maplesu-handover: source=%s identity failed step=%s errno=%d "
                     "uid=%d euid=%d gid=%d egid=%d\n",
                     env.provider, identity_step, identity_errno,
                     getuid(), geteuid(), getgid(), getegid());
            result.failed = 1;
            result.token = !strcmp(env.provider, "maplesu_93260")
                ? "MAPLESU_93260_IDENTITY_INVALID" : "GHOSTLOCK_IDENTITY_INVALID";
            result.detail = "root credential normalization failed";
            handover_write_evidence(&result, request.attempt, request.boot);
            return MAPLESU_HANDOVER_EXIT_LOAD;
        }
        log_line("maplesu-handover: source=%s uid=%d euid=%d gid=%d egid=%d\n",
                 env.provider, getuid(), geteuid(), getgid(), getegid());
    }

    if (request.pre) {
        if (request.ultra) {
            const int directory = open(MAPLESU_ATTEMPT_DIRECTORY,
                                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct handover_file file;
            int verified = -1;
            if (directory >= 0 && handover_valid_hex64(env.stage2_sha256)) {
                verified = handover_verify_file(directory, MAPLESU_STAGE2_NAME,
                                                env.stage2_sha256, &file);
            }
            if (directory >= 0) close(directory);
            if (verified != 0) {
                result.failed = 1;
                result.token = "MAPLESU_HANDOVER_LOAD_FAILED";
                result.stage2 = "LOAD_FAILED";
                result.detail = "staged L3 module failed verification";
                handover_write_evidence(&result, request.attempt, request.boot);
                log_line("maplesu-dirtyfrag: handover: FAILED MAPLESU_HANDOVER_LOAD_FAILED\n");
                return MAPLESU_HANDOVER_EXIT_LOAD;
            }
            char entry[] = {request.entry_enforcing ? '1' : '0', '\0'};
            char *helper_argv[] = {(char *)request.helper, "--umh",
                                   "--entry-enforcing", entry, NULL};
            /* Match the shared helper: acquire every App-data descriptor before
             * it restores enforcing. Kernel-domain pathname lookups can be denied
             * afterwards, including the receipt and the daemon's gate document. */
            const int receipt = open(MAPLESU_HANDOVER_EVIDENCE,
                O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (receipt < 0 || fchmod(receipt, 0644) != 0) {
                if (receipt >= 0) close(receipt);
                log_line("maplesu-dirtyfrag: handover: receipt open failed errno=%d\n", errno);
                return MAPLESU_HANDOVER_EXIT_EVIDENCE;
            }
            struct hook_state observed;
            memset(&observed, 0, sizeof(observed));
            observed.readback_final = -1;
            const int rc = !strcmp(env.provider, "maplesu_93260")
                ? umh_main(4, helper_argv, 2, &observed)
                : umh_main(4, helper_argv, 1, &observed);
            result.enforcing_final = observed.readback_final;
            const int loaded = !strcmp(observed.stage2_state, "LOADED") ||
                               !strcmp(observed.stage2_state, "ALREADY_RESIDENT");
            result.stage2 = loaded ? "LOADED"
                : observed.stage2_state[0] ? observed.stage2_state : "NOT_EXERCISED";
            result.gate = observed.su_gate[0] ? observed.su_gate : "UNAVAILABLE";
            const int restore_failed = observed.unload_state != NULL &&
                                       !strcmp(observed.unload_state, "FAILED");
            result.restore_failures = restore_failed ? 1 : 0;
            int code = 0;
            if (rc != 0 || !loaded || observed.failures != 0) {
                result.failed = 1;
                result.token = observed.token != NULL ? observed.token
                    : restore_failed ? "MA_HOOK_RESTORE_FAILED" : "MAPLESU_HANDOVER_LOAD_FAILED";
                result.detail = !strcmp(result.stage2, "NOT_EXERCISED")
                    ? "shared helper stopped before L3 loading"
                    : restore_failed ? "shared helper did not finish restoration"
                    : !loaded ? "L3 module did not load" : "shared helper reported a failure";
                code = MAPLESU_HANDOVER_EXIT_LOAD;
            } else if (!strcmp(observed.su_gate, MAPLESU_L3_GATE_ARMED)) {
                result.gate = "ARMED";
            } else {
                result.gate = "UNAVAILABLE";
                result.degraded = 1;
            }
            const int published = handover_write_evidence_fd(receipt, &result,
                                                            request.attempt, request.boot);
            close(receipt);
            log_line("maplesu-dirtyfrag: handover: stage2=%s gate=%s restore=%d rc=%d receipt=%d\n",
                     result.stage2, result.gate, result.enforcing_final, rc, published);
            return published == 0 ? code : MAPLESU_HANDOVER_EXIT_EVIDENCE;
        } else {
            const char *ksud = request.ksud != NULL ? request.ksud : MAPLESU_KSUD_INSTALLED;
            if (!strcmp(env.provider, "maplesu_93260")) {
                struct handover_file daemon;
                if (handover_verify_file(-1, ksud, env.root_sha256, &daemon) != 0) {
                    result.failed = 1;
                    result.token = "MAPLESU_93260_KSUD_UNVERIFIED";
                    result.ksu = "FAILED";
                    result.detail = "staged ksud failed verification";
                    handover_write_evidence(&result, request.attempt, request.boot);
                    return MAPLESU_HANDOVER_EXIT_KSU;
                }
            }
            const int init = set_current_domain("u:r:init:s0");
            if (init != 0) log_line("maplesu-dirtyfrag: handover: init domain failed errno=%d\n", errno);
            char *late_load_argv[] = {(char *)ksud, "late-load", "--package-name",
                                      MAPLESU_KSU_PACKAGE, NULL};
            setenv("MAPLESU_JAILBREAK_SELINUX_HIDE",
                   read_byte(MAPLESU_ATTEMPT_DIRECTORY "/jailbreak-selinux-hide-request") == 0 ? "0" : "1", 1);
            const int load = run_ctx(NULL, late_load_argv);
            log_line("maplesu-dirtyfrag: handover: ksud late-load rc=%d\n", load);
            if (load != 0) {
                result.failed = 1;
                result.token = "MAPLESU_HANDOVER_KSU_LATE_LOAD_FAILED";
                result.ksu = "FAILED";
                result.detail = "ksud late-load failed";
                handover_write_evidence(&result, request.attempt, request.boot);
                return MAPLESU_HANDOVER_EXIT_KSU;
            }
            (void)wait_for_late_load(MAPLESU_LATE_LOAD_SECONDS);
            if (late_load_running() || access(MAPLESU_KSUD_INSTALLED, X_OK) != 0 ||
                !handover_module_loaded("kernelsu")) {
                result.failed = 1;
                result.token = "MAPLESU_HANDOVER_KSU_LATE_LOAD_FAILED";
                result.ksu = "FAILED";
                result.detail = "late-load did not produce a live kernelsu";
                handover_write_evidence(&result, request.attempt, request.boot);
                return MAPLESU_HANDOVER_EXIT_KSU;
            }
            result.ksu = "LATE_LOAD_OK";
            result.degraded = 0;
        }
        handover_write_evidence(&result, request.attempt, request.boot);
        return 0;
    }

    /* post: the restore already happened; only facts and the optional soft reboot. */
    if (request.ultra) {
        result.gate = handover_gate_armed(request.attempt, request.boot) ? "ARMED" : "UNAVAILABLE";
        result.stage2 = "LOADED";
        if (!strcmp(result.gate, "UNAVAILABLE")) result.degraded = 1;
    } else {
        result.ksu = (handover_module_loaded("kernelsu") &&
                      access(MAPLESU_KSUD_INSTALLED, X_OK) == 0) ? "LATE_LOAD_OK" : "FAILED";
        if (!strcmp(result.ksu, "FAILED")) {
            result.failed = 1;
            result.token = "MAPLESU_HANDOVER_KSU_LATE_LOAD_FAILED";
        }
    }
    result.enforcing_final = handover_enforcing_now();
    if (result.enforcing_final != 1) {
        result.degraded = 1;
        if (result.detail == NULL) result.detail = "restore did not end enforcing=1";
    }
    handover_write_evidence(&result, request.attempt, request.boot);
    if (request.soft_reboot) {
        if (request.ultra) {
            char *reboot_argv[] = {"/system/bin/sh", "-c",
                                   "setprop sys.powerctl reboot,soft_reboot", NULL};
            log_line("maplesu-dirtyfrag: handover: soft-reboot rc=%d\n", run_ctx(NULL, reboot_argv));
        } else {
            char *reboot_argv[] = {MAPLESU_KSUD_INSTALLED, "soft-reboot", NULL};
            log_line("maplesu-dirtyfrag: handover: ksud soft-reboot rc=%d\n",
                     run_ctx("u:r:ksu:s0", reboot_argv));
        }
    }
    return result.failed ? MAPLESU_HANDOVER_EXIT_KSU : 0;
}

int main(int argc, char **argv) {
    open_logs();
    /*
     * T8: `--handover` must be dispatched before UMH, because UMH's selector also
     * matches `--entry-enforcing` (both argv shapes carry it).
     */
    if (handover_mode_requested(argc, argv)) return handover_main(argc, argv);
    /*
     * Step-3 (design §2.4): one binary, two modes. UMH mode is decided before the
     * first marker and before any attempt-file access, so the module's helper can
     * never be mistaken for a second stage-1 and can never consume stage-1's
     * one-shot input. The exploit route passes no arguments, so this branch is dead
     * there (and argc == 1 keeps the body below byte-for-byte the same behaviour).
     */
    if (umh_mode_requested(argc, argv)) return umh_main(argc, argv, 0, NULL);
    /*
     * Step-4 (D4-8): the same binary's third mode. Its dispatch sits here for the same
     * reason UMH's does - before the first milestone and before any attempt-file
     * access - so the daemon slot's occupant can never be mistaken for stage-1.
     */
    if (attest_mode_requested(argc, argv)) return attest_main(argc, argv);
    /* Reference: "bootstrap: loading app preferences file". This chain's
     * privileged input is the one-shot attempt document read below; the
     * milestone name is the reference one so the stage table and the App see
     * the same sequence. */
    touch("/dev/dfm1");
    if (getuid() || geteuid() || getgid() || getegid()) {
        /* An unprivileged bootstrap cannot create /dev markers at all, so a
         * refusal here is logged rather than signalled. */
        log_line("maplesu-dirtyfrag: bootstrap not privileged uid=%d euid=%d\n",
                 (int)getuid(), (int)geteuid());
        return 70;
    }
    log_line("maplesu-dirtyfrag: bootstrap start pid=%d\n", (int)getpid());
    const int directory = open(MAPLESU_ATTEMPT_DIRECTORY, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) { log_line("maplesu-dirtyfrag: attempt dir unavailable errno=%d\n", errno); return fail_with("/dev/dfme0", 71, "attempt dir unavailable", NULL); }
    struct stat home;
    if (fstat(directory, &home) || !S_ISDIR(home.st_mode) || home.st_uid < 10000 ||
        home.st_uid >= 100000 || (home.st_mode & 0077)) { close(directory); return fail_with("/dev/dfme0", 71, "attempt dir rejected", NULL); }
    const int fd = openat(directory, MAPLESU_ATTEMPT_FILE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { log_line("maplesu-dirtyfrag: attempt file unavailable errno=%d\n", errno); close(directory); return fail_with("/dev/dfme0", 72, "attempt file unavailable", NULL); }
    struct stat status = {0};
    char document[2048];
    ssize_t count = -1;
    if (!fstat(fd, &status) && S_ISREG(status.st_mode) && status.st_uid == home.st_uid &&
        !(status.st_mode & 0077) && status.st_nlink == 1 && status.st_size > 0 &&
        status.st_size < (off_t)sizeof(document)) {
        do { count = read(fd, document, sizeof(document) - 1); } while (count < 0 && errno == EINTR);
    }
    close(fd);
    if (count != status.st_size || count <= 0 || memchr(document, '\0', (size_t)count)) {
        log_line("maplesu-dirtyfrag: attempt file rejected\n"); close(directory); return fail_with("/dev/dfme0", 72, "attempt file rejected", NULL);
    }
    document[count] = '\0';
    /*
     * Seven lease fields, plus an optional eighth field carrying a staged
     * KernelSU daemon (`ksud`). The App only stages it when KernelSU is
     * installed, and it is used only by the opt-in MAPLESU_USE_KSU control route;
     * the product path ignores it and runs the MapleSU consumer.
     */
    char *fields[8] = {0}, *next = document;
    int field_count = 0;
    for (int i = 0; i < 8; ++i) {
        fields[i] = next;
        char *end = strchr(next, '\n');
        if (!end) {
            if (i == 7) break;  /* the optional eighth field is absent */
            close(directory); return fail_with("/dev/dfme0", 73, "attempt field missing", NULL);
        }
        *end = '\0'; next = end + 1;
        if (!fields[i][0] || strchr(fields[i], '\r')) { close(directory); return fail_with("/dev/dfme0", 73, "attempt field invalid", NULL); }
        field_count = i + 1;
    }
    if (*next) { close(directory); return fail_with("/dev/dfme0", 73, "attempt document trailing", NULL); }
    if (field_count < 7) { close(directory); return fail_with("/dev/dfme0", 73, "attempt field missing", NULL); }
    log_line("maplesu-dirtyfrag: attempt consumer=%s\n", fields[0]);
    unsigned char nonce[32];
    int uid, enforce = -1;
    /* Field 7 is the pre-entry enforcing value, or "u" when the ordinary App
     * could not read selinuxfs. It is forwarded unchanged; only the consumer
     * interprets it, after the lease is authenticated. */
    const int enforce_known = strcmp(fields[6], "u") != 0;
    if (!maplesu_lease_endpoint(fields[1]) || !maplesu_lease_nonce(fields[2], nonce) ||
        !maplesu_lease_decimal(fields[3], 10000, &uid) || (uid_t)uid != home.st_uid ||
        !maplesu_lease_boot_id(fields[4]) || strcmp(fields[5], "dirtyfrag") ||
        (enforce_known && (!maplesu_lease_decimal(fields[6], 0, &enforce) || enforce > 1))) {
        close(directory);
        return fail_with("/dev/dfme0", 73, "attempt lease fields invalid", fields[6]);
    }
    log_line("maplesu-dirtyfrag: attempt admitted enforce=%s\n", fields[6]);
    /* Reference: "bootstrap: cloning zygote env" - the step that follows an
     * accepted input and binds the runtime state the handoff needs. */
    touch("/dev/dfm2");
    /*
     * Reference: "cloning zygote env". The kernel helper inherits only the
     * module's minimal environment; adopt the runtime variables from the live
     * zygote before anything is exec'd. Non-fatal, exactly as upstream: without
     * it the consumer falls back to the two ART variables the App publishes.
     */
    if (adopt_zygote_env() != 0) {
        log_line("maplesu-dirtyfrag: zygote env unavailable\n");
        touch("/dev/dfmw0");
    }
    /* Reference: "WARNING - clone zygote env failed". The other degraded case is
     * a pre-entry policy the App could not read ("u"): the consumer applies the
     * documented baseline and records the assumption, so this is reported and
     * the attempt continues. */
    if (!enforce_known) touch("/dev/dfmw0");
    char canonical[PATH_MAX];
    const char suffix[] = "/lib/arm64/libmaplesu_root_consumer.so";
    size_t length = strlen(fields[0]), suffix_length = sizeof(suffix) - 1;
    struct stat consumer;
    memset(&consumer, 0, sizeof(consumer));
    const int resolves = realpath(fields[0], canonical) != NULL;
    if (strncmp(fields[0], "/data/app/", 10) || length <= suffix_length ||
        strcmp(fields[0] + length - suffix_length, suffix) || !resolves ||
        strcmp(fields[0], canonical) || stat(canonical, &consumer) || !S_ISREG(consumer.st_mode) ||
        /* Package-managed native entries are owned by system (1000); a rewritten
         * copy would be owned by the App or another uid. */
        (consumer.st_uid != 0 && consumer.st_uid != 1000) || (consumer.st_mode & 0022) ||
        access(canonical, X_OK)) {
        log_line("maplesu-dirtyfrag: consumer rejected resolves=%d uid=%d mode=%o errno=%d\n",
                 resolves, (int)consumer.st_uid, (unsigned)consumer.st_mode, errno);
        close(directory);
        return fail_with("/dev/dfme0", 74, "consumer rejected", fields[6]);
    }
    /* Reference: "bootstrap: setting partitions ro". */
    touch("/dev/dfm3");
    /*
     * Reference parity: freeze the writable block devices that carry
     * system/vendor metadata before any userspace program runs, so the kernel
     * cannot flush the exploit's dirty pages to the block device and corrupt the
     * filesystem. Non-fatal, as upstream.
     */
    const int ro = set_partitions_ro();
    log_line("maplesu-dirtyfrag: bootstrap partitions-ro rc=%d\n", ro);
    if (ro != 0) touch("/dev/dfmw1");
    /* Reference: "WARNING - set partitions ro failed". The other non-fatal
     * observation is leftover state from an earlier attempt: the consumer
     * refuses a stale disarm proof, so a survivor is reported where it is seen
     * instead of only at the teardown handshake. */
    if (access(MAPLESU_DISARM, F_OK) == 0 ||
        access(MAPLESU_ATTEMPT_DIRECTORY "/" MAPLESU_TEARDOWN, F_OK) == 0) {
        log_line("maplesu-dirtyfrag: previous attempt left state behind\n");
        touch("/dev/dfmw1");
    }
    /* Reference: "bootstrap: disabling ksu modules" - the step after which the
     * attempt can no longer re-fire on its own. Here it is consuming the
     * one-shot attempt document; as upstream, the step marker is published
     * before the action, so a failure shows dfm4 and dfme1 together. */
    touch("/dev/dfm4");
    if (unlinkat(directory, MAPLESU_ATTEMPT_FILE, 0)) { close(directory); return fail_with("/dev/dfme1", 75, "attempt file unlink failed", fields[6]); }
    close(directory);
    /*
     * MapleSU's own root stack is the product path: the consumer below runs the
     * lease handshake and the executor. The KernelSU handoff is an explicit,
     * opt-in control experiment only (it was used to prove the exploit itself is
     * sound on this device); it never runs unless the marker file exists, and it
     * needs the optional eighth field. Without that field the product consumer
     * route below is the fallback. This branch is checked first: the marker is
     * the more specific request, so a leftover no-consumer marker cannot quietly
     * turn the KernelSU experiment into the old diagnostic.
     */
    if (access(MAPLESU_USE_KSU, F_OK) == 0) {
        if (field_count == 8 && fields[7] != NULL && fields[7][0] == '/')
            return ksu_handoff(fields[7], fields[6]);
        log_line("maplesu-dirtyfrag: use-ksu requested without a staged daemon\n");
    }
    /*
     * In-kernel root route (manual 4.2 / W2). The App marks this route only when it
     * has an exact spec for the running release, and stages that spec plus our
     * module beside this bootstrap. It never returns on success: it restores the
     * entry policy and soft reboots into the patched kernel.
     */
    if (access(MAPLESU_USE_IR, F_OK) == 0) {
        log_line("maplesu-dirtyfrag: ir route selected\n");
        return install_ir(fields[6]);
    }
    /*
     * Diagnostic mode (2026-10-28): with this marker present the bootstrap skips the
     * MapleSU consumer and does what the reference implementation does - restore the
     * entry policy and soft reboot. It isolates whether the consumer, which the
     * reference does not have, is what destabilises this kernel.
     */
    if (access(MAPLESU_ATTEMPT_DIRECTORY "/no-consumer", F_OK) == 0) {
        const char target = entry_enforcing(fields[6]);
        const int wrote = write_byte("/sys/fs/selinux/enforce", target);
        const int readback = read_byte("/sys/fs/selinux/enforce");
        log_line("maplesu-dirtyfrag: diagnostic no-consumer wrote=%d readback=%d\n", wrote, readback);
        (void)set_exec_domain("u:r:shell:s0");
        touch("/dev/dfm5");
        touch("/dev/dfm6");
        char *reboot_argv[] = {"/system/bin/sh", "-c",
            "setprop sys.powerctl reboot,soft_reboot", NULL};
        execv(reboot_argv[0], reboot_argv);
        const int saved = errno;
        (void)unlink("/dev/dfm6");
        log_line("maplesu-dirtyfrag: diagnostic soft reboot exec failed errno=%d\n", saved);
        return fail_with("/dev/dfme2", 78, "diagnostic soft reboot exec failed", fields[6]);
    }
    /*
     * Product route. Move out of the kernel domain before exec, exactly as the
     * reference implementation's run_ctx() does; without it the consumer - and
     * the ART runtime it starts - keep the domain the module dispatched from.
     */
    const int domain = set_exec_domain("u:r:shell:s0");
    if (domain != 0)
        log_line("maplesu-dirtyfrag: bootstrap exec domain shell failed errno=%d\n", errno);
    log_line("maplesu-dirtyfrag: bootstrap dispatching consumer\n");
    /* Named apart from main()'s argv, which step-3 added: the UMH mode needs the real
     * argv and the exploit route must keep passing exactly these seven fields. */
    char *consumer_argv[] = {fields[0], fields[1], fields[2], fields[3], fields[4],
                             fields[5], fields[6], NULL};
    /*
     * Reference milestones for this hop: "bootstrap: starting SU daemon" (dfm5)
     * and "ksud start: SUCCESS" (dfm6) once the dispatched program returned 0.
     * Here the dispatched program is the consumer and execv replaces this image,
     * so there is no return value left to observe: dfm6 is published as the
     * handoff itself, and the consumer's authenticated lease - not the marker -
     * is what the App treats as readiness. If execv returns, dfm6 is withdrawn
     * before dfme2 is published, so a failed handoff is never seen as success.
     */
    touch("/dev/dfm5");
    touch("/dev/dfm6");
    execv(consumer_argv[0], consumer_argv);
    const int exec_error = errno;
    (void)unlink("/dev/dfm6");
    log_line("maplesu-dirtyfrag: consumer exec failed errno=%d\n", exec_error);
    return fail_with("/dev/dfme2", 77, "consumer exec failed", fields[6]);
}
