"""Exercise the production GhostLock handover with kernel operations replaced.

The first harness traps a redundant root-module load; the second executes the
production helper and restore body with OS/kernel operations replaced. These
verify dispatch, restoration order and failure propagation, not a device's kernel
backend.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_handover_mode import HOST_CC, HARNESS_PREAMBLE, SOURCE, definition, read_block


IDENTITY_BOUNDARIES = r'''
static int uid, euid, gid, egid;
static int fixture_setgroups(size_t count, const void *groups) {
    (void)count; (void)groups;
    puts("IDENTITY_NORMALIZED");
    if (euid != 0 || !strcmp(scenario, "identity-failed")) { errno = EPERM; return -1; }
    return 0;
}
static int fixture_setresgid(int real, int effective, int saved) {
    (void)saved;
    puts("SETRESGID");
    if (!strcmp(scenario, "gid-failed")) { errno = EPERM; return -1; }
    if (strcmp(scenario, "identity-readback-failed")) { gid = real; egid = effective; }
    return 0;
}
static int fixture_setresuid(int real, int effective, int saved) {
    (void)saved;
    puts("SETRESUID");
    if (!strcmp(scenario, "uid-failed")) { errno = EPERM; return -1; }
    uid = real; euid = effective;
    return 0;
}
#define setgroups fixture_setgroups
#define setresgid fixture_setresgid
#define setresuid fixture_setresuid
#define getuid() uid
#define geteuid() euid
#define getgid() gid
#define getegid() egid
'''

HARNESS = r'''
#include <stdarg.h>
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#define MAPLESU_ATTEMPT_DIRECTORY "."
#define MAPLESU_STAGE2_NAME "maplesu_stage2.ko"
#define MAPLESU_HANDOVER_ROOT_MODULE "./maplesu_root.ko"
#define MAPLESU_KSUD_INSTALLED "/system/bin/true"
#define MAPLESU_KSU_PACKAGE "dev.maplesu.manager"
#define MAPLESU_NR_FINIT_MODULE 273
#define MAPLESU_HANDOVER_EXIT_USAGE 64
#define MAPLESU_HANDOVER_EXIT_LOAD 65
#define MAPLESU_HANDOVER_EXIT_KSU 66
#define MAPLESU_HANDOVER_EXIT_EVIDENCE 68
#define MAPLESU_LATE_LOAD_SECONDS 1
#define MAPLESU_HANDOVER_EVIDENCE "./maplesu-handover.json"
#define MAPLESU_L3_GATE_ARMED "ARMED"
struct hook_state {
    int readback_final, failures;
    const char *token, *unload_state;
    char stage2_state[32], su_gate[32];
};
static const char *scenario;
static char env_text[HANDOVER_ENV_MAX];
static int helper_ran, restored;
''' + IDENTITY_BOUNDARIES + r'''
static void log_line(const char *format, ...) {
    va_list args; va_start(args, format); vprintf(format, args); va_end(args);
}
static int handover_read_env(struct handover_env *env) {
    return handover_env_parse(env_text, env);
}
static int handover_enforcing_now(void) { return restored ? 1 : 0; }
static int handover_gate_armed(const char *attempt, const char *boot) {
    (void)attempt; (void)boot;
    return helper_ran && strcmp(scenario, "no-gate");
}
static int handover_wait_for_carrier(int ultra, const char *attempt, const char *boot) {
    return ultra ? handover_gate_armed(attempt, boot) : 1;
}
static int handover_module_loaded(const char *name) {
    if (!strcmp(name, "kernelsu")) return 1;
    return helper_ran && strcmp(scenario, "load-failed");
}
static int handover_write_evidence(const struct handover_result *result,
                                   const char *attempt, const char *boot) {
    char json[2048];
    if (handover_format_json(json, sizeof(json), result, attempt, boot) < 0) return -1;
    printf("RECEIPT=%s", json);
    return 0;
}
static int handover_write_evidence_fd(int fd, const struct handover_result *result,
                                      const char *attempt, const char *boot) {
    (void)fd; return handover_write_evidence(result, attempt, boot);
}
static int set_current_domain(const char *domain) { printf("DOMAIN=%s\n", domain); return 0; }
static int run_ctx(const char *domain, char **args) {
    (void)domain; printf("COMMAND=%s\n", args[1]); restored = 1; return 0;
}
static int read_byte(const char *path) { (void)path; return -1; }
static int fixture_setenv(const char *key, const char *value, int overwrite) {
    (void)key; (void)overwrite; printf("SELINUX_HIDE_REQUEST=%s\n", value); return 0;
}
#define setenv fixture_setenv
static int wait_for_late_load(int seconds) { (void)seconds; return 0; }
static int late_load_running(void) { return 0; }
static int fixture_access(const char *path, int mode) {
    return !strcmp(path, MAPLESU_KSUD_INSTALLED) ? 0 : access(path, mode);
}
#define access fixture_access
static long fixture_syscall(long nr, ...) {
    (void)nr; puts("UNEXPECTED_ROOT_MODULE_LOAD"); errno = ENOEXEC; return -1;
}
#define syscall fixture_syscall
static int fixture_open(const char *path, int flags, ...) {
    if (!strcmp(path, MAPLESU_ATTEMPT_DIRECTORY)) return 100;
    if (!strcmp(path, MAPLESU_HANDOVER_EVIDENCE)) return 101;
    return open(path, flags);
}
#define open fixture_open
#define fchmod(fd, mode) ((void)(fd), (void)(mode), 0)
static int umh_main(int argc, char **argv, int from_ghostlock, struct hook_state *observed) {
    if (argc != 4 || strcmp(argv[1], "--umh") ||
        strcmp(argv[2], "--entry-enforcing") || strcmp(argv[3], "1") ||
        !from_ghostlock) return 64;
    printf("SHARED_HELPER=%s entry=1\n", from_ghostlock == 2 ? "maplesu_93260" : "ghostlock");
    helper_ran = 1;
    strcpy(observed->stage2_state, "NOT_EXERCISED");
    strcpy(observed->su_gate, "UNAVAILABLE");
    observed->unload_state = "PENDING";
    if (getuid() || geteuid() || getgid() || getegid() ||
        !strcmp(scenario, "helper-not-privileged") || !strcmp(scenario, "helper-dir-rejected")) {
        observed->token = !strcmp(scenario, "helper-dir-rejected")
            ? "MA_HOOK_DIR_REJECTED" : "MA_HOOK_NOT_PRIVILEGED";
        observed->failures = 1;
        return !strcmp(scenario, "helper-dir-rejected") ? 71 : 70;
    }
    observed->unload_state = !strcmp(scenario, "restore-failed") ? "FAILED" : "DONE";
    if (!strcmp(scenario, "restore-failed")) {
        observed->token = "MA_HOOK_RESTORE_FAILED"; observed->failures = 1;
    } else if (!strcmp(scenario, "load-failed")) {
        observed->token = "MA_HOOK_STAGE2_INVALID"; observed->failures = 1;
    } else if (!strcmp(scenario, "daemon-failed")) {
        observed->token = "MA_HOOK_DAEMON_EXEC_FAILED"; observed->failures = 1;
    }
    strcpy(observed->stage2_state, !strcmp(scenario, "load-failed") ? "LOAD_FAILED" : "LOADED");
    strcpy(observed->su_gate, !strcmp(scenario, "no-gate") ? "UNAVAILABLE" : "ARMED");
    observed->readback_final = !strcmp(scenario, "restore-failed") ? 0 : 1;
    if (!strcmp(scenario, "restore-failed")) return 2;
    restored = 1;
    return 0;
}
'''


MAIN = r'''
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    scenario = argv[2];
    if (!strcmp(scenario, "root-euid")) euid = 10367;
    if (!strcmp(scenario, "root-gid") || !strcmp(scenario, "identity-readback-failed")) gid = 10367;
    if (!strcmp(scenario, "root-egid")) egid = 10367;
    size_t count = fread(env_text, 1, sizeof(env_text) - 1, stdin);
    env_text[count] = '\0';
    char *args[] = {"/fixture/bs", "--handover", "--target", argv[1],
        "--phase", "pre", "--attempt", "attempt-1", "--boot", "boot-1",
        "--entry-enforcing", "1", "--ksud", "/fixture/ksud", NULL};
    const int rc = handover_main(14, args);
    printf("EXIT=%d\n", rc);
    return 0;
}
'''

# Execute the production helper and restore body too, replacing only OS and
# kernel boundaries. This catches a helper stub hiding a leftover unload/fork.
HELPER_PREAMBLE = r'''
#include <stdarg.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#define MAPLESU_HOOK_SMALL_MAX 192
#define MAPLESU_L3_TOKEN_DIGITS 16
#define MAPLESU_HOOK_JSON_MAX 4096
#define MAPLESU_L3_GATE_UNAVAILABLE "UNAVAILABLE"
#define MAPLESU_L3_REASON_NOT_EXERCISED "not_exercised"
#define MAPLESU_USE_KSU "use-ksu"
#define MAPLESU_CE_KSUD "ksud"
#define MAPLESU_CURRENT_DOMAIN_PATH "domain"
#define MAPLESU_BOOT_ID_PATH "boot"
#define MAPLESU_ATTEMPT_DIRECTORY "attempt"
#define MAPLESU_ENFORCE_PATH "enforce"
#define MAPLESU_HOOK_EVIDENCE "evidence"
#define MAPLESU_HOOK_UNLOAD_EVIDENCE "child-evidence"
#define MAPLESU_STAGE2_NAME "maplesu_stage2.ko"
#define MAPLESU_HOOK_MODULE_NAME "maplesu_root"
#define MAPLESU_DELETE_ATTEMPTS 3
#define MAPLESU_DELETE_RETRY_USEC 1
#define MAPLESU_NR_DELETE_MODULE 106
'''

HELPER_FIXTURE = r'''
static const char *scenario;
static int enforcing, writes, forks, deletes, partitions;
static struct hook_state *live_state;
static char child_document[MAPLESU_HOOK_JSON_MAX];
static int hook_unload_child(struct hook_state *state);
static void log_line(const char *format, ...) {
    va_list args; va_start(args, format); vprintf(format, args); va_end(args);
}
static void hook_set_state(char *out, size_t size, const char *value) {
    snprintf(out, size, "%s", value);
}
static void hook_fail(struct hook_state *state, const char *token) {
    state->failures++; state->token = token;
}
static int hook_parse_argv(int argc, char **argv, struct hook_request *request) {
    memset(request, 0, sizeof(*request));
    request->helper = argv[0]; request->entry = argv[3][0];
    return argc == 4 ? 0 : -1;
}
static int fixture_access(const char *path, int mode) {
    (void)path; (void)mode; return strcmp(scenario, "stale-ksu") ? -1 : 0;
}
#define access fixture_access
static int ksu_handoff(const char *path, const char *entry) {
    (void)path; (void)entry; puts("KSU_HANDOFF"); return 77;
}
static int hook_read_small(const char *path, char *out, size_t size) {
    snprintf(out, size, "%s", path); return 0;
}
#define getuid() 0
#define geteuid() (!strcmp(scenario, "root-euid") ? 10367 : 0)
#define getgid() (!strcmp(scenario, "root-gid") ? 10367 : 0)
#define getegid() (!strcmp(scenario, "root-egid") ? 10367 : 0)
static int fixture_open(const char *path, int flags, ...) {
    if (!strcmp(path, MAPLESU_ATTEMPT_DIRECTORY) && !strcmp(scenario, "dir-open-failed")) return -1;
    if (!strcmp(path, MAPLESU_ENFORCE_PATH))
        return (flags & O_ACCMODE) == O_WRONLY ? 10 : 11;
    return !strcmp(path, MAPLESU_HOOK_UNLOAD_EVIDENCE) ? 40 : 30;
}
#define open fixture_open
static int fixture_fstat(int fd, struct stat *info) {
    (void)fd; memset(info, 0, sizeof(*info));
    info->st_mode = S_IFDIR | (!strcmp(scenario, "dir-invalid") ? 0777 : 0700);
    info->st_uid = 10001; return 0;
}
#define fstat fixture_fstat
#define close(fd) ((void)(fd), 0)
#define fchmod(fd, mode) ((void)(fd), (void)(mode), 0)
#define fsync(fd) ((void)(fd), 0)
static void hook_read_env(struct hook_state *state, const struct stat *home) {
    (void)home; state->env_ok = strcmp(scenario, "invalid-env") != 0;
    state->env_expected = 1; strcpy(state->env_source, "baseline");
}
static int read_byte(const char *path) { (void)path; return enforcing; }
static int read_byte_fd(int fd) { (void)fd; return enforcing; }
static int set_partitions_ro(void) { partitions++; return 0; }
static void hook_sibling(const char *helper, const char *name, char *out, size_t size) {
    (void)helper; snprintf(out, size, "/fixture/%s", name);
}
static void hook_stage2(struct hook_state *state) {
    live_state = state; puts("STAGE2");
    if (!strcmp(scenario, "preexisting")) enforcing = 1;
}
static void hook_daemon(struct hook_state *state) { (void)state; puts("DAEMON"); }
static void ir_dump_kernel_log(const char *tag) { (void)tag; }
static ssize_t fixture_write(int fd, const void *data, size_t size) {
    if (fd == 10) {
        writes++; puts("RESTORE_WRITE");
        if (!strcmp(scenario, "restore-failed")) return -1;
        enforcing = *(const char *)data == '1';
    } else if (fd == 40) snprintf(child_document, sizeof(child_document), "%.*s", (int)size, (const char *)data);
    return (ssize_t)size;
}
#define write fixture_write
static long fixture_syscall(long nr, ...) { (void)nr; deletes++; return 0; }
#define syscall fixture_syscall
static pid_t fixture_fork(void) { forks++; return 42; }
#define fork fixture_fork
static int hook_wait_child(pid_t child) {
    (void)child;
    return !strcmp(scenario, "pending") ? -1 : hook_unload_child(live_state);
}
static void hook_write_main_json(struct hook_state *state) {
    printf("MAIN failures=%d token=%s unload=%s final=%d\n", state->failures,
           state->token ? state->token : "", state->unload_state, state->readback_final);
    printf("CHILD=%s", child_document);
}
'''

HELPER_MAIN = r'''
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    scenario = argv[2];
    char *args[] = {"/fixture/bs", "--umh", "--entry-enforcing", "1", NULL};
    struct hook_state observed;
    memset(&observed, 0, sizeof(observed));
    int rc = umh_main(4, args, atoi(argv[1]), &observed);
    printf("OBSERVED stage2=%s token=%s failures=%d final=%d\n",
           observed.stage2_state, observed.token ? observed.token : "", observed.failures,
           observed.readback_final);
    printf("RESULT rc=%d enforce=%d writes=%d forks=%d deletes=%d partitions=%d\n",
           rc, enforcing, writes, forks, deletes, partitions);
    return 0;
}
'''


@unittest.skipUnless(HOST_CC is not None, "no host C compiler")
class GhostlockUltraHandoverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ghostlock-ultra-")
        cls.directory = Path(cls.temp.name)
        source = cls.directory / "fixture.c"
        source.write_text(HARNESS_PREAMBLE + read_block() + HARNESS +
                          definition(SOURCE.read_text(encoding="utf-8"), "handover_main") + MAIN,
                          encoding="utf-8")
        cls.exe = cls.directory / ("fixture.exe" if os.name == "nt" else "fixture")
        build = subprocess.run([str(HOST_CC), "-std=c11", "-O0", str(source), "-o", str(cls.exe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise AssertionError(build.stderr)
        cls.payload = b"\x7fELF" + b"fixture-L3" * 8
        cls.digest = hashlib.sha256(cls.payload).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_handover(self, scenario="ok", target="ultra", digest=None, missing=False,
                     include_stage2_digest=True, provider=None, root_digest=None):
        with tempfile.TemporaryDirectory(dir=self.directory) as temp:
            work = Path(temp)
            (work / "maplesu_root.ko").write_bytes(self.payload)
            (work / "ksud").write_bytes(self.payload)
            if not missing:
                (work / "maplesu_stage2.ko").write_bytes(self.payload)
            # Keep the legacy digest too, so the old route reaches its unsafe
            # root-module syscall instead of failing solely on the new env field.
            env = ("schema=maplesu.handover.env.v1 boot=boot-1 attempt=attempt-1 "
                   f"target={target} root_sha256={root_digest or self.digest}")
            if include_stage2_digest:
                env += f" stage2_sha256={digest or self.digest}"
            if provider:
                env += f" provider={provider}"
            env += "\n"
            result = subprocess.run([str(self.exe), target, scenario], input=env,
                                    text=True, capture_output=True, cwd=work)
            self.assertEqual(0, result.returncode, result.stderr)
            text = result.stdout
            receipt = next(line[len("RECEIPT="):] for line in text.splitlines()
                           if line.startswith("RECEIPT="))
            return text, json.loads(receipt)

    def test_ultra_reuses_root_and_finishes_restore_synchronously(self):
        text, receipt = self.run_handover()
        self.assertNotIn("UNEXPECTED_ROOT_MODULE_LOAD", text)
        self.assertIn("SHARED_HELPER=ghostlock entry=1", text)
        self.assertEqual("OK", receipt["verdict"])
        self.assertEqual("ARMED", receipt["carrier"]["gate"])
        self.assertEqual(1, receipt["restore"]["enforcingFinal"])
        self.assertIn("EXIT=0", text)

    def test_ghostlock_ultra_normalizes_partial_root_identity_before_the_helper(self):
        for scenario in ("root-euid", "root-gid", "root-egid"):
            with self.subTest(scenario=scenario):
                text, receipt = self.run_handover(scenario)
                self.assertIn("IDENTITY_NORMALIZED", text)
                self.assertIn("SETRESUID", text)
                self.assertIn("SHARED_HELPER", text)
                self.assertLess(text.index("SETRESUID"), text.index("SHARED_HELPER"))
                self.assertIn("uid=0 euid=0 gid=0 egid=0", text)
                self.assertEqual("OK", receipt["verdict"])
                self.assertEqual("LOADED", receipt["carrier"]["stage2"])

    def test_ghostlock_identity_errors_stop_before_loading_and_report_the_step(self):
        for scenario, step in (("identity-failed", "setgroups"), ("gid-failed", "setresgid"),
                               ("uid-failed", "setresuid"), ("identity-readback-failed", "readback")):
            with self.subTest(scenario=scenario):
                text, receipt = self.run_handover(scenario)
                self.assertNotIn("SHARED_HELPER", text)
                self.assertEqual("GHOSTLOCK_IDENTITY_INVALID", receipt["token"])
                self.assertIn(f"step={step}", text)
                self.assertEqual(0, receipt["restore"]["failures"])

    def test_normal_keeps_its_working_ksu_identity_path(self):
        text, receipt = self.run_handover("root-gid", target="normal")
        self.assertNotIn("IDENTITY_NORMALIZED", text)
        self.assertIn("COMMAND=late-load", text)
        self.assertEqual("OK", receipt["verdict"])

    def test_helper_entry_errors_retain_their_token_and_unexercised_stage(self):
        for scenario, token in (("helper-not-privileged", "MA_HOOK_NOT_PRIVILEGED"),
                                ("helper-dir-rejected", "MA_HOOK_DIR_REJECTED")):
            with self.subTest(scenario=scenario):
                _, receipt = self.run_handover(scenario)
                self.assertEqual(token, receipt["token"])
                self.assertEqual("NOT_EXERCISED", receipt["carrier"]["stage2"])
                self.assertEqual(-1, receipt["restore"]["enforcingFinal"])
                self.assertEqual(0, receipt["restore"]["failures"])

    def test_loader_error_after_verified_restore_is_not_a_restore_failure(self):
        _, receipt = self.run_handover("load-failed")
        self.assertEqual("MA_HOOK_STAGE2_INVALID", receipt["token"])
        self.assertEqual(1, receipt["restore"]["enforcingFinal"])
        self.assertEqual(0, receipt["restore"]["failures"])

    def test_daemon_error_is_not_hidden_by_a_successful_load_and_restore(self):
        _, receipt = self.run_handover("daemon-failed")
        self.assertEqual("FAILED", receipt["verdict"])
        self.assertEqual("MA_HOOK_DAEMON_EXEC_FAILED", receipt["token"])
        self.assertEqual("LOADED", receipt["carrier"]["stage2"])
        self.assertEqual(1, receipt["restore"]["enforcingFinal"])
        self.assertEqual(0, receipt["restore"]["failures"])

    def test_mismatched_l3_is_rejected_before_loading(self):
        text, receipt = self.run_handover(digest="b" * 64)
        self.assertNotIn("SHARED_HELPER", text)
        self.assertNotIn("UNEXPECTED_ROOT_MODULE_LOAD", text)
        self.assertEqual("FAILED", receipt["verdict"])
        self.assertEqual("MAPLESU_HANDOVER_LOAD_FAILED", receipt["token"])

    def test_missing_l3_is_rejected_before_loading(self):
        text, receipt = self.run_handover(missing=True)
        self.assertNotIn("SHARED_HELPER", text)
        self.assertEqual("FAILED", receipt["verdict"])

    def test_missing_l3_digest_does_not_fall_back_to_the_legacy_root_digest(self):
        text, receipt = self.run_handover(include_stage2_digest=False)
        self.assertNotIn("SHARED_HELPER", text)
        self.assertNotIn("UNEXPECTED_ROOT_MODULE_LOAD", text)
        self.assertEqual("FAILED", receipt["verdict"])

    def test_helper_failure_never_claims_a_handover(self):
        text, receipt = self.run_handover("restore-failed")
        self.assertIn("SHARED_HELPER", text)
        self.assertNotIn("UNEXPECTED_ROOT_MODULE_LOAD", text)
        self.assertEqual("FAILED", receipt["verdict"])
        self.assertEqual("LOADED", receipt["carrier"]["stage2"])
        self.assertEqual("MA_HOOK_RESTORE_FAILED", receipt["token"])
        self.assertEqual(1, receipt["restore"]["failures"])
        self.assertNotIn("EXIT=0", text)

    def test_unarmed_gate_never_claims_readiness(self):
        _, receipt = self.run_handover("no-gate")
        self.assertEqual("DEGRADED", receipt["verdict"])
        self.assertEqual("UNAVAILABLE", receipt["carrier"]["gate"])

    def test_l3_load_failure_is_reported_immediately(self):
        text, receipt = self.run_handover("load-failed")
        self.assertIn("SHARED_HELPER", text)
        self.assertEqual("FAILED", receipt["verdict"])
        self.assertEqual("LOAD_FAILED", receipt["carrier"]["stage2"])

    def test_normal_still_uses_ksu_late_load(self):
        text, receipt = self.run_handover(target="normal")
        self.assertIn("COMMAND=late-load", text)
        self.assertNotIn("SHARED_HELPER", text)
        self.assertEqual("LATE_LOAD_OK", receipt["carrier"]["ksu"])
        self.assertEqual("OK", receipt["verdict"])

    def test_maplesu_93260_normalizes_identity_and_reuses_the_ultra_helper(self):
        text, receipt = self.run_handover(provider="maplesu_93260")
        self.assertIn("IDENTITY_NORMALIZED", text)
        self.assertIn("SHARED_HELPER=maplesu_93260 entry=1", text)
        self.assertNotIn("UNEXPECTED_ROOT_MODULE_LOAD", text)
        self.assertEqual("maplesu_93260", receipt["provider"])
        self.assertEqual("OK", receipt["verdict"])

    def test_maplesu_93260_identity_failure_stops_before_backend_loading(self):
        for target in ("normal", "ultra"):
            text, receipt = self.run_handover("identity-failed", target=target, provider="maplesu_93260")
            self.assertNotIn("SHARED_HELPER", text)
            self.assertNotIn("COMMAND=late-load", text)
            self.assertEqual("MAPLESU_93260_IDENTITY_INVALID", receipt["token"])
            self.assertEqual("FAILED", receipt["verdict"])

    def test_maplesu_93260_normal_verifies_the_staged_ksud(self):
        text, receipt = self.run_handover(target="normal", provider="maplesu_93260")
        self.assertIn("COMMAND=late-load", text)
        self.assertEqual("maplesu_93260", receipt["provider"])
        self.assertEqual("OK", receipt["verdict"])
        text, receipt = self.run_handover(target="normal", provider="maplesu_93260", root_digest="b" * 64)
        self.assertNotIn("COMMAND=late-load", text)
        self.assertEqual("MAPLESU_93260_KSUD_UNVERIFIED", receipt["token"])
        self.assertEqual("FAILED", receipt["verdict"])


@unittest.skipUnless(HOST_CC is not None, "no host C compiler")
class GhostlockSharedHelperTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ghostlock-shared-helper-")
        source = Path(cls.temp.name) / "helper.c"
        text = SOURCE.read_text(encoding="utf-8")
        structures = ""
        for name in ("hook_request", "hook_state"):
            start = text.index("struct " + name + " {")
            structures += text[start:text.index("};", start) + 2] + "\n"
        source.write_text(HARNESS_PREAMBLE + HELPER_PREAMBLE + structures + HELPER_FIXTURE +
                          definition(text, "hook_decide_target") +
                          definition(text, "hook_unload_child") +
                          definition(text, "umh_main") + HELPER_MAIN, encoding="utf-8")
        cls.exe = Path(cls.temp.name) / ("helper.exe" if os.name == "nt" else "helper")
        build = subprocess.run([str(HOST_CC), "-std=c11", "-O0", str(source), "-o", str(cls.exe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_helper(self, scenario="ok", ghostlock=True):
        result = subprocess.run([str(self.exe), str(int(ghostlock)), scenario],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def test_ghostlock_restores_once_before_return_without_unload_or_partition_ioctl(self):
        text = self.run_helper()
        self.assertIn("rc=0 enforce=1 writes=1 forks=0 deletes=0 partitions=0", text)
        self.assertLess(text.index("DAEMON"), text.index("RESTORE_WRITE"))
        self.assertLess(text.index("RESTORE_WRITE"), text.index("MAIN "))
        child = json.loads(text.split("CHILD=", 1)[1].splitlines()[0])
        self.assertEqual(1, child["skipped"])
        self.assertEqual(0, child["attempts"])
        self.assertEqual(1, child["readbackFinal"])

    def test_partial_root_identity_remains_rejected_and_is_returned_to_the_caller(self):
        for scenario in ("root-euid", "root-gid", "root-egid"):
            with self.subTest(scenario=scenario):
                text = self.run_helper(scenario)
                self.assertIn("rc=70 enforce=0 writes=0 forks=0 deletes=0 partitions=0", text)
                self.assertIn("OBSERVED stage2=NOT_EXERCISED token=MA_HOOK_NOT_PRIVILEGED failures=1 final=-1", text)
                self.assertNotIn("STAGE2\n", text)
                self.assertIn("euid=", text)
                self.assertIn("egid=", text)

    def test_rejected_attempt_directory_also_returns_the_original_failure(self):
        for scenario in ("dir-open-failed", "dir-invalid"):
            with self.subTest(scenario=scenario):
                text = self.run_helper(scenario)
                self.assertIn("rc=71 enforce=0 writes=0", text)
                self.assertIn("OBSERVED stage2=NOT_EXERCISED token=MA_HOOK_DIR_REJECTED failures=1 final=-1", text)

    def test_dirtyfrag_keeps_its_fork_unload_and_partition_path(self):
        text = self.run_helper(ghostlock=False)
        self.assertIn("rc=0 enforce=1 writes=1 forks=1 deletes=1 partitions=1", text)
        self.assertIn('"skipped":0', text)

    def test_stale_ksu_marker_does_not_reboot_a_ghostlock_ultra_handover(self):
        text = self.run_helper("stale-ksu")
        self.assertNotIn("KSU_HANDOFF", text)
        self.assertIn("rc=0 enforce=1", text)
        self.assertIn("KSU_HANDOFF", self.run_helper("stale-ksu", ghostlock=False))

    def test_restore_failure_is_synchronous_and_reported(self):
        text = self.run_helper("restore-failed")
        self.assertIn("MA_HOOK_RESTORE_FAILED", text)
        self.assertIn("unload=FAILED final=0", text)
        self.assertIn("rc=2 enforce=0 writes=1 forks=0 deletes=0 partitions=0", text)

    def test_an_already_restored_value_needs_no_second_write(self):
        self.assertIn("rc=0 enforce=1 writes=0 forks=0 deletes=0 partitions=0",
                      self.run_helper("preexisting"))

    def test_invalid_env_does_not_guess_a_restore_target(self):
        text = self.run_helper("invalid-env")
        self.assertIn("rc=2 enforce=0 writes=0 forks=0 deletes=0 partitions=0", text)

    def test_dirtyfrag_pending_child_is_still_pending_without_a_failure_token(self):
        text = self.run_helper("pending", ghostlock=False)
        self.assertIn("MAIN failures=0 token= unload=PENDING final=-1", text)
        self.assertIn("rc=2 enforce=0", text)


if __name__ == "__main__":
    unittest.main()
