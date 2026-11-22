"""Run the real GhostLock handover, shared helper and restore across enforcement.

Only OS/kernel boundaries are replaced. App-data pathname opens become EACCES
once the production restore writes enforcing=1, matching the kernel domain's
contract. Previously the helper succeeded but the handover lost its receipt.
This is a userspace integration regression, not a kernel-freeze reproduction.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_handover_mode import HARNESS_PREAMBLE, HOST_CC, SOURCE, definition, read_block
from test_ghostlock_ultra_handover import HELPER_FIXTURE, HELPER_PREAMBLE, IDENTITY_BOUNDARIES


PREAMBLE = r'''
#define MAPLESU_L3_GATE_ARMED "ARMED"
#define MAPLESU_KSUD_INSTALLED "/fixture/ksud"
#define MAPLESU_KSU_PACKAGE "dev.maplesu.manager"
#define MAPLESU_HANDOVER_EXIT_USAGE 64
#define MAPLESU_HANDOVER_EXIT_LOAD 65
#define MAPLESU_HANDOVER_EXIT_KSU 66
#define MAPLESU_HANDOVER_EXIT_EVIDENCE 68
#define MAPLESU_HANDOVER_WAIT_SECONDS 2
#define MAPLESU_LATE_LOAD_SECONDS 1
#define MAPLESU_HANDOVER_ENV_NAME "maplesu-handover-env"
#define MAPLESU_HANDOVER_EVIDENCE "attempt/maplesu-handover.json"
#define MAPLESU_HOOK_DAEMON_DOC "attempt/maplesu-hook-daemon.json"
static char receipt[4096], env_text[HANDOVER_ENV_MAX];
static int denied_opens, receipt_synced;
static int set_current_domain(const char *domain) { (void)domain; return 0; }
static int run_ctx(const char *domain, char **args) { (void)domain; (void)args; return 0; }
static int wait_for_late_load(int seconds) { (void)seconds; return 0; }
static int late_load_running(void) { return 0; }
static int fixture_setenv(const char *key, const char *value, int overwrite) {
    (void)key; (void)value; (void)overwrite; return 0;
}
#define setenv fixture_setenv
'''

OPEN = r'''
static int fixture_open(const char *path, int flags, ...) {
    if (!strncmp(path, "attempt", 7) && enforcing) {
        denied_opens++; errno = EACCES; return -1;
    }
    if (!strcmp(path, MAPLESU_HANDOVER_EVIDENCE)) {
        if (!strcmp(scenario, "receipt-open-failed")) { errno = EACCES; return -1; }
        return 41;
    }
    if (!strcmp(path, MAPLESU_ENFORCE_PATH) || !strcmp(path, "/sys/fs/selinux/enforce"))
        return (flags & O_ACCMODE) == O_WRONLY ? 10 : 11;
    if (strstr(path, MAPLESU_HANDOVER_ENV_NAME)) return 50;
    if (!strcmp(path, MAPLESU_HOOK_DAEMON_DOC)) return 51;
    if (!strcmp(path, "/proc/modules")) return 52;
    return !strcmp(path, MAPLESU_HOOK_UNLOAD_EVIDENCE) ? 40 : 30;
}
'''

WRITE = r'''
static ssize_t fixture_write(int fd, const void *data, size_t size) {
    if (fd == 10) {
        writes++; puts("RESTORE_WRITE");
        if (!strcmp(scenario, "restore-failed")) return -1;
        enforcing = *(const char *)data == '1';
    } else if (fd == 40) {
        snprintf(child_document, sizeof(child_document), "%.*s", (int)size, (const char *)data);
    } else if (fd == 41) {
        if (!strcmp(scenario, "receipt-write-failed")) { errno = EIO; return -1; }
        snprintf(receipt, sizeof(receipt), "%.*s", (int)size, (const char *)data);
    }
    return (ssize_t)size;
}
'''

BOUNDARIES = r'''
static ssize_t fixture_read(int fd, void *out, size_t size) {
    const char *text = fd == 50 ? env_text : fd == 51 ?
        "{\"attempt\":\"attempt-1\",\"bootId\":\"boot-1\",\"suGate\":\"ARMED\"}" :
        fd == 52 ? "maplesu_l3 4096 0 - Live 0x0\n" : enforcing ? "1" : "0";
    size_t count = strlen(text); if (count > size) count = size;
    memcpy(out, text, count); return (ssize_t)count;
}
#define read fixture_read
static unsigned fixture_sleep(unsigned seconds) { (void)seconds; return 0; }
#define sleep fixture_sleep
#undef fsync
static int fixture_fsync(int fd) { if (fd == 41) receipt_synced++; return 0; }
#define fsync fixture_fsync
'''

MAIN = r'''
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    scenario = argv[1];
    size_t got = fread(env_text, 1, sizeof(env_text) - 1, stdin);
    env_text[got] = '\0';
    char *args[] = {"/fixture/bs", "--handover", "--target", "ultra",
        "--phase", "pre", "--attempt", "attempt-1", "--boot", "boot-1",
        "--entry-enforcing", "1", NULL};
    int rc = handover_main(12, args);
    printf("RESULT rc=%d enforcing=%d denied=%d synced=%d\n",
           rc, enforcing, denied_opens, receipt_synced);
    printf("RECEIPT=%s\n", receipt);
    return 0;
}
'''


@unittest.skipUnless(HOST_CC is not None, "no host C compiler")
class GhostlockUltraWindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ghostlock-ultra-window-")
        directory = Path(cls.temp.name)
        text = SOURCE.read_text(encoding="utf-8")
        structures = ""
        for name in ("hook_request", "hook_state"):
            start = text.index("struct " + name + " {")
            structures += text[start:text.index("};", start) + 2] + "\n"
        fixture = HELPER_FIXTURE
        fixture = fixture.replace(definition(fixture, "fixture_open"), OPEN)
        fixture = fixture.replace(definition(fixture, "fixture_write"), WRITE)
        fixture = fixture.replace(definition(fixture, "hook_read_env"), r'''
static void hook_read_env(struct hook_state *state, const struct stat *home) {
    (void)home; state->env_ok = 1; state->env_expected = 1;
    strcpy(state->env_source, "observed"); strcpy(state->attempt, "attempt-1");
    strcpy(state->boot_id, "boot-1");
}
''')
        fixture = fixture.replace(definition(fixture, "hook_stage2"), r'''
static void hook_stage2(struct hook_state *state) {
    live_state = state; puts("STAGE2");
    strcpy(state->stage2_state, !strcmp(scenario, "load-failed") ? "LOAD_FAILED" :
           !strcmp(scenario, "resident") ? "ALREADY_RESIDENT" : "LOADED");
    strcpy(state->su_gate, (!strcmp(scenario, "load-failed") || !strcmp(scenario, "no-gate")) ?
           "UNAVAILABLE" : "ARMED");
}
''')
        names = ("hook_decide_target", "hook_unload_child", "umh_main",
                 "handover_read_text", "handover_read_env", "handover_gate_armed",
                 "handover_module_loaded", "handover_enforcing_now",
                 "handover_write_evidence_fd", "handover_write_evidence",
                 "handover_wait_for_carrier", "handover_main")
        source = directory / "fixture.c"
        source.write_text(HARNESS_PREAMBLE + read_block() + HELPER_PREAMBLE +
                          structures + PREAMBLE + fixture + IDENTITY_BOUNDARIES + BOUNDARIES +
                          "\n".join(definition(text, name) or "" for name in names) + MAIN,
                          encoding="utf-8")
        cls.exe = directory / ("fixture.exe" if os.name == "nt" else "fixture")
        build = subprocess.run([str(HOST_CC), "-std=c11", "-O0", str(source), "-o", str(cls.exe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_handover(self, scenario="ok", provider=None):
        import hashlib
        with tempfile.TemporaryDirectory(dir=self.temp.name) as temp:
            payload = b"\x7fELF" + b"fixture-L3" * 8
            (Path(temp) / "maplesu_stage2.ko").write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            env = ("schema=maplesu.handover.env.v1 boot=boot-1 attempt=attempt-1 target=ultra "
                   f"root_sha256={digest} stage2_sha256={digest}")
            env += (f" provider={provider}" if provider else "") + "\n"
            result = subprocess.run([str(self.exe), scenario], input=env, cwd=temp,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            receipt = result.stdout.split("RECEIPT=", 1)[1].strip()
            return result.stdout, json.loads(receipt) if receipt else None

    def test_ultra_publishes_a_durable_bound_receipt_without_reopening_app_data(self):
        text, receipt = self.run_handover()
        self.assertIsNotNone(receipt, text)
        self.assertEqual("OK", receipt["verdict"], text)
        self.assertEqual("ARMED", receipt["carrier"]["gate"])
        self.assertEqual(1, receipt["restore"]["enforcingFinal"])
        self.assertIn("RESULT rc=0 enforcing=1 denied=0 synced=1", text)

    def test_resident_module_uses_the_observed_arm_result(self):
        text, receipt = self.run_handover("resident")
        self.assertIsNotNone(receipt, text)
        self.assertEqual("OK", receipt["verdict"])
        self.assertEqual("LOADED", receipt["carrier"]["stage2"])

    def test_maplesu_93260_uses_the_real_helper_and_publishes_across_restore(self):
        text, receipt = self.run_handover(provider="maplesu_93260")
        self.assertEqual("OK", receipt["verdict"], text)
        self.assertEqual("maplesu_93260", receipt["provider"])
        self.assertEqual("ARMED", receipt["carrier"]["gate"])
        self.assertIn("RESULT rc=0 enforcing=1 denied=0 synced=1", text)

    def test_unarmed_gate_does_not_accept_a_daemon_document_claiming_armed(self):
        text, receipt = self.run_handover("no-gate")
        self.assertIsNotNone(receipt, text)
        self.assertEqual("DEGRADED", receipt["verdict"])
        self.assertEqual("UNAVAILABLE", receipt["carrier"]["gate"])

    def test_load_failure_is_preserved_even_when_proc_modules_claims_residency(self):
        text, receipt = self.run_handover("load-failed")
        self.assertIsNotNone(receipt, text)
        self.assertEqual("FAILED", receipt["verdict"])
        self.assertEqual("LOAD_FAILED", receipt["carrier"]["stage2"])
        self.assertEqual("MAPLESU_HANDOVER_LOAD_FAILED", receipt["token"])

    def test_restore_failure_is_published_through_the_same_descriptor(self):
        text, receipt = self.run_handover("restore-failed")
        self.assertIsNotNone(receipt, text)
        self.assertEqual("FAILED", receipt["verdict"])
        self.assertEqual("MA_HOOK_RESTORE_FAILED", receipt["token"])
        self.assertEqual(0, receipt["restore"]["enforcingFinal"])

    def test_a_failed_receipt_open_stops_before_stage2_and_outer_restore_can_continue(self):
        text, receipt = self.run_handover("receipt-open-failed")
        self.assertIsNone(receipt, text)
        self.assertNotIn("STAGE2", text)
        self.assertIn("RESULT rc=68 enforcing=0 denied=0", text)

    def test_receipt_write_failure_is_not_reported_as_success(self):
        text, receipt = self.run_handover("receipt-write-failed")
        self.assertIsNone(receipt, text)
        self.assertIn("RESULT rc=68 enforcing=1", text)


if __name__ == "__main__":
    unittest.main()
