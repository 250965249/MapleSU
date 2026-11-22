"""Exercise the production L3 initializer at its kernel-call boundaries.

Fault injection checks which initialization stage was reached and that diagnostic
changes preserve return values and rollback. This does not reproduce a device panic.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "jailbreak-providers/dirtyfrag/tests"))
from test_l3_arm import definition, host_compiler

SOURCE = ROOT / "jailbreak-providers/root-loader/module/maplesu_l3.c"
FIXTURE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef uint64_t u64;
typedef uintptr_t uptr;
#define MAPLESU_NULL ((void *)0)
#define MAPLESU_TAG "maplesu_l3: "
#define MAPLESU_ENOSYS 38
#define MAPLESU_ENOENT 2
#define MAPLESU_ENOMEM 12
#define MAPLESU_EIO 5
#define MAPLESU_CRED_INIT_TASK 1
#define MAPLESU_CRED_SOURCE 1
#define MAPLESU_CRED_SOURCE_UNRESOLVED(source) (!(source))
#define MAPLESU_NOCFI
#define MAPLESU_GROUP_USAGE_OFF 0
#define MAPLESU_CRED_USAGE_OFF 0
#if MAPLESU_CRED_USAGE_SIZE == 8
typedef u64 fixture_cred_ref_t;
#else
typedef u32 fixture_cred_ref_t;
#endif
#define MAPLESU_L3_POOL 64
#define MAPLESU_L3_PRE_KCFI_ID 1
#define MAPLESU_L3_SYMBOL "__arm64_sys_prctl"
#define MAPLESU_LEGACY_CFI 1
struct kprobe;
struct pt_regs;
struct maplesu_l3_probe {
    uptr addr;
    const char *symbol_name;
    int (*pre_handler)(struct kprobe *, struct pt_regs *);
};
struct maplesu_selinux_state { u8 enforcing; };
typedef uptr (*maplesu_kallsyms_lookup_name_fn)(const char *);
typedef void *(*maplesu_prepare_kernel_cred_fn)(void *);
typedef int (*maplesu_commit_creds_fn)(void *);
typedef void (*maplesu_put_cred_fn)(const void *);
typedef long (*maplesu_getuid_fn)(void *);
static maplesu_kallsyms_lookup_name_fn maplesu_lookup;
static maplesu_prepare_kernel_cred_fn maplesu_prepare;
static maplesu_commit_creds_fn maplesu_commit;
static maplesu_put_cred_fn maplesu_put, maplesu_put_final;
static maplesu_getuid_fn maplesu_getuid;
static struct maplesu_selinux_state *maplesu_selinux;
static struct maplesu_l3_probe maplesu_probe, maplesu_avc_probe;
static void *(*maplesu_groups_alloc)(int);
static void (*maplesu_groups_free)(void *);
static void (*maplesu_set_groups)(void *, void *);
static uptr maplesu_groups, maplesu_cred_source, maplesu_pool[64];
static u32 maplesu_avc_registered, maplesu_registered, maplesu_pool_count, maplesu_ready, maplesu_armed;
static const char *scenario;
static unsigned registrations, unregistrations, prepared, released, status_calls, groups_freed;
static struct maplesu_selinux_state selinux;
static struct { u32 usage; } groups;
static struct { fixture_cred_ref_t usage; u32 guard; } creds[64];
static void _printk(const char *format, ...) {
    va_list args; va_start(args, format); vprintf(format, args); va_end(args);
}
static void *prepare(void *source) {
    if (source != (void *)1) abort();
    if (!strcmp(scenario, "empty-pool")) return NULL;
    if (!strcmp(scenario, "short-pool") && prepared == 2) return NULL;
    creds[prepared].usage = 1;
    creds[prepared].guard = 0xc0decafeu;
    return &creds[prepared++];
}
static int commit(void *cred) { (void)cred; return 0; }
static void put_final(const void *cred) {
    const fixture_cred_ref_t *usage = (const fixture_cred_ref_t *)cred;
    if (*usage != 0 || groups.usage <= 1) abort();
    released++; groups.usage--;
}
static void put(const void *cred) {
    fixture_cred_ref_t *usage = (fixture_cred_ref_t *)cred;
    if (!--*usage) put_final(cred);
}
static long caller_uid(void *frame) { (void)frame; return 0; }
static void *groups_alloc(int count) {
    if (count) abort();
    groups.usage = 1;
    return !strcmp(scenario, "groups") ? NULL : &groups;
}
static void groups_free(void *value) {
    if (value != &groups || groups.usage != 0) abort();
    groups_freed++;
}
static void set_groups(void *cred, void *value) {
    if (!cred || value != &groups) abort();
    groups.usage++;
}
static uptr maplesu_sym(const char *name) {
    if (!strcmp(name, "prepare_kernel_cred")) return (uptr)prepare;
    if (!strcmp(name, "commit_creds")) return (uptr)commit;
    if (!strcmp(name, "put_cred"))
        return strstr(scenario, "no-inline-put") || !strcmp(scenario, "no-releaser") ? 0 : (uptr)put;
    if (!strcmp(name, "__put_cred"))
        return !strcmp(scenario, "no-releaser") ? 0 : (uptr)put_final;
    if (!strcmp(name, "__arm64_sys_getuid")) return (uptr)caller_uid;
    if (!strcmp(name, "selinux_state")) return (uptr)&selinux;
    if (!strcmp(name, "init_task")) return 1;
    if (!strcmp(name, "groups_alloc")) return (uptr)groups_alloc;
    if (!strcmp(name, "groups_free")) return (uptr)groups_free;
    if (!strcmp(name, "set_groups")) return (uptr)set_groups;
    abort();
}
static int register_kprobe(struct maplesu_l3_probe *probe) {
    registrations++;
    if (!strcmp(probe->symbol_name, "kallsyms_lookup_name")) {
        if (!strcmp(scenario, "lookup")) return -1;
        probe->addr = (uptr)maplesu_sym;
    } else if (probe == &maplesu_avc_probe && !strncmp(scenario, "avc", 3)) return -5;
    else if (probe == &maplesu_probe && !strncmp(scenario, "prctl", 5)) return -22;
    else probe->addr = 1;
    return 0;
}
static void unregister_kprobe(struct maplesu_l3_probe *probe) {
    (void)probe; unregistrations++;
}
static void maplesu_status_init(void) { status_calls++; }
static void maplesu_policy_init(void) { }
static void maplesu_policy_cleanup(void) { }
static void maplesu_status_cleanup(void) { }
int maplesu_l3_pre(struct kprobe *p, struct pt_regs *r) { (void)p; (void)r; return 0; }
int maplesu_avc_pre(struct kprobe *p, struct pt_regs *r) { (void)p; (void)r; return 0; }
void __cfi_check(u64 type, void *target, void *diag) { (void)type; (void)target; (void)diag; }
'''
MAIN = r'''
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    scenario = argv[1];
    int rc = init_module();
    if (!strcmp(scenario, "cleanup-no-inline-put") && rc == 0) {
        creds[0].usage++; /* one credential remains owned by a live task */
        cleanup_module();
    }
    for (unsigned i = 0; i < prepared; ++i)
        if (creds[i].guard != 0xc0decafeu) abort();
    printf("REFS pool=%u groups=%u freed=%u first=%llu\n",
        maplesu_pool_count, groups.usage, groups_freed, (unsigned long long)creds[0].usage);
    printf("RESULT rc=%d register=%u unregister=%u prepared=%u released=%u status=%u\n",
        rc, registrations, unregistrations, prepared, released, status_calls);
    return 0;
}
'''


class L3InitProgressTest(unittest.TestCase):
    usage_size = 8

    @classmethod
    def setUpClass(cls):
        compiler = host_compiler()
        if compiler is None:
            raise unittest.SkipTest("no host C compiler")
        cls.temp = tempfile.TemporaryDirectory(prefix="maplesu-l3-init-")
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        source = path / "fixture.c"
        production = SOURCE.read_text(encoding="utf-8")
        body = "\n".join(definition(production, name) for name in (
            "maplesu_groups_release", "maplesu_pool_release", "init_module", "cleanup_module"))
        source.write_text(FIXTURE + body + MAIN, encoding="utf-8")
        cls.binary = path / ("fixture.exe" if os.name == "nt" else "fixture")
        result = subprocess.run([str(compiler), "-std=c11", "-O0",
                                 f"-DMAPLESU_CRED_USAGE_SIZE={cls.usage_size}",
                                 str(source), "-o", str(cls.binary)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_init(self, scenario):
        result = subprocess.run([str(self.binary), scenario], capture_output=True, text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        stages = [line.split("stage=", 1)[1] for line in result.stdout.splitlines()
                  if line.startswith("maplesu_l3: init stage=")]
        return result.stdout, stages

    def test_success_distinguishes_each_sleeping_or_registering_stage(self):
        text, stages = self.run_init("ok")
        self.assertEqual(["entry", "lookup-ready", "symbols-ready", "groups-ready", "pool-ready",
                          "callbacks-ready", "avc-ready", "prctl-ready"], stages)
        self.assertIn("rc=0 register=3 unregister=1 prepared=64 released=0 status=1", text)

    def test_lookup_failure_is_distinct_from_loader_not_entering_init(self):
        text, stages = self.run_init("lookup")
        self.assertEqual(["entry"], stages)
        self.assertIn("rc=-38 register=1 unregister=0 prepared=0 released=0 status=0", text)

    def test_group_allocation_and_empty_pool_stop_before_any_callback(self):
        for scenario, final_stage in (("groups", "symbols-ready"), ("empty-pool", "groups-ready")):
            with self.subTest(scenario=scenario):
                text, stages = self.run_init(scenario)
                self.assertTrue(stages)
                self.assertEqual(final_stage, stages[-1])
                self.assertIn("rc=-12 register=1 unregister=1 prepared=0 released=0 status=0", text)

    def test_registration_failure_preserves_full_rollback(self):
        for scenario, expected, final_stage in (
            ("avc", "rc=-5 register=2 unregister=1 prepared=64 released=64 status=0", "callbacks-ready"),
            ("prctl", "rc=-22 register=3 unregister=2 prepared=64 released=64 status=0", "avc-ready"),
        ):
            with self.subTest(scenario=scenario):
                text, stages = self.run_init(scenario)
                self.assertTrue(stages)
                self.assertEqual(final_stage, stages[-1])
                self.assertIn(expected, text)

    def test_out_of_line_releaser_rolls_back_failed_probe_registration(self):
        for scenario, expected in (
            ("avc-no-inline-put", "rc=-5 register=2 unregister=1 prepared=64 released=64"),
            ("prctl-no-inline-put", "rc=-22 register=3 unregister=2 prepared=64 released=64"),
        ):
            with self.subTest(scenario=scenario):
                text, _ = self.run_init(scenario)
                self.assertIn(expected, text)
                self.assertIn("REFS pool=0 groups=0 freed=1 first=0", text)

    def test_cleanup_keeps_the_issued_credential_alive(self):
        text, _ = self.run_init("cleanup-no-inline-put")
        self.assertIn("rc=0 register=3 unregister=3 prepared=64 released=63", text)
        self.assertIn("REFS pool=0 groups=1 freed=0 first=1", text)

    def test_no_releaser_stops_before_allocating_pool_or_groups(self):
        text, stages = self.run_init("no-releaser")
        self.assertEqual(["entry", "lookup-ready"], stages)
        self.assertIn("rc=-2 register=1 unregister=1 prepared=0 released=0", text)
        self.assertIn("REFS pool=0 groups=0 freed=0 first=0", text)

    def test_short_pool_keeps_the_existing_success_behavior(self):
        text, stages = self.run_init("short-pool")
        self.assertIn("pool-ready", stages)
        self.assertIn("rc=0 register=3 unregister=1 prepared=2 released=0 status=1", text)


class L3InitProgress32BitUsageTest(L3InitProgressTest):
    usage_size = 4


if __name__ == "__main__":
    unittest.main()
