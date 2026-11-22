"""Host tests for the step-3 UMH structural gate (`hook_contract.py`).

`hook_contract.py` asserts the shape of `adapter/bootstrap.c`'s UMH mode. A gate that
cannot go red proves nothing, so every negative below tampers a *copy* of the source
(or of the object) in a temporary directory and asserts exactly which check fails:

  * the UMH dispatch moved after stage-1's first marker;
  * a `/dev/dfm*` milestone planted inside `umh_main`;
  * `execv(` smuggled into `umh_main` (the consumer route);
  * the attempt document consulted by the mode decision;
  * a TR-12 needle removed (the production gate would go red too - this proves the
    coupling is real, not assumed);
  * a new library dependency added to the object's undefined symbols (patched .symtab
    byte, so the check is exercised on real ELF bytes);
  * P1's one approved exception (the marker-gated KernelSU branch in `umh_main`):
    removing its guard, moving it after the first hook descriptor, or guessing the
    daemon path must all go red again.

The L2 leg (S26-S40 / O6-O10) has its own class: it is red-first by construction (the
module and the helper slot are C1/C2), so it is tested twice - once against the real
tree (every gate id must be red today) and once against two synthetic stubs that are
shaped like the C1/C2 deliverables (every check must be able to go *green*, or the
gate would be a permanent red). Each stub is then mutated to prove the individual
checks bite.

The real `bootstrap.c` is hashed before the run and re-hashed afterwards: a test that
edits the file it verifies would be worse than no test.

Run: python -m unittest discover -s jailbreak-providers/dirtyfrag/tests
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROVIDERS = HERE.parents[1]
SOURCE = HERE.parent / "adapter" / "bootstrap.c"
GATE = HERE / "hook_contract.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("maplesu_hook_contract", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate_module = _load_gate()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class HookContractSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise unittest.SkipTest("bootstrap.c is missing")
        cls.text = SOURCE.read_text(encoding="utf-8")
        cls.sha_before = _sha(SOURCE)

    @classmethod
    def tearDownClass(cls):
        if _sha(SOURCE) != cls.sha_before:
            raise AssertionError("a test modified the real bootstrap.c")

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)

    def checks(self, text: str) -> list:
        return gate_module.source_checks(text)

    @staticmethod
    def failures(checks: list) -> list:
        return [check for check in checks if not check["ok"]]

    def test_01_real_source_passes(self):
        baseline = [check for check in self.checks(self.text)
                    if check.get("stage") != "l2"]
        self.assertEqual([], self.failures(baseline))

    def test_02_dispatch_after_the_first_marker_is_red(self):
        # Move the dispatch below the stage-1 head: the exact regression this gate is
        # for (the helper would then touch /dev/dfm1 and reach for the attempt file).
        dispatch = "    if (umh_mode_requested(argc, argv)) return umh_main(argc, argv, 0, NULL);\n"
        self.assertEqual(1, self.text.count(dispatch))
        moved = self.text.replace(dispatch, "")
        moved = moved.replace('    touch("/dev/dfm1");\n',
                              '    touch("/dev/dfm1");\n' + dispatch, 1)
        failures = self.failures(self.checks(moved))
        self.assertTrue(any("dispatches UMH before" in item["title"] for item in failures),
                        [item["title"] for item in failures])

    def test_03_marker_inside_umh_main_is_red(self):
        body = gate_module.function_body(self.text, "umh_main")
        self.assertIsNotNone(body)
        injected = body.replace("    /* Step 4: what the kernel observed.",
                                '    touch("/dev/dfm2");\n'
                                "    /* Step 4: what the kernel observed.", 1)
        self.assertNotEqual(body, injected)
        failures = self.failures(self.checks(self.text.replace(body, injected)))
        self.assertTrue(any("stage-1 irreversible step" in item["title"]
                            for item in failures), [item["title"] for item in failures])

    def test_04_execv_inside_umh_main_is_red(self):
        body = gate_module.function_body(self.text, "umh_main")
        injected = body.replace("    /* Step 4: what the kernel observed.",
                                '    execv("/system/bin/sh", 0);\n'
                                "    /* Step 4: what the kernel observed.", 1)
        failures = self.failures(self.checks(self.text.replace(body, injected)))
        self.assertTrue(any("execv(" in item["title"] for item in failures),
                        [item["title"] for item in failures])

    def test_05_mode_consulting_the_attempt_document_is_red(self):
        body = gate_module.function_body(self.text, "umh_mode_requested")
        mutated = body.replace("if (argc <= 1 || argv == NULL) return 0;",
                               "if (access(MAPLESU_ATTEMPT_FILE, F_OK) == 0) return 1;")
        self.assertNotEqual(body, mutated)
        failures = self.failures(self.checks(self.text.replace(body, mutated)))
        self.assertTrue(any("does not consult the attempt document" in item["title"]
                            for item in failures), [item["title"] for item in failures])

    def test_06_tr12_needle_removal_is_red(self):
        checks = self.checks(self.text.replace("emergency_teardown", "teardown_gone"))
        failures = self.failures(checks)
        self.assertTrue(any("TR-12 needle" in item["title"] for item in failures),
                        [item["title"] for item in failures])

    def test_07_missing_token_is_red(self):
        checks = self.checks(self.text.replace("MA_HOOK_WINDOW_CLOSED",
                                               "MA_HOOK_WINDOW_CLOSEX"))
        failures = self.failures(checks)
        self.assertTrue(any("token present: MA_HOOK_WINDOW_CLOSED" in item["title"]
                            for item in failures), [item["title"] for item in failures])

    def test_08_ungated_ksu_handoff_in_umh_main_is_red(self):
        # P1's exception is the *marker-gated* branch, not any call: remove the guard
        # and p1_ksu_branch() can no longer strip it, so S2 sees the forbidden step.
        body = gate_module.function_body(self.text, "umh_main")
        branch = gate_module.p1_ksu_branch(body)
        self.assertIsNotNone(branch, "the P1 branch is missing from umh_main")
        ungated = branch.replace("parsed == 0 && access(MAPLESU_USE_KSU, F_OK) == 0",
                                 "1")
        self.assertNotEqual(branch, ungated)
        failures = self.failures(self.checks(self.text.replace(branch, ungated, 1)))
        self.assertTrue(any("umh_main contains no stage-1 irreversible step"
                            in item["title"] for item in failures),
                        [item["title"] for item in failures])

    def test_09_p1_branch_after_the_first_fd_is_red(self):
        body = gate_module.function_body(self.text, "umh_main")
        branch = gate_module.p1_ksu_branch(body)
        self.assertIsNotNone(branch)
        moved = self.text.replace(branch, "", 1)
        anchor = "    state.write_fd = open(MAPLESU_ENFORCE_PATH, O_WRONLY | O_CLOEXEC);\n"
        self.assertEqual(1, moved.count(anchor), "the first hook fd is not recognisable")
        moved = moved.replace(anchor, anchor + branch + "\n", 1)
        failures = self.failures(self.checks(moved))
        self.assertTrue(any("precedes every hook descriptor" in item["title"]
                            for item in failures), [item["title"] for item in failures])

    def test_10_a_guessed_daemon_path_is_red(self):
        mutated = self.text.replace("/data/user/0/dev.maplesu.manager/ksud",
                                    "/data/local/tmp/ksud")
        self.assertNotEqual(self.text, mutated)
        failures = self.failures(self.checks(mutated))
        self.assertTrue(any("App's CE staging target" in item["title"]
                            for item in failures), [item["title"] for item in failures])


class HookContractObjectTest(unittest.TestCase):
    """Object-level leg. Skipped when no bootstrap.o was compiled for this run."""
    def setUp(self):
        self.object = PROVIDERS.parent / "work" / "hook" / "bootstrap.o"
        if not self.object.is_file():
            raise unittest.SkipTest("work/hook/bootstrap.o is absent; compile it first")
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)

    def test_01_real_object_passes(self):
        self.assertEqual([], [check for check in gate_module.object_checks(self.object)
                              if not check["ok"]])

    def test_02_new_library_dependency_is_red(self):
        # Rename one undefined symbol in a copy: `write` -> `xyzzy` keeps the string
        # table byte-for-byte the same length (so the ELF stays valid) while removing a
        # documented bionic entry, so the dependency check must refuse it.
        copy = self.dir / "bootstrap.o"
        shutil.copy2(self.object, copy)
        elf = gate_module.Elf(copy)
        table = next(section for section in elf.sections if section["type"] == 2)
        strings = elf.sections[table["link"]]
        raw = bytearray(copy.read_bytes())
        replacement = b"xyzzy\x00"
        patched = 0
        for base in range(table["offset"], table["offset"] + table["size"], 24):
            name, info, _other, shndx = struct.unpack_from("<IBBH", raw, base)
            if shndx != 0 or (info >> 4) not in (1, 2):
                continue
            start = strings["offset"] + name
            end = raw.find(b"\x00", start)
            if raw[start:end] == b"write":
                self.assertEqual(len(replacement), end + 1 - start)
                raw[start:end + 1] = replacement
                patched += 1
        self.assertEqual(1, patched)
        copy.write_bytes(bytes(raw))
        failures = [check for check in gate_module.object_checks(copy) if not check["ok"]]
        self.assertTrue(any("documented bionic set" in item["title"]
                            for item in failures), [item["title"] for item in failures])


# --------------------------------------------------------------------------- #
# L2 (S26-S40 / O6-O10): red on the real tree, green on the C1/C2-shaped stubs.
# --------------------------------------------------------------------------- #

# The smallest helper source that satisfies S26-S35. This is not a product file: it
# is the *satisfiability proof* for the L2 source leg. Without it, "the gate is red"
# would be indistinguishable from "the gate can never be green".
HELPER_STUB = r"""
struct hook_state {
    int dirfd;
    int l2_enabled;
    int l2_required;
    int l2_verdict;
};

static void hook_stage2(struct hook_state *state);
static void hook_daemon(struct hook_state *state);

static int l2_read_staged(int dirfd, const char *name, unsigned char *buffer,
                          size_t capacity) {
    const int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat status = {0};
    if (fd < 0) return -1;
    if (!fstat(fd, &status) && S_ISREG(status.st_mode) &&
        status.st_uid == home_uid && !(status.st_mode & 0077) &&
        status.st_nlink == 1) {
        close(fd);
        return 0;
    }
    close(fd);
    return -1;
}

static void l2_disarm(const char *why) {
    log_line("maplesu-hook: l2 disarm state=DISARMED why=%s armed_after=0\n", why);
}

static void hook_l2(struct hook_state *state) {
    unsigned char image[8192];
    int armed = 0;
    if (!state->l2_enabled) return;
    if (l2_read_staged(state->dirfd, "maplesu_l2.ko", image, sizeof(image)) != 0)
        return;
    if (ir_elf_precheck(image, sizeof(image)) != 0) return;
    const int rc = (int)syscall(MAPLESU_NR_FINIT_MODULE, -1,
                                "cookie=0x0123456789abcdef", 0);
    if (rc != 0) {
        log_line("maplesu-hook: l2 module state=LOAD_FAILED errno=%d\n", -rc);
        return;
    }
    armed = 1;
    log_line("maplesu-hook: l2 module state=LOADED name=maplesu_l2\n");
    l2_disarm("hook_l2");
    if (armed) {
        (void)syscall(MAPLESU_NR_DELETE_MODULE, MAPLESU_L2_MODULE_NAME, O_NONBLOCK);
        log_line("maplesu-hook: l2 unload name=maplesu_l2 rc=0 errno=0\n");
    }
}

static void hook_write_main_json(struct hook_state *state) {
    char document[4096];
    int count = 0;
    if (state->l2_enabled) {
        count = snprintf(document, sizeof(document),
            "{\"schema\":\"maplesu.hook.v1\",\"l2\":{\"schema\":\"maplesu.hook.l2.v1\","
            "\"module\":{\"state\":\"LOADED\"},\"hooks\":[{\"id\":\"ctl.magic\"},"
            "{\"id\":\"execve.entry\"},{\"id\":\"execve.ret\"}],"
            "\"selfcheck\":{\"kread\":0},\"selinux\":{\"before\":0,\"after\":0},"
            "\"disarm\":{\"state\":\"DISARMED\"},\"unload\":{\"rc\":0}},\"ts\":0}\n");
    }
    if (count > 0) {
        (void)write(state->ev_fd, document, (size_t)count);
        (void)fsync(state->ev_fd);
    }
}

static const char *hook_verdict(const struct hook_state *state) {
    if (state->l2_required && state->l2_verdict != 0) return "FAILED";
    return "OK";
}

static int hook_parse_argv(int argc, char **argv, struct hook_request *request) {
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--l2")) request->l2_enabled = 1;
        if (!strcmp(argv[i], "--l2-required")) {
            request->l2_required = request->l2_enabled = 1;
        }
    }
    return 0;
}

static int umh_main(int argc, char **argv) {
    struct hook_state state;
    hook_stage2(&state);
    if (state.l2_enabled) hook_l2(&state);
    hook_daemon(&state);
    hook_write_main_json(&state);
    return 0;
}

static const char *const l2_tokens[] = {
    "MA_L2_NOT_EXERCISED", "MA_L2_MODULE_", "MA_L2_LOAD_", "MA_L2_NO_COOKIE",
    "MA_L2_PROBE_", "MA_L2_SELFCHECK_FAILED", "MA_L2_DISARM_FAILED",
    "MA_L2_UNLOAD_BUSY", "MA_L2_NO_HIT", "MA_L2_RET_NO_HIT", "MA_L2_ARM_BUSY",
    "MA_L2_POLICY_MOVED", "MA_L2_SCNO_NOT_UNIMPLEMENTED",
};
"""

# The smallest module source + glue + compat header that satisfies S36-S40. Numbers in
# the header are the contract's (BTF-derived) values, written the way C1 must write
# them: asserted, not remembered.
MODULE_STUB = r"""
struct kprobe;
struct pt_regs;
struct kretprobe_instance;

#define MAPLESU_NOCFI __attribute__((no_sanitize("kcfi")))
#define WL_SCRATCH 0x80000001U
#define WL_SELINUX 0x80000002U

static unsigned long l2_scratch;
static unsigned long l2_enforcing_now;
static unsigned long l2_selinux_enforcing_addr;
static void *l2_sys_call_table;
static unsigned long l2_ni_addr;

static int l2_pre_execve(struct kprobe *p, struct pt_regs *regs);
static void l2_post_execve(struct kprobe *p, struct pt_regs *regs, unsigned long flags);
static int l2_ret_execve(struct kretprobe_instance *ri, struct pt_regs *regs);
static int l2_pre_ctl(struct kprobe *p, struct pt_regs *regs);

static MAPLESU_NOCFI int l2_kread(unsigned long addr, void *dst, unsigned int len) {
    return (int)l2_copy_from_kernel_nofault(dst, (const void *)addr, (size_t)len);
}

static MAPLESU_NOCFI int l2_kwrite(unsigned long addr, unsigned long value,
                                   unsigned int tag) {
    if (tag == WL_SCRATCH) {
        l2_scratch = value;
        return (l2_scratch == value) ? 0 : -5;
    }
    if (tag == WL_SELINUX) {
        if (addr != l2_selinux_enforcing_addr) return -EACCES;
        if (value != l2_enforcing_now) return -EACCES;
        *(volatile unsigned char *)addr = (unsigned char)value;
        return (*(volatile unsigned char *)addr == (unsigned char)value) ? 0 : -5;
    }
    return -EACCES;
}

static int l2_pre_ctl(struct kprobe *p, struct pt_regs *regs) {
    unsigned int scno = (unsigned int)regs->syscallno;
    void *slot = (void *)((unsigned long)l2_sys_call_table + (unsigned long)scno * 8UL);
    if (l2_ni_addr != 0 && slot != 0) return 0;
    return 0;
}

static int l2_pre_execve(struct kprobe *p, struct pt_regs *regs) { return 0; }
static void l2_post_execve(struct kprobe *p, struct pt_regs *regs,
                           unsigned long flags) { }
static int l2_ret_execve(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

int init_module(void) {
    return l2_kwrite(l2_selinux_enforcing_addr, l2_enforcing_now, WL_SELINUX);
}

void cleanup_module(void) {
}
"""

GLUE_STUB = """
    .section .gnu.linkonce.this_module,"aw",@progbits
    .zero 0x18
    .asciz "maplesu_l2"
    .section .modinfo,"a",@progbits
    .asciz "license=GPL"
    .asciz "name=maplesu_l2"
    .asciz "vermagic=6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k SMP preempt "
          "mod_unload modversions aarch64"
"""

COMPAT_STUB = """
struct maplesu_kretprobe { unsigned char raw[0xb0]; };
struct maplesu_pt_regs { unsigned char raw[0x150]; };
_Static_assert(sizeof(struct maplesu_kretprobe) >= 0xb0, "kretprobe size");
_Static_assert(__builtin_offsetof(struct maplesu_kretprobe, handler) == 0x80, "handler");
_Static_assert(__builtin_offsetof(struct maplesu_kretprobe, entry_handler) == 0x88,
               "entry_handler");
_Static_assert(__builtin_offsetof(struct maplesu_kretprobe, data_size) == 0x98,
               "data_size");
_Static_assert(__builtin_offsetof(struct maplesu_pt_regs, syscallno) == 0x118,
               "syscallno");
"""

L2_SOURCE_IDS = {"S%d" % number for number in range(26, 41)}
L2_OBJECT_IDS = {"O%d" % number for number in range(6, 11)}


class L2HookContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = gate_module.load_l2_contract()
        if cls.contract is None:
            raise unittest.SkipTest("no root-loader contract with an l2 block")
        if not SOURCE.is_file():
            raise unittest.SkipTest("bootstrap.c is missing")
        cls.text = SOURCE.read_text(encoding="utf-8")

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)
        self.module_dir = self.write_module()

    # -- fixtures ---------------------------------------------------------- #
    def write_module(self, source: str = MODULE_STUB, glue: str = GLUE_STUB,
                     compat: str = COMPAT_STUB) -> Path:
        module_dir = self.dir / "module"
        module_dir.mkdir(exist_ok=True)
        (module_dir / "maplesu_l2.c").write_text(source, encoding="utf-8")
        (module_dir / "root_glue_l2.S.in").write_text(glue, encoding="utf-8")
        (module_dir / "kernel_compat.h").write_text(compat, encoding="utf-8")
        return module_dir

    def checks(self, text: str, module_dir: Path | None = None) -> list:
        return gate_module.l2_source_checks(
            text, module_dir=module_dir or self.module_dir, contract=self.contract)

    @staticmethod
    def failed(checks: list, check_id: str | None = None) -> list:
        return [check for check in checks if not check["ok"]
                and (check_id is None or check["id"] == check_id)]

    # -- red first, on the real tree --------------------------------------- #
    def test_01_every_l2_gate_id_is_red_on_the_real_tree(self):
        real = gate_module.l2_source_checks(self.text, contract=self.contract)
        real += gate_module.l2_object_checks(Path(self.dir / "absent.ko"))
        ids = {check["id"] for check in real}
        self.assertEqual(L2_SOURCE_IDS | L2_OBJECT_IDS, ids,
                         "the L2 leg does not emit exactly S26-S40 / O6-O10")
        red_ids = {check["id"] for check in real if not check["ok"]}
        self.assertEqual((L2_SOURCE_IDS | L2_OBJECT_IDS) - {"S34"}, red_ids,
                         "every L2 gate id except S34 (the frozen-invariants digest, "
                         "which holds today) must be red before C1/C2 exists; these "
                         "are green: %s" % sorted((L2_SOURCE_IDS | L2_OBJECT_IDS)
                                                  - red_ids))
        # The checks that are already true today are named, so a future green cannot
        # be mistaken for progress it is not.
        green = [(check["id"], check["title"]) for check in real if check["ok"]]
        self.assertTrue(all(check_id in {"S34", "S37"} for check_id, _title in green),
                        green)

    def test_02_the_default_run_stays_green_and_l2_required_is_red(self):
        def run(*extra: str) -> tuple:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = gate_module.main(["--source", str(SOURCE),
                                         "--l2-source", str(self.dir / "no.c"),
                                         *extra])
            return code, buffer.getvalue()

        code, output = run("--no-l2")
        self.assertEqual(0, code, output[-2000:])
        self.assertIn("l2_checks=0", output)
        code, output = run()
        self.assertEqual(0, code, "the L2 leg must be non-fatal by default")
        self.assertIn("l2_red=", output)
        self.assertIn("the L2 leg is red by design", output)
        code, output = run("--l2-required")
        self.assertEqual(1, code, "with --l2-required the L2 reds must be fatal")
        self.assertIn("RESULT: FAILED", output)

    # -- ... and green on a C1/C2-shaped stub ------------------------------ #
    def test_03_helper_stub_satisfies_s26_s35(self):
        checks = self.checks(HELPER_STUB)
        self.assertEqual([], self.failed(checks),
                         "the C2-shaped stub does not satisfy the L2 source gate: %s"
                         % [(check["id"], check["title"], check["detail"])
                            for check in self.failed(checks)])

    def test_04_module_stub_satisfies_s36_s40(self):
        checks = self.checks(HELPER_STUB)
        for check_id in ("S36", "S37", "S38", "S39", "S40"):
            self.assertEqual([], self.failed(checks, check_id),
                             "%s is red on the C1-shaped stub" % check_id)
        # And the object leg, given an absent artifact, is red on all five ids: the
        # object side cannot be satisfied until C1 produces the .ko.
        object_checks = gate_module.l2_object_checks(Path(self.dir / "absent.ko"))
        self.assertEqual(L2_OBJECT_IDS,
                         {check["id"] for check in object_checks
                          if not check["ok"]})

    # -- every negative these gates exist for ------------------------------ #
    def test_05_moving_the_slot_after_the_daemon_is_red(self):
        moved = HELPER_STUB.replace(
            "    if (state.l2_enabled) hook_l2(&state);\n"
            "    hook_daemon(&state);",
            "    hook_daemon(&state);\n"
            "    if (state.l2_enabled) hook_l2(&state);")
        self.assertNotEqual(HELPER_STUB, moved)
        self.assertTrue(self.failed(self.checks(moved), "S26"))

    def test_06_a_flag_parsed_outside_hook_parse_argv_is_red(self):
        stray = HELPER_STUB.replace(
            "static void hook_l2(struct hook_state *state) {",
            'static void hook_l2(struct hook_state *state) {\n'
            '    if (!strcmp("--l2", "--l2")) return;')
        self.assertNotEqual(HELPER_STUB, stray)
        self.assertTrue(self.failed(self.checks(stray), "S28"))

    def test_07_deleting_the_module_before_disarming_is_red(self):
        wrong = HELPER_STUB.replace(
            "    l2_disarm(\"hook_l2\");\n    if (armed) {\n"
            "        (void)syscall(MAPLESU_NR_DELETE_MODULE",
            "    if (armed) {\n"
            "        (void)syscall(MAPLESU_NR_DELETE_MODULE")
        self.assertNotEqual(HELPER_STUB, wrong)
        self.assertTrue(self.failed(self.checks(wrong), "S32"))

    def test_08_an_eight_byte_policy_store_is_red(self):
        wide = MODULE_STUB.replace(
            "*(volatile unsigned char *)addr = (unsigned char)value;",
            "*(volatile unsigned long *)addr = value;")
        self.assertNotEqual(MODULE_STUB, wide)
        module_dir = self.write_module(source=wide)
        self.assertTrue(self.failed(self.checks(HELPER_STUB, module_dir), "S39"))

    def test_09_a_wrong_kretprobe_assert_is_red(self):
        wrong = COMPAT_STUB.replace("handler) == 0x80", "handler) == 0x48")
        self.assertNotEqual(COMPAT_STUB, wrong)
        module_dir = self.write_module(compat=wrong)
        self.assertTrue(self.failed(self.checks(HELPER_STUB, module_dir), "S37"))

    def test_10_a_shim_typed_callback_is_red(self):
        shim = MODULE_STUB.replace(
            "static int l2_pre_execve(struct kprobe *p, struct pt_regs *regs);",
            "static int l2_pre_execve(struct maplesu_kprobe *p, "
            "struct maplesu_pt_regs *regs);")
        self.assertNotEqual(MODULE_STUB, shim)
        module_dir = self.write_module(source=shim)
        self.assertTrue(self.failed(self.checks(HELPER_STUB, module_dir), "S38"))

    def test_11_a_magic_syscall_literal_in_the_module_is_red(self):
        literal = MODULE_STUB.replace(
            "static unsigned long l2_ni_addr;",
            "static unsigned long l2_ni_addr;\nstatic const int l2_scno = 453;")
        self.assertNotEqual(MODULE_STUB, literal)
        module_dir = self.write_module(source=literal)
        self.assertTrue(self.failed(self.checks(HELPER_STUB, module_dir), "S40"))

    def test_12_an_unnamed_module_is_red(self):
        glue = GLUE_STUB.replace("name=maplesu_l2", "name=maplesu_rooX")
        self.assertNotEqual(GLUE_STUB, glue)
        module_dir = self.write_module(glue=glue)
        self.assertTrue(self.failed(self.checks(HELPER_STUB, module_dir), "S36"))

    def test_13_loading_without_the_cookie_uargs_is_red(self):
        """M6: empty uargs means no cookie, so OP_ARM could never authenticate."""
        no_cookie = HELPER_STUB.replace(
            '                                "cookie=0x0123456789abcdef", 0);',
            '                                "", 0);')
        self.assertNotEqual(HELPER_STUB, no_cookie)
        self.assertTrue(self.failed(self.checks(no_cookie), "S27"))


if __name__ == "__main__":
    unittest.main()
