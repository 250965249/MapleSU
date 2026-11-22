"""Host tests for the L2 contract additions (C0).

What this file proves, and why each test exists:

  * the committed contract still regenerates byte-identically, twice in a row
    (`derive_contract.py --out`, `--check`), so no L2 number is hand-edited;
  * the L2 layout numbers equal an *independent* BTF parse - the gate's parser
    (`loader_contract._Btf`), not the generator's - for `struct kretprobe` and
    `struct pt_regs`, and the KCFI ids are pinned to the image's own compare sites;
  * the declaration -> type-id mapping is real: compiling the kernel-named
    declarations with the repo's clang reproduces the image ids, and the shim-named
    spelling produces a *different* id (0x2b8cdf69), which is the measurement the
    "kernel struct names in callback prototypes" rule rests on;
  * the two lists the gates assert on are exactly the design's: 6 imports and 3
    runtime lookups, and the lookups are unexported (an import would not link);
  * every structural rule in `validate_l2_contract` can fail: the mutations below
    each name the field they broke;
  * G11's corrected decode requirement works: a compiled `movz #0x1c5` / `cmp #0x1c5`
    is found by the movz/movk/cmp decoder and the raw bytes `c5 01 00 00` are not in
    the object at all - the byte-pattern check the design first proposed is vacuous;
  * the write-scope census bites on a bare `str xN,[xM]` to a caller pointer, which
    no other gate can see.

No device, no adb, no module load. Everything here is host-side, and every artifact
written by a test lives in a temporary directory.

Run: python -m unittest discover -s jailbreak-providers/root-loader/tests
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import native_toolchain  # noqa: E402
ROOT_LOADER = ROOT / "jailbreak-providers" / "root-loader"
IR_LOADER = ROOT / "jailbreak-providers" / "ir-loader"
LOADER_CONTRACT = IR_LOADER / "tests" / "loader_contract.py"
CONTRACTS = sorted((ROOT_LOADER / "contracts").glob("*.json"))
CONTRACT = CONTRACTS[0] if CONTRACTS else ROOT_LOADER / "contracts" / "missing.json"
DERIVE = ROOT_LOADER / "contracts" / "derive_contract.py"
IMAGE = ROOT / ".analysis" / "ace6-20261025" / "boot" / "kernel"
BUILDER = ROOT_LOADER / "build_root_module.py"
GOOD = ROOT_LOADER / "build" / "maplesu_root.ko"
HOOK_CONTRACT = ROOT / "jailbreak-providers" / "dirtyfrag" / "tests" / "hook_contract.py"
NDK = native_toolchain.provider_ndk()
CLANG = NDK / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin" / "clang.exe"

# Stated independently of the generator on purpose: the contract has to agree with a
# second statement of these numbers, not only with the code that produced it.
PRE_HANDLER_ID = 0xA6BE5DD9
KRETPROBE_HANDLER_ID = 0x8078BE15
INIT_ID = 0x36B1C5A6
SHIM_PRE_HANDLER_ID = 0x2B8CDF69
IMPORTS = {"register_kprobe", "register_kretprobe", "unregister_kprobe",
           "unregister_kretprobe", "_printk", "copy_from_kernel_nofault"}
LOOKUPS = {"__arm64_sys_ni_syscall", "sys_call_table", "copy_to_user_nofault"}


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class L2ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (CONTRACT, DERIVE, IMAGE, LOADER_CONTRACT, BUILDER):
            if not path.is_file():
                raise unittest.SkipTest("missing input: %s" % path)
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.l2 = cls.contract["l2"]
        cls.derive = _load(DERIVE, "maplesu_derive_contract_l2")
        cls.loader_contract = _load(LOADER_CONTRACT, "maplesu_loader_contract_l2")

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)

    # -- the contract is derived, and derived twice the same way ------------ #
    def test_01_regenerates_byte_identically_twice(self):
        first, second = self.dir / "a.json", self.dir / "b.json"
        for output in (first, second):
            result = subprocess.run([sys.executable, str(DERIVE), "--out", str(output),
                                     "--quiet"], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(_sha256(first), _sha256(second),
                         "two runs of derive_contract.py disagree: the contract is no "
                         "longer a deterministic function of the image")
        self.assertEqual(_sha256(CONTRACT), _sha256(first),
                         "the committed contract is stale: regenerate it with "
                         "contracts/derive_contract.py")
        check = subprocess.run([sys.executable, str(DERIVE), "--check"],
                               capture_output=True, text=True)
        self.assertEqual(0, check.returncode, check.stdout + check.stderr)
        self.assertIn("RESULT: PASS", check.stdout)
        self.assertIn("l2 block    ok", check.stdout)

    def test_02_l2_offsets_match_an_independent_btf_parse(self):
        btf = self.loader_contract._load_btf(IMAGE, IMAGE.read_bytes(),
                                             self.contract["btf"]["magicOffset"])
        kretprobe = btf.struct("kretprobe")
        offsets = self.contract["structOffsets"]["kretprobe"]
        self.assertEqual(kretprobe["size"], offsets["size"])
        self.assertEqual(0xB0, offsets["size"])
        for member, key in (("kp", "kp"), ("handler", "handler"),
                            ("entry_handler", "entryHandler"),
                            ("data_size", "dataSize")):
            self.assertEqual(
                self.loader_contract._Btf.member(kretprobe, member)["byte"],
                offsets[key], "kretprobe.%s" % member)
        self.assertEqual(0x80, offsets["handler"])
        self.assertEqual(0x88, offsets["entryHandler"])
        self.assertEqual(0x98, offsets["dataSize"])
        self.assertEqual(4926, offsets["btfTypeId"])

        pt_regs = btf.struct("pt_regs")
        mine = self.contract["structOffsets"]["ptRegs"]
        self.assertEqual(pt_regs["size"], mine["size"])
        self.assertEqual(0x150, mine["size"])
        self.assertEqual(0x118, mine["syscallno"])
        self.assertEqual(2275, mine["btfTypeId"])
        # regs/sp/pc/pstate live inside the anonymous union, so the generator had to
        # descend; assert the descent rather than the four numbers alone.
        for key in ("regs", "sp", "pc", "pstate"):
            self.assertIn(key, mine)
        self.assertIn("user_regs", mine["regsPath"])

    def test_03_kcfi_ids_are_pinned_to_the_image_compare_sites(self):
        ids = self.l2["kcfiIds"]
        self.assertEqual("0x%08x" % PRE_HANDLER_ID, ids["preHandler"]["value"])
        self.assertEqual("0x%08x" % KRETPROBE_HANDLER_ID,
                         ids["kretprobeHandler"]["value"])
        self.assertEqual("0x%08x" % INIT_ID, ids["init"]["value"])
        for key, row in ids.items():
            self.assertTrue(row["matches"], "%s did not match the image" % key)
            if key != "init":
                self.assertTrue(row["inImageTypeIdSet"],
                                "%s is not an id the image compares" % key)
                self.assertTrue(row["callSitesWithThisId"],
                                "%s has no dispatch call site" % key)
        pre = ids["preHandler"]
        self.assertEqual(0x40, pre["member"]["offset"])
        self.assertIn("kprobe_breakpoint_handler",
                      [site["function"] for site in pre["callSitesWithThisId"]])
        kret = ids["kretprobeHandler"]
        self.assertEqual(0x80, kret["member"]["offset"])
        self.assertIn("__kretprobe_trampoline_handler",
                      [site["function"] for site in kret["callSitesWithThisId"]])
        # The strong form of the evidence: the compare site is fed by a load of the
        # member the contract names (kp->pre_handler / rp->handler).
        self.assertTrue(pre["memberLoadConfirmed"])
        self.assertTrue(kret["memberLoadConfirmed"])
        self.assertEqual([], self.l2["kcfiMismatches"])

    # -- the declarations really hash to those ids -------------------------- #
    def _compile(self, name: str, source: str) -> int:
        """Compile one TU and return the 4 bytes before the callback's entry."""
        c_path, o_path = self.dir / (name + ".c"), self.dir / (name + ".o")
        c_path.write_text(source, encoding="utf-8")
        flags = ["--target=aarch64-linux-gnu", "-ffreestanding", "-nostdlib",
                 "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-ffixed-x18",
                 "-mgeneral-regs-only", "-mno-outline-atomics", "-fsanitize=kcfi",
                 "-O2", "-c"]
        result = subprocess.run([str(CLANG), *flags, str(c_path), "-o", str(o_path)],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr[-800:])
        build = _load(BUILDER, "maplesu_build_l2")
        elf = build.Elf(o_path)
        symbol = elf.symbol("cb")
        self.assertIsNotNone(symbol, "no cb symbol in the compiled TU")
        position = elf.symbol_file_offset(symbol)
        return int.from_bytes(elf.raw[position - 4:position], "little")

    @unittest.skipUnless(CLANG.is_file(), "the NDK clang is absent")
    def test_04_declarations_reproduce_the_ids_kernel_names_vs_shims(self):
        cases = {
            "pre_kernel": (
                "struct kprobe; struct pt_regs;\n"
                "typedef int (*t)(struct kprobe *, struct pt_regs *);\n"
                "__attribute__((noinline)) int cb(struct kprobe *p, struct pt_regs *r)"
                "{return (int)(long)p+(int)(long)r;}\n"
                "volatile t slot = cb;\n"
                "int call(void){t f=slot;return f((struct kprobe*)0,"
                "(struct pt_regs*)0);}\n", PRE_HANDLER_ID),
            "kret_kernel": (
                "struct kretprobe_instance; struct pt_regs;\n"
                "typedef int (*t)(struct kretprobe_instance *, struct pt_regs *);\n"
                "__attribute__((noinline)) int cb(struct kretprobe_instance *i, "
                "struct pt_regs *r){return (int)(long)i+(int)(long)r;}\n"
                "volatile t slot = cb;\n"
                "int call(void){t f=slot;return f((struct kretprobe_instance*)0,"
                "(struct pt_regs*)0);}\n", KRETPROBE_HANDLER_ID),
            "pre_shim": (
                "struct maplesu_kprobe; struct maplesu_pt_regs;\n"
                "typedef int (*t)(struct maplesu_kprobe *, struct maplesu_pt_regs *);\n"
                "__attribute__((noinline)) int cb(struct maplesu_kprobe *p, "
                "struct maplesu_pt_regs *r){return (int)(long)p+(int)(long)r;}\n"
                "volatile t slot = cb;\n"
                "int call(void){t f=slot;return f((struct maplesu_kprobe*)0,"
                "(struct maplesu_pt_regs*)0);}\n", SHIM_PRE_HANDLER_ID),
        }
        measured = {}
        for name, (source, expected) in cases.items():
            measured[name] = self._compile(name, source)
            self.assertEqual(expected, measured[name],
                             "%s: the declaration does not hash to 0x%08x"
                             % (name, expected))
        # The measured mismatch is why kernel struct names are mandatory: the shim
        # spelling yields a different id, so the kernel's first check would trap.
        self.assertNotEqual(measured["pre_kernel"], measured["pre_shim"])
        recorded = {case["case"]: case["typeId"]
                    for case in self.l2["declarationCheck"]["cases"]}
        self.assertEqual("0x%08x" % measured["pre_shim"],
                         recorded["preHandler.shimNames"])
        self.assertEqual("0x%08x" % measured["pre_kernel"],
                         recorded["preHandler.kernelNames"])

    # -- the two lists the gates assert on --------------------------------- #
    def test_05_imports_and_lookups_are_exactly_the_designed_sets(self):
        imports = [row["name"] for row in self.l2["imports"]]
        self.assertEqual(6, len(imports))
        self.assertEqual(IMPORTS, set(imports))
        self.assertEqual(6, self.l2["importCount"])
        for row in self.l2["imports"]:
            self.assertTrue(row["export"], "%s is not exported" % row["name"])
            self.assertFalse(row["kcfiSignature"],
                             "%s unexpectedly carries a KCFI signature" % row["name"])
        self.assertEqual([], self.l2["importsWithKcfiSignature"])
        self.assertIn("KCFI type signature", self.l2["importKcfiRule"])
        self.assertIn("panic", self.l2["importKcfiRule"])

        # M6's cookie channel: exactly one increment on the six, recorded separately,
        # and the complete set is what O6 asserts.
        cookie = self.l2["cookieChannel"]
        self.assertEqual("param_ops_ullong", cookie["paramOps"])
        self.assertIn("cookie=0x", cookie["uargs"])
        self.assertIn("finit_module", cookie["source"])
        self.assertEqual("__param", cookie["section"])
        self.assertEqual(0, cookie["perm"])
        self.assertTrue(cookie["paramOpsExport"], "param_ops_ullong is not exported")
        self.assertEqual(["param_ops_ullong"],
                         [row["name"] for row in self.l2["importsCookieParam"]])
        self.assertEqual(["register_kprobe", "register_kretprobe",
                          "unregister_kprobe", "unregister_kretprobe", "_printk",
                          "copy_from_kernel_nofault", "param_ops_ullong"],
                         self.l2["importSetFull"])
        self.assertEqual(7, self.l2["importSetFullCount"])
        kernel_param = self.contract["structOffsets"]["kernelParam"]
        self.assertEqual(0x28, kernel_param["size"])
        self.assertEqual(0x10, kernel_param["ops"])
        self.assertEqual(0x20, kernel_param["arg"])

        lookups = [row["name"] for row in self.l2["runtimeLookups"]]
        self.assertEqual(3, len(lookups))
        self.assertEqual(LOOKUPS, set(lookups))
        self.assertEqual(3, self.l2["runtimeLookupCount"])
        for row in self.l2["runtimeLookups"]:
            self.assertFalse(row["exported"], "%s is exported: it is an import"
                             % row["name"])
            self.assertEqual("must-not-be-hardcoded", row["addressUse"])
            self.assertIn("kallsyms_lookup_name", row["resolution"])
        probes = {row["id"]: row for row in self.l2["probes"]}
        self.assertEqual({"ctl.magic", "execve.entry", "execve.ret"}, set(probes))
        self.assertEqual("kretprobe", probes["execve.ret"]["kind"])
        for row in probes.values():
            self.assertFalse(row["blacklisted"], row["symbol"])
        self.assertEqual(69, self.l2["kprobeBlacklist"]["entries"])

    def test_06_config_facts_are_the_measured_ones(self):
        config = self.l2["config"]
        for key in ("kprobes", "kretprobes", "panicOnOops", "cfi"):
            self.assertEqual("y", config[key]["value"], key)
            self.assertTrue(config[key]["satisfied"], key)
        self.assertEqual("n", config["functionTracer"]["value"])
        self.assertTrue(config["functionTracer"]["satisfied"])
        self.assertNotEqual("y", config["kprobesOnFtrace"]["value"])
        self.assertTrue(config["kprobesOnFtrace"]["satisfied"])
        self.assertIn("DYNAMIC_FTRACE", config["kprobesOnFtrace"]["why"])

    # -- every structural rule can fail ------------------------------------ #
    def test_07_field_presence_negatives_are_detected(self):
        self.assertEqual([], self.derive.validate_l2_contract(self.contract),
                         "the committed contract must validate cleanly first")

        def mutate(path, value):
            copy = json.loads(json.dumps(self.contract))
            node = copy
            parts = path.split(".")
            for part in parts[:-1]:
                node = node[part]
            node[parts[-1]] = value
            return self.derive.validate_l2_contract(copy)

        cases = [
            ("l2.module.name", "maplesu_root"),
            ("l2.imports", []),
            ("l2.importCount", 4),
            ("l2.runtimeLookups", []),
            ("l2.runtimeLookupCount", 9),
            ("l2.importsCookieParam", []),
            ("l2.importSetFull", ["register_kprobe"]),
            ("l2.importSetFullCount", 6),
            ("l2.cookieChannel.paramOps", "param_ops_int"),
            ("structOffsets.kernelParam.ops", 0x8),
            ("l2.kcfiIds.preHandler.value", "0xd9421881"),
            ("l2.kcfiMismatches", ["preHandler"]),
            ("l2.importsWithKcfiSignature", ["_printk"]),
            ("l2.config.kprobes.satisfied", False),
            ("l2.kprobeBlacklist.targets", [{"symbol": "do_execveat_common",
                                             "blacklisted": True}]),
            ("l2.gateNamespace.l2SourceChecks", []),
            ("l2.declarationCheck.cases", []),
            ("structOffsets.kretprobe.handler", 0x48),
            ("structOffsets.ptRegs.syscallno", 0x110),
            ("l2.controlAbi.ops", []),
        ]
        for path, value in cases:
            self.assertTrue(mutate(path, value),
                            "mutation %s was not detected" % path)
        copy = json.loads(json.dumps(self.contract))
        copy.pop("l2")
        self.assertTrue(self.derive.validate_l2_contract(copy))

    def test_08_gate_ids_are_s26_s40_and_o6_o10(self):
        namespace = self.l2["gateNamespace"]
        self.assertEqual(["S%d" % number for number in range(26, 41)],
                         [row["id"] for row in namespace["l2SourceChecks"]])
        self.assertEqual(["O%d" % number for number in range(6, 11)],
                         [row["id"] for row in namespace["l2ObjectChecks"]])
        hook = _load(HOOK_CONTRACT, "maplesu_hook_contract_ids")
        source_ids = {check["id"] for check in
                      hook.l2_source_checks("", module_dir=self.dir,
                                            contract=self.contract)}
        object_ids = {check["id"] for check in hook.l2_object_checks(
            self.dir / "no-such-ko")}
        self.assertEqual({"S%d" % number for number in range(26, 41)}, source_ids,
                         "hook_contract emits an L2 source id outside S26-S40")
        self.assertEqual({"O%d" % number for number in range(6, 11)}, object_ids,
                         "hook_contract emits an L2 object id outside O6-O10")

    # -- the gates-first plumbing: --module fails on the artifact, not argparse #
    def test_09_module_flag_fails_on_the_missing_artifact(self):
        result = subprocess.run(
            [sys.executable, str(BUILDER), "--verify-only", "--module", "maplesu_l2",
             "--out-dir", str(self.dir / "build"), "--quiet"],
            capture_output=True, text=True)
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("artifact missing", output)
        self.assertNotIn("unrecognized arguments", output)
        self.assertNotIn("Traceback", output)

    def test_10_good_root_module_still_passes_with_the_new_contract(self):
        if not GOOD.is_file():
            raise unittest.SkipTest("maplesu_root.ko is missing")
        out_dir = self.dir / "verify"
        out_dir.mkdir()
        shutil.copy2(GOOD, out_dir / GOOD.name)
        result = subprocess.run(
            [sys.executable, str(BUILDER), "--verify-only",
             "--out-dir", str(out_dir)],
            capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("RESULT: all gates pass", result.stdout + result.stderr)


class G11DecodeTest(unittest.TestCase):
    """G11 ① as reviewed (M7): decode movz/movk/cmp #imm, never a byte pattern."""

    @classmethod
    def setUpClass(cls):
        if not HOOK_CONTRACT.is_file():
            raise unittest.SkipTest("hook_contract.py is missing")
        cls.hook = _load(HOOK_CONTRACT, "maplesu_hook_contract_g11")
        cls.build = _load(BUILDER, "maplesu_build_g11")

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)

    def compile_tu(self, name: str, source: str, extra: list | None = None) -> Path:
        c_path, o_path = self.dir / (name + ".c"), self.dir / (name + ".o")
        c_path.write_text(source, encoding="utf-8")
        flags = ["--target=aarch64-linux-gnu", "-ffreestanding", "-nostdlib",
                 "-fno-builtin", "-O2", "-c"] + list(extra or [])
        result = subprocess.run([str(CLANG), *flags, str(c_path), "-o", str(o_path)],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr[-800:])
        return o_path

    @unittest.skipUnless(CLANG.is_file(), "the NDK clang is absent")
    def test_01_movz_and_cmp_are_decoded(self):
        o_path = self.compile_tu(
            "g11", "int magic(void) { return 453; }\n"
                   "int other(void) { return 452; }\n"
                   "int compare_magic(int x) { return x == 453; }\n")
        elf = self.build.Elf(o_path)
        code = elf.section_bytes(".text")
        hits_453 = self.hook._materialised(code, 453)
        hits_452 = self.hook._materialised(code, 452)
        self.assertTrue(hits_453, "453 is materialised by movz/cmp and was not found")
        ways = [hit["how"] for hit in hits_453]
        self.assertIn("movz", ways)
        self.assertIn("cmp #imm", ways)
        self.assertTrue(hits_452, "452 is materialised too (the control)")
        self.assertNotEqual([hit["offset"] for hit in hits_453],
                            [hit["offset"] for hit in hits_452])
        # The byte pattern the design's first version searched for is not in the
        # object at all: that is exactly why the decode requirement was mandatory.
        self.assertNotIn(b"\xc5\x01\x00\x00", o_path.read_bytes())

    @unittest.skipUnless(CLANG.is_file(), "the NDK clang is absent")
    def test_02_write_scope_census_bites_on_a_raw_store(self):
        """A bare `str x1,[x0]` is invisible to the symbol ban; the census sees it."""
        o_path = self.compile_tu(
            "raw_store",
            "void raw_store(unsigned long *p) { *p = 1UL; }\n"
            "void own_store(unsigned long *p) { static unsigned long slot; "
            "slot = *p; }\n")
        elf = self.build.Elf(o_path)
        # hook_contract's Elf is a different reader; the census needs its own class.
        hook_elf = self.hook.Elf(o_path)
        census = self.hook._l2_store_census(hook_elf)
        self.assertTrue(census["violations"],
                        "a store to a caller pointer must be a violation: %r" % census)
        self.assertTrue(any(violation["function"] == "raw_store"
                            for violation in census["violations"]), census)
        self.assertEqual([], [violation for violation in census["violations"]
                              if violation["function"] == "own_store"],
                         "a store to the module's own .bss is not a violation: %r"
                         % census)

    @unittest.skipUnless(GOOD.is_file(), "maplesu_root.ko is missing")
    def test_03_frozen_root_module_writes_only_its_own_data(self):
        census = self.hook._l2_store_census(self.hook.Elf(GOOD))
        self.assertEqual([], census["violations"], census["violations"])
        self.assertGreaterEqual(census["stores"], 1)


if __name__ == "__main__":
    unittest.main()
