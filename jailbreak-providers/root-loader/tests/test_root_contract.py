"""Host tests for the resident root module's seven loader gates (G1-G7).

What this file proves, and why each test exists:

  * the committed contract still regenerates byte-identically from the image
    (`contracts/derive_contract.py`), so no layout number in it is hand-edited;
  * the contract's numbers equal an *independent* BTF parse (the gate's parser,
    not the generator's);
  * the built `build/maplesu_root.ko` passes all seven gates and the CLI, and the
    legacy positional invocation of `loader_contract.py` still exits 0 on both
    modules it was written for;
  * every gate can go red: each negative test tampers one byte range of a *copy*
    in a temp directory and asserts exactly which gate(s) fail.  The real .ko is
    hashed before the run and re-hashed afterwards.  The canary blockers have their
    own negatives: a wrapper-only handover (the static-UMH silent no-op) fails G5, a
    relocated `subprocess_info.path` store fails G5, one planted `brk #0x8228` fails
    G6, and a wrong `subprocess_info.path` in the contract fails G7.

Run: python -m unittest discover -s jailbreak-providers/root-loader/tests
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROOT_LOADER = ROOT / "jailbreak-providers" / "root-loader"
IR_LOADER = ROOT / "jailbreak-providers" / "ir-loader"
LOADER_CONTRACT = IR_LOADER / "tests" / "loader_contract.py"
CONTRACTS = sorted((ROOT_LOADER / "contracts").glob("*.json"))
CONTRACT = CONTRACTS[0] if CONTRACTS else ROOT_LOADER / "contracts" / "missing.json"
DERIVE = ROOT_LOADER / "contracts" / "derive_contract.py"
HEADER = ROOT_LOADER / "module" / "kernel_compat.h"
IMAGE = ROOT / ".analysis" / "ace6-20261025" / "boot" / "kernel"
GOOD = ROOT_LOADER / "build" / "maplesu_root.ko"
LEGACY_KO = IR_LOADER / "build" / "maplesu_ir.ko"

GATE_IDS = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"]


def _load_loader_contract():
    spec = importlib.util.spec_from_file_location("maplesu_loader_contract",
                                                  LOADER_CONTRACT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loader_contract = _load_loader_contract()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RootContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (LOADER_CONTRACT, CONTRACT, DERIVE, HEADER, IMAGE, GOOD,
                     LEGACY_KO):
            if not path.is_file():
                raise unittest.SkipTest("missing input: %s" % path)
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.elf = loader_contract.Elf(GOOD)
        cls.good_bytes = GOOD.read_bytes()
        cls.sha_before = _sha256(cls.good_bytes)

    @classmethod
    def tearDownClass(cls):
        after = _sha256(GOOD.read_bytes())
        if after != cls.sha_before:
            raise AssertionError("a test modified the real maplesu_root.ko: "
                                 "%s != %s" % (after, cls.sha_before))

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)

    # -- helpers ----------------------------------------------------------- #
    def write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def gates(self, data=None, module_path=None, contract_path=None,
              header_path=None):
        path = module_path or self.write("mutated.ko", data)
        return loader_contract.run_gates(path, IMAGE, contract_path or CONTRACT,
                                         root=True, header_path=header_path)

    @staticmethod
    def failed(result) -> list:
        return [gate["id"] for gate in result["gates"] if not gate["ok"]]

    @staticmethod
    def detail(result, gate_id: str) -> str:
        for gate in result["gates"]:
            if gate["id"] == gate_id:
                return gate["detail"]
        raise AssertionError("no gate %s in the result" % gate_id)

    def btf_member(self, struct_name: str, member: str) -> int:
        btf = loader_contract._load_btf(IMAGE, IMAGE.read_bytes(),
                                        self.contract["btf"]["magicOffset"])
        return loader_contract._Btf.member(btf.struct(struct_name),
                                           member)["byte"]

    # -- the contract is still derived, not typed -------------------------- #
    def test_01_contract_regenerates_byte_identically(self):
        output = self.dir / "regenerated.json"
        result = subprocess.run([sys.executable, str(DERIVE), "--out",
                                 str(output), "--quiet"],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(_sha256(CONTRACT.read_bytes()), _sha256(output.read_bytes()),
                         "the committed contract is stale: regenerate it with "
                         "contracts/derive_contract.py --out %s" % CONTRACT)

    def test_02_contract_layout_claims_match_independent_btf(self):
        btf = loader_contract._load_btf(IMAGE, IMAGE.read_bytes(),
                                        self.contract["btf"]["magicOffset"])
        module = btf.struct("module")
        self.assertEqual(self.contract["thisModule"]["size"], module["size"])
        for member, key in (("name", "nameOffset"), ("init", "initOffset"),
                            ("exit", "exitOffset")):
            self.assertEqual(self.contract["thisModule"][key],
                             loader_contract._Btf.member(module, member)["byte"])
        self.assertEqual(sorted(entry[0] for entry in btf.structs("module")),
                         self.contract["thisModule"]["allBtfTypeIds"])
        kprobe = btf.struct("kprobe")
        self.assertEqual(self.contract["kprobe"]["size"], kprobe["size"])
        self.assertEqual(self.contract["kprobe"]["addrOffset"],
                         loader_contract._Btf.member(kprobe, "addr")["byte"])
        self.assertEqual(self.contract["kprobe"]["symbolNameOffset"],
                         loader_contract._Btf.member(kprobe,
                                                     "symbol_name")["byte"])
        selinux = btf.struct("selinux_state")
        self.assertEqual(self.contract["selinuxState"]["size"], selinux["size"])
        self.assertEqual(self.contract["selinuxState"]["enforcingOffset"],
                         loader_contract._Btf.member(selinux,
                                                     "enforcing")["byte"])
        self.assertEqual(len(btf.types) - 1, self.contract["btf"]["numTypes"])

    # -- the artifact passes ------------------------------------------------ #
    def test_03_good_module_passes_all_seven_gates(self):
        result = self.gates(module_path=GOOD)
        failures = [(gate["id"], gate["detail"]) for gate in result["gates"]
                    if not gate["ok"]]
        self.assertTrue(result["ok"], failures)
        self.assertEqual(GATE_IDS, [gate["id"] for gate in result["gates"]])
        for gate in result["gates"]:
            self.assertTrue(gate["detail"], "%s has no detail" % gate["id"])
            self.assertGreaterEqual(
                len([check for check in gate["checks"] if check["fatal"]]), 1,
                "%s recorded no fatal check" % gate["id"])
            self.assertFalse(gate.get("skipped"), "%s must not be skipped" % gate["id"])
        self.assertEqual(["_printk", "call_usermodehelper", "register_kprobe",
                          "unregister_kprobe"], result["imports"])
        self.assertEqual("all gates pass", result["result"])
        plan = result["patchPlan"]
        self.assertIsNotNone(plan, "G5 did not produce a symbolic patch plan")
        self.assertEqual(5, len(plan["steps"]))
        self.assertEqual([1, 2, 3, 4, 5], [step["step"] for step in plan["steps"]])
        self.assertEqual(1, plan["steps"][3]["wait"])

    def test_04_cli_root_mode_writes_json(self):
        output = self.dir / "gates.json"
        result = subprocess.run(
            [sys.executable, str(LOADER_CONTRACT), "--root", str(GOOD),
             "--image", str(IMAGE), "--contract", str(CONTRACT),
             "--json", str(output)], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        for gate_id in GATE_IDS:
            self.assertIn("[%s]" % gate_id, result.stdout)
        self.assertIn("RESULT: all gates pass", result.stdout)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(GATE_IDS, [gate["id"] for gate in payload["gates"]])
        self.assertEqual(4, len(payload["imports"]))

    def test_05_legacy_positional_cli_still_passes(self):
        for module in (LEGACY_KO, GOOD):
            result = subprocess.run([sys.executable, str(LOADER_CONTRACT),
                                     str(module), str(IMAGE)],
                                    capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("RESULT: every pre-init loader check passes",
                          result.stdout)
            self.assertIn("this_module 0x600", result.stdout)

    # -- negatives: every gate must bite ------------------------------------ #
    def test_10_g1_negative_this_module_name(self):
        data = bytearray(self.good_bytes)
        section = self.elf.by_name(".gnu.linkonce.this_module")
        offset = section["offset"] + self.btf_member("module", "name")
        self.assertEqual(b"maplesu_root\x00", bytes(data[offset:offset + 13]))
        data[offset:offset + 12] = b"maplesu_rooX"
        result = self.gates(bytes(data))
        self.assertFalse(result["ok"])
        self.assertEqual(["G1"], self.failed(result))
        self.assertIn("module name embedded", self.detail(result, "G1"))

    def test_11_g2_negative_plt_section_renamed(self):
        data = self.good_bytes
        self.assertEqual(1, data.count(b"\x00.plt\x00"))
        result = self.gates(data.replace(b"\x00.plt\x00", b"\x00.plX\x00"))
        self.assertFalse(result["ok"])
        self.assertEqual(["G2"], self.failed(result))
        self.assertIn(".plt exists exactly once", self.detail(result, "G2"))

    def test_12_g3_negative_import_renamed(self):
        data = self.good_bytes
        self.assertEqual(1, data.count(b"\x00register_kprobe\x00"))
        result = self.gates(data.replace(b"\x00register_kprobe\x00",
                                         b"\x00register_kprobX\x00"))
        self.assertFalse(result["ok"])
        self.assertEqual(["G3"], self.failed(result))
        self.assertIn("deliberate imports are present", self.detail(result, "G3"))

    def test_13_g4_negative_cleanup_module_renamed(self):
        data = self.good_bytes
        self.assertEqual(1, data.count(b"\x00cleanup_module\x00"))
        result = self.gates(data.replace(b"\x00cleanup_module\x00",
                                         b"\x00cleanup_modulX\x00"))
        self.assertFalse(result["ok"])
        # G1 loses the exit relocation target and G6 can no longer read the
        # prefix of a symbol that no longer exists; all three are real.
        self.assertEqual(["G1", "G4", "G6"], self.failed(result))
        self.assertIn("cleanup_module is defined", self.detail(result, "G4"))

    def test_14_g5_negative_umh_wait_proc(self):
        data = bytearray(self.good_bytes)
        section = self.elf.by_name(".init.text")
        patched = 0
        for offset in range(section["offset"], section["offset"] + section["size"], 4):
            if struct.unpack_from("<I", data, offset)[0] == 0x52800023:  # mov w3,#1
                struct.pack_into("<I", data, offset, 0x52800043)          # mov w3,#2
                patched += 1
                break
        self.assertEqual(1, patched, "no `mov w3, #1` in .init.text")
        result = self.gates(bytes(data))
        self.assertFalse(result["ok"])
        self.assertEqual(["G5"], self.failed(result))
        self.assertIn("UMH_WAIT_PROC", self.detail(result, "G5"))

    def test_15_g5_negative_planted_kernel_va(self):
        data = bytearray(self.good_bytes)
        section = self.elf.by_name(".rodata")
        struct.pack_into("<Q", data, section["offset"], 0xFFFFFFC080000000)
        result = self.gates(bytes(data))
        self.assertFalse(result["ok"])
        self.assertEqual(["G5"], self.failed(result))
        self.assertIn("kernel virtual address", self.detail(result, "G5"))

    def test_16_g5_negative_helper_path(self):
        # Step-3 (D-5/D3-3): the module constant is the contract's policy path, so the
        # negative mutates exactly that string (one byte inside the basename) instead of
        # the pre-D-5 `maplesu-bootstrap` name. A third path must always be red.
        needle = self.contract["helperPathPolicy"]["policyPath"].encode()
        self.assertEqual(1, self.good_bytes.count(needle),
                         "the module carries %r exactly once" % needle)
        data = self.good_bytes.replace(needle, needle[:-1] + b"X")
        result = self.gates(data)
        self.assertFalse(result["ok"])
        self.assertEqual(["G5"], self.failed(result))
        self.assertIn("helper path agrees with the contract's D-5 record",
                      self.detail(result, "G5"))

    def test_17_g6_negative_init_kcfi_prefix(self):
        data = bytearray(self.good_bytes)
        symbol = next(entry for entry in loader_contract._elf_symbols(self.elf)
                      if entry["name"] == "init_module" and entry["shndx"])
        section = self.elf.sections[symbol["shndx"]]
        struct.pack_into("<I", data, section["offset"] + symbol["value"] - 4,
                         0xDEADBEEF)
        result = self.gates(bytes(data))
        self.assertFalse(result["ok"])
        self.assertEqual(["G6"], self.failed(result))
        self.assertIn("init_module's KCFI prefix", self.detail(result, "G6"))

    def test_18_g7_negative_wrong_contract_offset(self):
        wrong = json.loads(CONTRACT.read_text(encoding="utf-8"))
        wrong["thisModule"]["nameOffset"] = 0x20
        contract_path = self.dir / "contract-wrong-offset.json"
        contract_path.write_text(json.dumps(wrong, indent=2, ensure_ascii=True) + "\n",
                                 encoding="utf-8")
        result = self.gates(module_path=GOOD, contract_path=contract_path,
                            header_path=HEADER)
        self.assertFalse(result["ok"])
        self.assertEqual(["G7"], self.failed(result))
        self.assertIn("contract nameOffset", self.detail(result, "G7"))

    def test_19_g7_negative_wrong_header_assert(self):
        text = HEADER.read_text(encoding="utf-8")
        old = "_Static_assert(sizeof(struct maplesu_kprobe) == 0x80"
        self.assertEqual(1, text.count(old))
        header = self.dir / "kernel_compat.h"
        header.write_text(text.replace(old, old[:-2] + "78"), encoding="utf-8")
        result = self.gates(module_path=GOOD, header_path=header)
        self.assertFalse(result["ok"])
        self.assertEqual(["G7"], self.failed(result))
        self.assertIn("kernel_compat.h sizeof(maplesu_kprobe)",
                      self.detail(result, "G7"))

    # -- the canary blockers: static-UMH handover, zero traps, the shim ------ #
    def test_20_g5_negative_wrapper_only_handover(self):
        """A module that only calls the four-argument wrapper must fail G5.

        On this kernel CONFIG_STATIC_USERMODEHELPER_PATH="" makes that call a silent
        no-op (setup() replaces the path with "", exec() returns 0 without forking), so
        "handover started; resident" from such a module is a false positive. The gate
        detects the missing two-stage handover by the two runtime lookup names the
        fix cannot work without.
        """
        data = self.good_bytes
        self.assertEqual(1, data.count(b"call_usermodehelper_setup\x00"))
        self.assertEqual(1, data.count(b"call_usermodehelper_exec\x00"))
        mutated = (data.replace(b"call_usermodehelper_setup\x00",
                                b"call_usermodehelper_setuX\x00")
                       .replace(b"call_usermodehelper_exec\x00",
                                b"call_usermodehelper_exeX\x00"))
        result = self.gates(mutated)
        self.assertFalse(result["ok"])
        self.assertEqual(["G5"], self.failed(result))
        self.assertIn("resolves call_usermodehelper_setup/_exec",
                      self.detail(result, "G5"))

    def test_21_g5_negative_missing_path_store(self):
        """The `str xN,[xM,#0x38]` that restores subprocess_info.path is the fix."""
        data = bytearray(self.good_bytes)
        section = self.elf.by_name(".init.text")
        patched = 0
        for offset in range(section["offset"], section["offset"] + section["size"], 4):
            insn = struct.unpack_from("<I", data, offset)[0]
            if (insn & 0xFFC00000) == 0xF9000000 and ((insn >> 10) & 0xFFF) * 8 == 0x38:
                # same store, wrong field: +0x40 instead of +0x38
                struct.pack_into("<I", data, offset,
                                 (insn & ~(0xFFF << 10)) | (8 << 10))
                patched += 1
        self.assertEqual(1, patched, "no store at subprocess_info.path (+0x38)")
        result = self.gates(bytes(data))
        self.assertFalse(result["ok"])
        self.assertEqual(["G5"], self.failed(result))
        self.assertIn("stores the helper pointer at subprocess_info.path",
                      self.detail(result, "G5"))

    def test_22_g6_negative_planted_brk(self):
        """One BRK anywhere in module text is a panic on this image (panic_on_oops)."""
        data = bytearray(self.good_bytes)
        section = self.elf.by_name(".text")
        # Step-3: cleanup_module now ends with its restore-evidence printk, so the last
        # .text word is a tail branch to _printk (it used to be a bare `ret`). The
        # premise of this test is "one word inside .text that no other gate keys on",
        # not "a ret": the final word still satisfies it, and the branch relocation that
        # points at it stays a branch relocation either way.
        last = section["offset"] + section["size"] - 4
        insn = struct.unpack_from("<I", data, last)[0]
        self.assertTrue(insn & 0xFC000000 == 0x14000000 or insn == 0xD65F03C0,
                        "the last .text word is neither a bare RET nor a tail branch: "
                        "0x%08x" % insn)
        struct.pack_into("<I", data, last, 0xD4304500)
        result = self.gates(bytes(data))
        self.assertFalse(result["ok"])
        self.assertEqual(["G6"], self.failed(result))
        self.assertIn("zero BRK instructions", self.detail(result, "G6"))

    def test_23_g7_negative_wrong_subprocess_info_offset(self):
        """A wrong subprocess_info.path offset would corrupt a kernel object."""
        wrong = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(0x38, wrong["structOffsets"]["subprocessInfo"]["path"])
        wrong["structOffsets"]["subprocessInfo"]["path"] = 0x40
        wrong["handover"]["primaryPath"]["pathOffset"] = 0x40
        contract_path = self.dir / "contract-wrong-subprocess-offset.json"
        contract_path.write_text(json.dumps(wrong, indent=2, ensure_ascii=True) + "\n",
                                 encoding="utf-8")
        result = self.gates(module_path=GOOD, contract_path=contract_path,
                            header_path=HEADER)
        self.assertFalse(result["ok"])
        # G7 owns the shim-vs-BTF comparison; G5 also goes red because the store it
        # looks for is now at a different offset -- both statements are true.
        self.assertIn("G7", self.failed(result))
        self.assertIn("BTF offsetof(subprocess_info, path) == contract",
                      self.detail(result, "G7"))

    def test_24_g5_plan_names_the_two_stage_handover(self):
        result = self.gates(module_path=GOOD)
        self.assertTrue(result["ok"], self.failed(result))
        plan = result["patchPlan"]
        step4 = plan["steps"][3]
        self.assertIn("call_usermodehelper_setup", step4["via"])
        self.assertIn("call_usermodehelper_exec", step4["via"])
        self.assertEqual(0x38, step4["pathOffset"])
        self.assertEqual("UMH_WAIT_EXEC", step4["waitName"])
        self.assertEqual("call_usermodehelper", step4["fallbackVia"])
        for gate in result["gates"]:
            if gate["id"] == "G5":
                self.assertEqual("setup-exec", gate["extras"]["handoverMode"])
                self.assertEqual([], gate["extras"]["umhPrimary"]["missing"])
            if gate["id"] == "G6":
                self.assertEqual({}, gate["extras"]["traps"])
                self.assertEqual([], gate["extras"]["kcfiSites"])

    def test_25_source_carries_nocfi_on_every_indirect_caller(self):
        source = (ROOT_LOADER / "module" / "maplesu_root.c").read_text(encoding="utf-8")
        for function in ("maplesu_sym", "maplesu_patch_return_zero", "init_module"):
            self.assertTrue(loader_contract._nocfi_covers(source, function),
                            "%s lost MAPLESU_NOCFI: an indirect call through a "
                            "runtime-resolved address would get a KCFI check back"
                            % function)
        # The vendor step is compiled out by default (P3b): a `0` default and the
        # `#if` around the handler block are what keep aarch64_insn_patch_text out of
        # the canary binary.
        self.assertIn("#define MAPLESU_PATCH_VENDOR_HANDLERS 0", source)
        self.assertIn("#if MAPLESU_PATCH_VENDOR_HANDLERS", source)

    def test_26_artifact_carries_one_modinfo_and_zero_brk(self):
        """The two step-1 must-fix items, asserted on the committed .ko itself."""
        sections = [section for section in self.elf.sections
                    if section["name"] == ".modinfo"]
        self.assertEqual(1, len(sections), "the loader rejects a module with two "
                                          ".modinfo sections")
        tags = loader_contract._modinfo_tags(
            loader_contract._Context(GOOD, IMAGE, self.contract, CONTRACT))
        self.assertEqual("GPL", tags.get("license"))
        self.assertEqual(self.contract["vermagic"], tags.get("vermagic"))
        self.assertEqual("maplesu_root", tags.get("name"))
        self.assertIn("depends", tags)
        brks = []
        for section in self.elf.sections:
            if not section["flags"] & 0x4:              # SHF_EXECINSTR
                continue
            blob = self.elf.raw[section["offset"]:
                               section["offset"] + section["size"]]
            for index in range(len(blob) // 4):
                insn = struct.unpack_from("<I", blob, index * 4)[0]
                if (insn & 0xFFE0001F) == 0xD4200000:
                    brks.append("%s+0x%x" % (section["name"], index * 4))
        self.assertEqual([], brks, "a BRK in module text is a panic on this image "
                                   "(panic_on_oops=1, no CFI_PERMISSIVE)")

    # -- step-4 (D5): the module only writes back the window it opened ---------- #
    def test_27_cleanup_module_skips_an_inherited_window(self):
        """D4-4/D5: `saved == 0` means the window was open before this module loaded.

        Writing the inherited byte back is not a restore - it overwrites the helper's
        App-supplied target with 0, which is exactly how step-3's kernel-side "restore"
        came to describe 0. The shape is asserted at the source level because the branch
        is only reachable on a device with the dfroot chain in front of it.
        """
        source = (ROOT_LOADER / "module" / "maplesu_root.c").read_text(encoding="utf-8")

        def body(name: str) -> str | None:
            """The brace-balanced body of a top-level C function in this source."""
            pattern = re.compile(r"(?m)^[A-Za-z_][^\n;{}]*?(?<![A-Za-z0-9_])" +
                                 re.escape(name) + r"\s*\(")
            for match in pattern.finditer(source):
                brace = source.find("{", match.end())
                statement = source.find(";", match.end())
                if brace < 0 or (0 <= statement < brace):
                    continue
                depth = 0
                for position in range(brace, len(source)):
                    if source[position] == "{":
                        depth += 1
                    elif source[position] == "}":
                        depth -= 1
                        if depth == 0:
                            return source[brace:position + 1]
            return None

        cleanup = body("cleanup_module")
        self.assertIsNotNone(cleanup, "cleanup_module is still a definition")
        self.assertIn("maplesu_saved_enforcing == 0", cleanup,
                      "cleanup_module must branch on an inherited window")
        self.assertIn("cleanup skipped (window inherited)", cleanup,
                      "the skipped rung has to name itself in the ring buffer")
        restore = body("maplesu_restore_enforcing")
        self.assertIsNotNone(restore)
        self.assertIn("maplesu_saved_enforcing == 0", restore,
                      "the shared restore helper must refuse an inherited value, so "
                      "every caller (including the init failure paths) inherits the rule")
        self.assertIn("own_window=%d", source,
                      "the init printk must state whether the module owned the window")
        handover = self.contract["handover"]
        self.assertIn("entryBaseline", handover)
        self.assertEqual("maplesu.hook.env.v1", handover["entryBaseline"]["schema"])
        self.assertEqual(["schema", "boot", "attempt", "expected", "source"],
                         handover["entryBaseline"]["keys"])
        self.assertEqual("enforce_before==1",
                         handover["entryBaseline"]["neverWriteZeroWhen"])
        self.assertEqual(["decide", "fork", "delete_module", "readback_post",
                          "write_if_needed", "readback_final", "klog", "record"],
                         handover["restoreOrder"]["steps"])


if __name__ == "__main__":
    unittest.main()
