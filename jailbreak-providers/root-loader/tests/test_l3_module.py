#!/usr/bin/env python3
"""Host tests for the L3 artifact: the build, and every gate's ability to be red.

Why each test exists
--------------------
  * the build runs end to end, both engines green, and the published bytes are
    deterministic (two builds, one sha256) -- a gate suite that only runs inside
    the build cannot show that;
  * every L3 gate is shown to fail on a mutation: a flipped KCFI prefix (L3-1), a
    fourth undefined symbol (L3-2), a `/data/` literal (L3-3), a callback that
    moved to .init.text (L3-4), a BRK in module text (L3-5), a cleanup path that
    no longer unregisters (L3-6), a build whose -D facts or ABI v2 constant
    disagree with the image (L3-7), a printk that would carry the token (L3-8), a
    registration name that is not `__arm64_sys_prctl` (L3-9), an ARM branch
    without the enforcing gate (L3-10), and a callback that writes the probed
    frame or returns something other than 0 (L3-11). A gate that cannot be red is
    not a gate, and this file is where that is measured instead of asserted;
  * the root module's bytes are pinned here too, because the L3 round touched the
    shared builder: `--module maplesu_root` must still produce the same .ko it
    produced before any L3 change (byte-identical, 9712 bytes).

No device, no adb, no module load. Every artifact written by a test lives in a
temporary directory.

Run: python -m unittest discover -s jailbreak-providers/root-loader/tests -p "test_l3_*.py"
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROOT_LOADER = ROOT / "jailbreak-providers" / "root-loader"
BUILDER_PATH = ROOT_LOADER / "build_root_module.py"
CONTRACTS = sorted((ROOT_LOADER / "contracts").glob("6.6.89-*.json"))
CONTRACT = CONTRACTS[0] if CONTRACTS else ROOT_LOADER / "contracts" / "missing.json"
IMAGE = ROOT / ".analysis" / "ace6-20261025" / "boot" / "kernel"
PYTHON = sys.executable

# The .ko this round must keep producing for maplesu_root (clang 19.0.1 from
# NDK r28c (28.2.13676358), the pinned toolchain), recorded by building
# the module before the L3 change landed.
ROOT_FROZEN_SHA256 = \
    "a8dffe06010e23d218117487b0f3743c2cacfd1041c173d6d19bb3dc294c585b"
ROOT_FROZEN_BYTES = 9712


def _load_builder():
    spec = importlib.util.spec_from_file_location("maplesu_builder_l3_test",
                                                  BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = _load_builder()


def _run(args: list, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run([PYTHON, str(BUILDER_PATH), *args], cwd=str(cwd),
                          capture_output=True, text=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class L3BuildTest(unittest.TestCase):
    """Build the artifact once; every later test reads this record."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="maplesu-l3-test-"))
        cls.out_dir = cls.tmp / "l3"
        cls.result = _run(["--module", "maplesu_l3", "--contract",
                           str(CONTRACT), "--out-dir", str(cls.out_dir)])
        cls.record = None
        record_path = cls.out_dir / "build.json"
        if record_path.is_file():
            cls.record = json.loads(record_path.read_text(encoding="utf-8"))
        cls.module = cls.out_dir / "maplesu_l3.ko"
        # The reference TU's ids, measured once for the whole class: the same
        # function L3-1 uses (and the builder used), cached per process.
        cls.callbacks = BUILDER.kprobe_callback_ids()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _context(self, module: Path, cflags=None, source: str | None = None):
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        # The build's own rendered header and recorded -D flags: G6/G7/L3-1/L3-7
        # judge what the compiler saw, so a test that omits them is testing a
        # different build than the one under test.
        header = self.out_dir / "kernel_compat_family.h"
        context = BUILDER.VerifyContext(
            module, contract, CONTRACT, IMAGE, BUILDER.Log(echo=False),
            cflags=list(cflags) if cflags is not None else list(self.record["cflags"]),
            module_key="maplesu_l3",
            header_path=header if header.is_file() else None,
            l3_callbacks=self.callbacks)
        if source is not None:
            context.source = source
        return context

    def _red(self, module: Path, cflags=None, source: str | None = None) -> list:
        outcome = BUILDER.run_internal_gates(
            self._context(module, cflags=cflags, source=source))
        return [gate["id"] for gate in outcome["gates"] if not gate["ok"]]

    def _mutated(self, name: str) -> Path:
        target = self.tmp / (name + ".ko")
        target.write_bytes(self.module.read_bytes())
        return target

    def _symbol_entry_offset(self, elf, name: str) -> tuple[int, int]:
        """(index, symtab file offset) of one symbol row."""
        index = next(i for i, symbol in enumerate(elf.symbols)
                     if symbol["name"] == name)
        symtab = next(section for section in elf.sections
                      if section["type"] == BUILDER.SHT_SYMTAB)
        return index, symtab["offset"] + index * 24

    # -- the build itself -------------------------------------------------- #
    def test_01_build_is_green_through_both_engines(self):
        self.assertEqual(0, self.result.returncode,
                         self.result.stdout + self.result.stderr)
        self.assertIn("RESULT: all gates pass", self.result.stdout)
        self.assertIn("loader_contract.run_gates(root=False, module=maplesu_l3): "
                      "PASS", self.result.stdout)
        self.assertTrue(self.module.is_file())
        gates = {gate["id"]: gate["ok"] for gate in self.record["gates"]}
        self.assertEqual({"G1", "G2", "G3", "G4", "G5", "G6", "G7",
                          "L3-1", "L3-2", "L3-3", "L3-4", "L3-5", "L3-6",
                          "L3-7", "L3-8", "L3-9", "L3-10", "L3-11", "L3-12"}, set(gates))
        self.assertTrue(all(gates.values()), gates)

    def test_root_subject_gate_rejects_missing_marker_uid_and_cleanup(self):
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        for old, new in (
                ("== maplesu_groups", "!= maplesu_groups"),
                ("MAPLESU_CRED_EUID_OFF) == 0 &&", "MAPLESU_CRED_EUID_OFF) != 0 &&"),
                ("unregister_kprobe(&maplesu_avc_probe)", "/* removed */")):
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                self.assertIn("L3-12", self._red(self.module, source=source.replace(old, new)))

    def test_root_subject_gate_rejects_wrong_callback_prefix(self):
        mutated = self._mutated("avc-prefix")
        elf = BUILDER.Elf(mutated)
        offset = elf.symbol_file_offset(elf.symbol("maplesu_avc_pre")) - 4
        data = bytearray(mutated.read_bytes())
        data[offset] ^= 1
        mutated.write_bytes(data)
        self.assertIn("L3-12", self._red(mutated))

    def test_02_build_is_deterministic(self):
        second = self.tmp / "l3-second"
        result = _run(["--module", "maplesu_l3", "--contract", str(CONTRACT),
                       "--out-dir", str(second), "--quiet"])
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(_sha256(self.module), _sha256(second / "maplesu_l3.ko"))

    def test_03_image_facts_are_what_the_module_was_built_from(self):
        facts = self.record["imageFacts"]
        self.assertEqual("kprobe_breakpoint_handler", facts["kprobe"]["symbol"])
        self.assertEqual("0x106864c", facts["kprobe"]["address"])
        self.assertEqual(["0x36183889", "0x6e21b9c7", "0xa6be5dd9"],
                         facts["kprobe"]["cfiTypeIds"])
        self.assertEqual({"preHandler": "0xa6be5dd9",
                          "postHandler": "0x6e21b9c7"}, facts["callbackPins"])
        self.assertEqual({"preHandler": "0xa6be5dd9",
                          "postHandler": "0x6e21b9c7"},
                         facts["contractCallbacks"])
        self.assertEqual("__arm64_sys_prctl", facts["probedSymbol"]["symbol"])
        self.assertEqual("0xd503233f", facts["probedSymbol"]["entryInstruction"])
        self.assertEqual(1, facts["credSource"]["source"])
        self.assertEqual("kernel/cred.c", facts["credSource"]["nullBranch"]["file"])
        self.assertEqual("0x80", facts["callbackSize"])
        self.assertEqual({"credSource": 1, "preKcfiId": 0xA6BE5DD9,
                          "kprobeSize": 0x80}, facts["injectedFlags"])
        self.assertEqual(["module"],
                         self.record["gateResult"]["contractView"]["changedFields"])
        self.assertEqual("kprobe", self.record["abi"]["entry"])
        # ABI v2, restated against the published record: option 4 is
        # PR_SET_DUMPABLE, the ops are its two accepted arg2 values, the magic is
        # the token halves, and the syscall's return value is not rewritten.
        self.assertEqual("maplesu-l3-abi/2", self.record["abi"]["schema"])
        self.assertEqual(2, self.record["abi"]["version"])
        self.assertEqual("0x00000004", self.record["abi"]["option"])
        self.assertEqual("PR_SET_DUMPABLE", self.record["abi"]["optionName"])
        self.assertEqual(0, self.record["abi"]["opArm"])
        self.assertEqual(1, self.record["abi"]["opSu"])
        self.assertEqual(64, self.record["abi"]["pool"])
        self.assertEqual("(arg3 | arg4) != 0", self.record["abi"]["magic"])
        self.assertIn("unchanged", self.record["abi"]["returnValue"])
        self.assertEqual("armed owner=%u pool=%u",
                         self.record["abi"]["evidenceGateFormat"])
        safety = self.record["abi"]["frameSafety"]
        self.assertEqual("const", safety["framePointers"])
        self.assertEqual(0, safety["stores"])
        self.assertEqual([], safety["nonConstCasts"])
        self.assertIsNone(self.record["abi"]["evidenceTokenFormat"],
                          "the kernel prints no token, so there is no kernel "
                          "token format to record")

    def test_04_verify_only_still_judges_the_published_artifact(self):
        result = _run(["--module", "maplesu_l3", "--verify-only", "--contract",
                       str(CONTRACT), "--out-dir", str(self.out_dir)])
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("RESULT: all gates pass", result.stdout)
        # The artifact's own 4 bytes, read by L3-1: on this family the toolchain's
        # id and the image's dispatch id are the same number, so verify-only sees
        # it in front of maplesu_l3_pre without a rewrite.
        self.assertIn("artifact carries 0x%08x" % 0xA6BE5DD9, result.stdout)

    # -- each gate can be red ---------------------------------------------- #
    def test_05_l3_1_handler_prefix_must_be_the_reference_id(self):
        target = self._mutated("bad-prefix")
        data = bytearray(target.read_bytes())
        elf = BUILDER.Elf(target)
        offset = elf.symbol_file_offset(elf.symbol("maplesu_l3_pre"))
        data[offset - 4:offset] = (0xDEADBEEF).to_bytes(4, "little")
        target.write_bytes(bytes(data))
        self.assertIn("L3-1", self._red(target))
        # The -D the compiler saw is a second, independent statement.
        cflags = [flag for flag in self.record["cflags"]
                  if not flag.startswith("-DMAPLESU_L3_PRE_KCFI_ID=")]
        self.assertIn("L3-1", self._red(self.module, cflags=cflags))

    def test_06_l3_2_a_fourth_import_is_red(self):
        target = self._mutated("fourth-import")
        elf = BUILDER.Elf(target)
        index, at = self._symbol_entry_offset(elf, "maplesu_deny")
        data = bytearray(target.read_bytes())
        struct.pack_into("<H", data, at + 6, 0)      # st_shndx = SHN_UNDEF
        target.write_bytes(bytes(data))
        red = self._red(target)
        self.assertIn("L3-2", red)
        self.assertIn("maplesu_deny", BUILDER.Elf(target).imports())

    def test_07_l3_3_no_data_literal(self):
        target = self._mutated("data-literal")
        data = bytearray(target.read_bytes())
        needle = b"commit_creds\x00"
        at = bytes(data).find(needle)
        self.assertGreater(at, 0, "the module no longer carries the literal")
        data[at:at + len(needle)] = b"/data/AAAAAA\x00"
        target.write_bytes(bytes(data))
        self.assertIn("L3-3", self._red(target))

    def test_08_l3_3_no_write_primitive_by_name(self):
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        mutated = source + (
            "\nextern int set_memory_rw(unsigned long addr, int numpages);\n"
            "static void maplesu_write_probe(void)\n"
            "{\n\t(void)set_memory_rw(0, 1);\n}\n")
        self.assertNotEqual(source, mutated)
        self.assertIn("L3-3", self._red(self.module, source=mutated))

    def test_09_l3_4_handler_must_not_be_in_init_text(self):
        target = self._mutated("handler-in-init")
        elf = BUILDER.Elf(target)
        index, at = self._symbol_entry_offset(elf, "maplesu_l3_pre")
        init_index = next(section["index"] for section in elf.sections
                          if section["name"] == ".init.text")
        data = bytearray(target.read_bytes())
        struct.pack_into("<H", data, at + 6, init_index)
        target.write_bytes(bytes(data))
        self.assertIn("L3-4", self._red(target))

    def test_10_l3_5_zero_brk(self):
        target = self._mutated("brk")
        elf = BUILDER.Elf(target)
        text = next(section for section in elf.sections
                    if section["name"] == ".text")
        data = bytearray(target.read_bytes())
        # The callback's `paciasp`: replacing it with `brk #0` leaves the prefix
        # and the section in place, so only the trap count moves.
        struct.pack_into("<I", data, text["offset"] + 8, 0xD4200000)
        target.write_bytes(bytes(data))
        self.assertIn("L3-5", self._red(target))

    def test_11_l3_6_cleanup_must_unregister_the_kprobe(self):
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        # Mutate the *cleanup* body only: init_module carries the same statement on
        # its failure paths, and a mutation that hits those would not be testing the
        # gate at all.
        body = BUILDER.function_body(source, "cleanup_module")
        self.assertTrue(body)
        mutated_body = body.replace(
            "unregister_kprobe(&maplesu_probe);",
            "/* the unregister was removed */", 1)
        self.assertNotEqual(body, mutated_body)
        mutated = source.replace(body, mutated_body, 1)
        self.assertNotEqual(source, mutated)
        self.assertIn("L3-6", self._red(self.module, source=mutated))

    def test_12_l3_7_the_injected_facts_and_constants_must_match(self):
        for prefix, gate in (("-DMAPLESU_CRED_SOURCE=", "L3-7"),
                             ("-DMAPLESU_L3_KPROBE_SIZE=", "L3-7"),
                             ("-DMAPLESU_L3_PRE_KCFI_ID=", "L3-1")):
            cflags = [flag for flag in self.record["cflags"]
                      if not flag.startswith(prefix)]
            self.assertIn(gate, self._red(self.module, cflags=cflags), prefix)
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        self.assertIn("#define MAPLESU_L3_POOL\t\t64u", source)
        mutated = source.replace("#define MAPLESU_L3_POOL\t\t64u",
                                 "#define MAPLESU_L3_POOL\t\t63u", 1)
        self.assertNotEqual(source, mutated)
        self.assertIn("L3-7", self._red(self.module, source=mutated))
        # ABI v2's own numbers: the option (PR_SET_DUMPABLE = 4) and the two ops
        # are the constants this build was compiled with.
        self.assertIn("#define MAPLESU_L3_OPTION\t4u", source)
        for needle, replacement in (
                ("#define MAPLESU_L3_OPTION\t4u",
                 "#define MAPLESU_L3_OPTION\t5u"),
                ("#define MAPLESU_L3_OP_ARM\t0u",
                 "#define MAPLESU_L3_OP_ARM\t3u"),
                ("#define MAPLESU_L3_OP_SU\t1u",
                 "#define MAPLESU_L3_OP_SU\t2u")):
            mutated = source.replace(needle, replacement, 1)
            self.assertNotEqual(source, mutated, needle)
            self.assertIn("L3-7", self._red(self.module, source=mutated), needle)
        # The retired v1 magic is refused: a source that can answer 0x4D535503 is
        # a source that answers an ABI the controller no longer runs.
        retired = source + "\n#define MAPLESU_L3_V1_OPTION\t0x4D535503u\n"
        self.assertIn("L3-7", self._red(self.module, source=retired))

    def test_13_l3_8_no_token_in_printk(self):
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        needle = '\t\t_printk(MAPLESU_TAG "armed owner=%u pool=%u\\n",'
        self.assertIn(needle, source)
        # A second printk that carries the token: the ARM evidence line stays
        # byte-for-byte intact, so the only rule this mutation breaks is "the
        # token never reaches the ring buffer".
        mutated = source.replace(
            needle,
            '\t\t_printk(MAPLESU_TAG "suToken=%016llx\\n",\n'
            '\t\t\t(unsigned long long)token);\n' + needle, 1)
        self.assertNotEqual(source, mutated)
        self.assertIn("L3-8", self._red(self.module, source=mutated))

    def test_14_l3_9_the_registration_name_is_the_syscall(self):
        target = self._mutated("wrong-symbol")
        data = bytearray(target.read_bytes())
        at = bytes(data).find(b"__arm64_sys_prctl\x00")
        self.assertGreater(at, 0)
        data[at + 12] = ord("P")           # __arm64_sys_prctl -> ...prctl
        target.write_bytes(bytes(data))
        self.assertIn("L3-9", self._red(target))
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        mutated = source.replace('#define MAPLESU_L3_SYMBOL\t"__arm64_sys_prctl"',
                                 '#define MAPLESU_L3_SYMBOL\t"__arm64_sys_prctl2"', 1)
        self.assertNotEqual(source, mutated)
        self.assertIn("L3-9", self._red(self.module, source=mutated))

    def test_15_l3_10_the_arm_branch_must_keep_the_enforcing_gate(self):
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        self.assertIn("maplesu_selinux->enforcing != 0", source)
        mutated = source.replace("maplesu_selinux->enforcing != 0",
                                 "maplesu_selinux->enforcing == 42", 1)
        self.assertNotEqual(source, mutated)
        self.assertIn("L3-10", self._red(self.module, source=mutated))
        # The complementary statement: the module must not write that byte.
        writing = source.replace("maplesu_selinux->enforcing != 0",
                                 "maplesu_selinux->enforcing = 0", 1)
        self.assertIn("L3-10", self._red(self.module, source=writing))

    def test_16_l3_11_the_callback_must_not_write_the_frame(self):
        source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")
        # (a) The magic, as the ABI states it: (arg3 | arg4) != 0.
        self.assertIn("((((u32)(arg3)) | ((u32)(arg4))) != 0u)", source)
        inverted = source.replace("((((u32)(arg3)) | ((u32)(arg4))) != 0u)",
                                  "((((u32)(arg3)) | ((u32)(arg4))) == 0u)", 1)
        self.assertNotEqual(source, inverted)
        self.assertIn("L3-11", self._red(self.module, source=inverted))
        # (b) The magic must be decided before the op is dispatched.
        magic_line = "\tif (!MAPLESU_L3_MAGIC(argp->regs[2], argp->regs[3]))\n"
        op_line = "\top = (u32)argp->regs[1];\n"
        token_line = "\ttoken = MAPLESU_L3_TOKEN(argp->regs[2], argp->regs[3]);\n"
        self.assertIn(magic_line, source)
        self.assertIn(op_line, source)
        self.assertIn(token_line, source)
        reordered = source.replace(op_line, "", 1).replace(
            magic_line, op_line + magic_line, 1)
        self.assertNotEqual(source, reordered)
        self.assertIn("L3-11", self._red(self.module, source=reordered))
        # (c) No store may reach a frame field -- here the syscall's arg0 word,
        # which is also the syscall's return slot once the wrapper returns.
        storer = source.replace(
            "\toption = (u32)argp->regs[0];\n",
            "\toption = (u32)argp->regs[0];\n\targp->regs[0] = (u64)option;\n", 1)
        self.assertNotEqual(source, storer)
        self.assertIn("L3-11", self._red(self.module, source=storer))
        # (d) Both frame pointers are const; dropping one `const` is the write
        # one store away.
        non_const = source.replace(
            "frame = (const struct maplesu_pt_regs *)(const void *)regs;",
            "frame = (struct maplesu_pt_regs *)(const void *)regs;", 1)
        self.assertNotEqual(source, non_const)
        self.assertIn("L3-11", self._red(self.module, source=non_const))
        # (e) The callback never hands the syscall a different value.
        rewriter = source.replace(
            "return 0;\t/* not ours: observe nothing, change nothing */",
            "return -1;", 1)
        self.assertNotEqual(source, rewriter)
        self.assertIn("L3-11", self._red(self.module, source=rewriter))
        # (f) Casting the frame to anything but the const-qualifying view is the
        # cast-away route to a store.
        cast_away = source.replace(
            "\toption = (u32)argp->regs[0];\n",
            "\toption = (u32)argp->regs[0];\n"
            "\t{ u64 *slot = (u64 *)argp; *slot = 0; }\n", 1)
        self.assertNotEqual(source, cast_away)
        self.assertIn("L3-11", self._red(self.module, source=cast_away))

    def test_17_the_good_artifact_stays_green(self):
        self.assertEqual([], self._red(self.module))

    def test_18_l3_1_the_post_handler_id_is_not_the_pre_handler_id(self):
        """L3-1's pair assertion: the post id in the prefix is red even though it is
        a real id the same image compares -- the two callbacks are different types,
        and the kernel's pre_handler call checks only one of them."""
        target = self._mutated("post-id-prefix")
        data = bytearray(target.read_bytes())
        elf = BUILDER.Elf(target)
        offset = elf.symbol_file_offset(elf.symbol("maplesu_l3_pre"))
        data[offset - 4:offset] = (0x6E21B9C7).to_bytes(4, "little")
        target.write_bytes(bytes(data))
        self.assertIn("L3-1", self._red(target))


class RootModuleFrozenTest(unittest.TestCase):
    """The L3 round must not move maplesu_root.ko by a single byte."""

    def test_01_root_module_is_byte_identical(self):
        out_dir = Path(tempfile.mkdtemp(prefix="maplesu-root-frozen-"))
        try:
            result = _run(["--module", "maplesu_root", "--contract", str(CONTRACT),
                           "--out-dir", str(out_dir), "--quiet"])
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            module = out_dir / "maplesu_root.ko"
            self.assertEqual(ROOT_FROZEN_BYTES, module.stat().st_size,
                             "maplesu_root.ko changed size: either the module "
                             "source changed (not allowed in this round) or the "
                             "toolchain is not the pinned one")
            self.assertEqual(ROOT_FROZEN_SHA256, _sha256(module),
                             "maplesu_root.ko changed bytes: either the module "
                             "source/builder path changed (not allowed) or the "
                             "toolchain is not the pinned one")
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
