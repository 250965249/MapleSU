#!/usr/bin/env python3
"""Independent host check of the kprobe design: image ABI, toolchain, artifact.

What this proves, and why it does not use the builder's derivations
------------------------------------------------------------------
`build_root_module.py` decodes the image, compiles a reference TU and asserts the
module's callback prefix. Those are three statements *by the builder*. This file
re-derives the same facts with its own ~80 lines of `struct.unpack` and its own
compiler invocation, and then checks the artifact, so the acceptance is not one
program agreeing with itself:

  1. the image has `kprobe_breakpoint_handler`, its extent is the function the
     contract's L2 block names, and the kCFI compare sites inside it build
     exactly {0xa6be5dd9, 0x6e21b9c7, 0x36183889} -- the pre-handler id twice,
     the post-handler id twice and one more type;
  2. the two ids the kernel compares for a kprobe callback are the two the
     contract records (`l2.kcfiIds`) and the two the builder pins;
  3. a reference TU compiled here, with the builder's own published flags,
     reproduces both ids -- i.e. the prefix is a property of the prototype
     spelling, not of this particular source file;
  4. the built `maplesu_l3.ko` emits exactly that pre-handler id in front of
     `maplesu_l3_pre`, in `.text`, with no BRK and no surviving kCFI check --
     i.e. nothing was patched and nothing can trap;
  5. the design's negative statements hold in the artifact: three imports, no
     kernel-image write primitive anywhere, the registration name
     `__arm64_sys_prctl` in .rodata, the registration object in `.bss`;
  6. the source keeps ABI v2's magic (`option == 4`, `(arg3 | arg4) != 0`, decided
     before the op dispatch) and the ARM gate (`enforcing == 0`, uid 0, owner
     range, non-zero token, one CAS), never writes the enforcing byte, never
     prints the token, and never stores into the probed frame (so the syscall's
     return value is the kernel's own 0, not ours).

Host-side only: no device, no adb, no module load. The `prctl()` call, the
kernel's decision and the committed cred are NOT exercised here; until a real run
this is a host gate, not closure.

Run:
  python jailbreak-providers/root-loader/tests/test_l3_kprobe.py
  python -m unittest discover -s jailbreak-providers/root-loader/tests -p "test_l3_*.py"
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import native_toolchain  # noqa: E402
ROOT_LOADER = ROOT / "jailbreak-providers" / "root-loader"
BUILDER_PATH = ROOT_LOADER / "build_root_module.py"
CONTRACTS = sorted((ROOT_LOADER / "contracts").glob("6.6.89-*.json"))
CONTRACT = CONTRACTS[0] if CONTRACTS else ROOT_LOADER / "contracts" / "missing.json"
NDK = native_toolchain.provider_ndk()
PYTHON = sys.executable

# Measured on this image (contract 6.6.89), stated here independently of the
# builder's L3_CALLBACK_PINS and of the contract's l2.kcfiIds block.
ANCHOR = "kprobe_breakpoint_handler"
ANCHOR_ADDRESS = 0x106864C
PRE_HANDLER_ID = 0xA6BE5DD9
POST_HANDLER_ID = 0x6E21B9C7
EXTRA_ID = 0x36183889
CALLBACK_IDS = {PRE_HANDLER_ID, POST_HANDLER_ID, EXTRA_ID}
PRCTL_SYMBOL = "__arm64_sys_prctl"
IMPORTS = {"_printk", "register_kprobe", "unregister_kprobe"}

# The two prototypes, spelled with the kernel's own structure names. The pre one
# is the module's callback; both exist so the ids are hashed from the types the
# kernel actually calls.
REFERENCE_TU = """\
struct kprobe;
struct pt_regs;

int maplesu_l3_ref_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	(void)regs;
	return 0;
}

void maplesu_l3_ref_post(struct kprobe *p, struct pt_regs *regs,
			 unsigned long flags)
{
	(void)p;
	(void)regs;
	(void)flags;
}

void *maplesu_l3_ref_taken[2] = {
	(void *)maplesu_l3_ref_pre,
	(void *)maplesu_l3_ref_post,
};
"""


def _load_builder():
    spec = importlib.util.spec_from_file_location("maplesu_builder_l3_kprobe_test",
                                                  BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = _load_builder()


# --------------------------------------------------------------------------- #
# Independent AArch64 decoding: only the instructions a kCFI check is made of.
# --------------------------------------------------------------------------- #

def _movk(word: int):
    """MOVK <Wd>, #imm16, lsl #(hw*16) -> (rd, imm16, hw) or None."""
    if (word & 0x7F800000) != 0x72800000:
        return None
    return word & 0x1F, (word >> 5) & 0xFFFF, (word >> 21) & 0x3


def _cmp_reg(word: int):
    """CMP <Wn>, <Wm> (SUBS WZR, Wn, Wm) -> (rn, rm) or None."""
    if (word & 0xFF200000) != 0x6B000000 or (word & 0x1F) != 31:
        return None
    return (word >> 5) & 0x1F, (word >> 16) & 0x1F


def _is_blr(word: int) -> bool:
    return (word & 0xFFFFFC1F) == 0xD63F0000


def _brk(word: int):
    if (word & 0xFFE0001F) != 0xD4200000:
        return None
    return (word >> 5) & 0xFFFF


def _loads_from_x0(word: int) -> bool:
    """A load whose base register is x0 (LDR 64/32-bit, LDP 64-bit)."""
    for base in (0xF9400000, 0xB9400000, 0xA9400000):
        if (word & 0xFFC00000) == base and ((word >> 5) & 0x1F) == 0:
            return True
    return False


def kcfi_sites(code: bytes) -> list:
    """Every `movk wT,#lo ; movk wT,#hi ; cmp wX,wT ; ... blr` in `code`.

    The shape is clang's kCFI check, and requiring the BLR within four
    instructions keeps ordinary 32-bit constants (which clang builds with
    movz+movk) out of the result.
    """
    words = [struct.unpack_from("<I", code, index * 4)[0]
             for index in range(len(code) // 4)]
    sites = []
    for index in range(len(words) - 6):
        low = _movk(words[index])
        high = _movk(words[index + 1])
        if not low or low[2] != 0 or not high or high[2] != 1 or low[0] != high[0]:
            continue
        compare = _cmp_reg(words[index + 2])
        if not compare or compare[1] != low[0]:
            continue
        if not any(_is_blr(word) for word in words[index + 3:index + 7]):
            continue
        sites.append({"instruction": index * 4,
                      "typeId": ((high[1] << 16) | low[1])})
    return sites


def _symbols(path: Path) -> dict:
    """name -> (offset, kind), first row wins (kallsyms TSV)."""
    rows: dict = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) != 3 or parts[0].startswith("#"):
            continue
        try:
            address = int(parts[0])
        except ValueError:
            continue
        rows.setdefault(parts[2], (address, parts[1]))
    return rows


def _next_offset(rows: dict, address: int) -> int:
    candidates = [offset for offset, _kind in rows.values() if offset > address]
    return min(candidates) if candidates else address + 0x1000


class KprobeImageTest(unittest.TestCase):
    """The image's own statement about the kprobe callback ABI."""

    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.image = (ROOT / cls.contract["imagePath"]).read_bytes()
        cls.symbols = _symbols(ROOT / cls.contract["symbolsPath"])
        address, kind = cls.symbols[ANCHOR]
        cls.anchor = {"address": address, "kind": kind,
                      "end": _next_offset(cls.symbols, address)}
        cls.sites = kcfi_sites(cls.image[cls.anchor["address"]:cls.anchor["end"]])

    def test_01_the_anchor_is_a_text_function(self):
        self.assertEqual("TEXT", self.anchor["kind"])
        self.assertEqual(ANCHOR_ADDRESS, self.anchor["address"],
                         "kprobe_breakpoint_handler moved; every id below has to "
                         "be re-derived")
        self.assertGreater(self.anchor["end"], self.anchor["address"] + 0x100,
                           "the extent is the function, not a two-instruction "
                           "thunk")

    def test_02_the_kprobe_callback_ids_are_what_it_compares(self):
        ids = {site["typeId"] for site in self.sites}
        self.assertEqual(CALLBACK_IDS, ids)
        pre = [site for site in self.sites if site["typeId"] == PRE_HANDLER_ID]
        post = [site for site in self.sites if site["typeId"] == POST_HANDLER_ID]
        # Measured: the pre_handler call has one compare site in this
        # function, the post_handler call has two (the single-step and the
        # fault paths). The counts are stated so a re-derivation that finds a
        # different shape is visible rather than silently absorbed.
        self.assertEqual(1, len(pre), "one pre_handler compare site")
        self.assertEqual(2, len(post), "two post_handler compare sites")

    def test_03_contract_and_builder_pin_the_same_pair(self):
        recorded = (self.contract.get("l2") or {}).get("kcfiIds") or {}
        self.assertEqual("0x%08x" % PRE_HANDLER_ID,
                         (recorded.get("preHandler") or {}).get("value"))
        self.assertEqual("0x%08x" % POST_HANDLER_ID,
                         (recorded.get("postHandler") or {}).get("value"))
        self.assertEqual({"preHandler": PRE_HANDLER_ID,
                          "postHandler": POST_HANDLER_ID},
                         BUILDER.L3_CALLBACK_PINS)
        self.assertEqual(128, self.contract["kprobe"]["size"])
        self.assertEqual(0x40, self.contract["kprobe"]["members"][6]["byteOffset"],
                         "pre_handler must be at +0x40 in this image's struct kprobe")

    def test_04_the_registration_target_is_a_probed_text_function(self):
        self.assertIn(PRCTL_SYMBOL, self.symbols)
        address, kind = self.symbols[PRCTL_SYMBOL]
        self.assertEqual("TEXT", kind)
        # The image's prologue reads the syscall arguments through x0 -- x0 is the
        # pt_regs pointer the dispatcher passed, not the first argument. That is
        # why the callback dereferences regs->regs[0] before looking at op/token.
        prologue = [struct.unpack_from("<I", self.image, address + step * 4)[0]
                    for step in range(16)]
        self.assertEqual(0xD503233F, prologue[0], "expected paciasp at entry")
        self.assertTrue(any(_loads_from_x0(word) for word in prologue),
                        "__arm64_sys_prctl must load its arguments through x0")


class KprobeDispatchDerivationTest(unittest.TestCase):
    """G-1: the anchors are *candidates*; the derivation either names one id or stops.

    The dispatch id is not a pin any more, so the failure modes are the substance:
    an anchor the image cannot be attributed through, an absent anchor, and two
    anchors that disagree all have to be visible, and only the absent-anchor case is
    allowed to continue (6.1/6.18 depend on it).
    """

    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.image = (ROOT / cls.contract["imagePath"]).read_bytes()
        cls.symbols = BUILDER.SymbolTable(ROOT / cls.contract["symbolsPath"])

    def _contract(self, anchors):
        contract = dict(self.contract)
        contract["l3"] = {"callbackAnchors": anchors,
                          "callbackPrefixPolicy": "image-dispatch-id"}
        return contract

    def test_01_a_contract_without_the_block_uses_the_same_default_anchors(self):
        without = dict(self.contract)
        without.pop("l3", None)
        default = BUILDER.derive_kprobe_handler_ids(self.image, self.symbols, without)
        explicit = BUILDER.derive_kprobe_handler_ids(
            self.image, self.symbols,
            self._contract({"preHandler": ["aggr_pre_handler",
                                           "kprobe_breakpoint_handler"],
                            "postHandler": ["aggr_post_handler",
                                            "post_probe_handler_absent",
                                            "kprobe_breakpoint_handler"]}))
        self.assertEqual(default["dispatch"]["preHandler"]["typeId"],
                         explicit["dispatch"]["preHandler"]["typeId"])
        self.assertEqual("0x%08x" % PRE_HANDLER_ID,
                         default["dispatch"]["preHandler"]["typeId"])
        self.assertEqual("0x%08x" % POST_HANDLER_ID,
                         default["dispatch"]["postHandler"]["typeId"])
        self.assertNotEqual(default["dispatch"]["preHandler"]["typeId"],
                            default["dispatch"]["postHandler"]["typeId"])
        # Both callback ids are attributed through the BTF member offset, and the
        # aggregator's load is the list-relative form.
        forms = {site["form"] for key in ("preHandler", "postHandler")
                 for site in default["dispatch"][key]["attributedSites"]}
        self.assertEqual({"direct", "list-relative"}, forms)

    def test_02_an_absent_anchor_is_recorded_not_fatal(self):
        facts = BUILDER.derive_kprobe_handler_ids(
            self.image, self.symbols,
            self._contract({"preHandler": ["no_such_symbol", "aggr_pre_handler"],
                            "postHandler": ["aggr_post_handler"]}))
        self.assertEqual(["no_such_symbol"],
                         facts["dispatch"]["preHandler"]["anchorsAbsent"])
        self.assertEqual(["aggr_pre_handler"],
                         facts["dispatch"]["preHandler"]["anchorsPresent"])
        self.assertEqual("0x%08x" % PRE_HANDLER_ID,
                         facts["dispatch"]["preHandler"]["typeId"])

    def test_03_an_anchor_with_no_attributable_site_stops_the_derivation(self):
        # pre_handler_kretprobe's only check loads kretprobe.handler (+0x88), not
        # kprobe.post_handler (+0x48): it is not a dispatch point for this callback.
        contract = self._contract({"preHandler": ["aggr_pre_handler"],
                                   "postHandler": ["pre_handler_kretprobe"]})
        with self.assertRaises(BUILDER.GateFailure) as caught:
            BUILDER.derive_kprobe_handler_ids(self.image, self.symbols, contract)
        self.assertIn("no postHandler dispatch site", str(caught.exception))

    def test_04_two_anchors_that_disagree_stop_the_derivation(self):
        # Two attributed sites that compare different ids cannot both be the
        # callback: the artifact's prefix is one 4-byte value, so this is red.
        image = bytearray(self.image)
        address = self.symbols.address("aggr_pre_handler")
        end = self.symbols.next_address(address, limit=0x1000)
        patched = False
        for hit in BUILDER.kcfi_type_ids(bytes(image[address:end])):
            if hit["typeId"] != PRE_HANDLER_ID:
                continue
            at = address + hit["instruction"] * 4
            word = BUILDER.read_uint32(bytes(image), at)
            decoded = BUILDER.decode_movk(word)
            self.assertIsNotNone(decoded)
            self.assertEqual(0, decoded[2], "the low half is the first movk")
            replacement = (word & ~(0xFFFF << 5)) | (0x1111 << 5)
            image[at:at + 4] = replacement.to_bytes(4, "little")
            patched = True
            break
        self.assertTrue(patched, "the aggregator's pre-handler compare site moved")
        with self.assertRaises(BUILDER.GateFailure) as caught:
            BUILDER.derive_kprobe_handler_ids(bytes(image), self.symbols,
                                             self.contract)
        self.assertIn("disagree on the callback type id",
                      str(caught.exception))

    def test_05_other_families_are_derived_from_their_own_dispatch_sites(self):
        """The cross-family rule: 6.1 keeps the toolchain's pair, 6.12/6.18 do not.

        6.1 is the case where G-1 alone is enough (the post dispatch moved to
        post_kprobe_handler, the ids did not change); 6.12/6.18 are the case where
        the image compares a different generation of ids for the same prototypes,
        which is what the prefix write exists for. Skipped when the family images
        are not present in this checkout.
        """
        expectations = {
            "family-6.1": {"preHandler": 0xA6BE5DD9, "postHandler": 0x6E21B9C7,
                           "anchors": ["kprobe_breakpoint_handler",
                                       "aggr_pre_handler"]},
            "family-6.12": {"preHandler": 0xC073BC77, "postHandler": 0x02BB4397,
                            "anchors": ["kprobe_breakpoint_handler",
                                        "aggr_pre_handler"]},
            "family-6.18": {"preHandler": 0xC073BC77, "postHandler": 0x02BB4397,
                            "anchors": ["aggr_pre_handler"]},
        }
        for name, expected in expectations.items():
            with self.subTest(family=name):
                contract_path = ROOT_LOADER / "contracts" / (name + ".json")
                contract = json.loads(contract_path.read_text(encoding="utf-8"))
                image_path = ROOT / contract["imagePath"]
                if not image_path.is_file():
                    self.skipTest("%s image is not in this checkout" % name)
                symbols = BUILDER.SymbolTable(
                    ROOT / contract["symbolsPath"]
                    if not Path(contract["symbolsPath"]).is_absolute()
                    else Path(contract["symbolsPath"]))
                facts = BUILDER.derive_l3_facts(image_path.read_bytes(),
                                                symbols, contract)
                dispatch = facts["kprobe"]["dispatch"]
                self.assertEqual("0x%08x" % expected["preHandler"],
                                 dispatch["preHandler"]["typeId"])
                self.assertEqual("0x%08x" % expected["postHandler"],
                                 dispatch["postHandler"]["typeId"])
                self.assertEqual(expected["anchors"],
                                 dispatch["preHandler"]["anchorsPresent"])
                self.assertEqual("image-dispatch-id",
                                 facts["callbackPrefixPolicy"])
                self.assertTrue(dispatch["preHandler"]["attributedSites"])


class KprobeToolchainTest(unittest.TestCase):
    """The prefix is a property of the prototype, measured by compiling it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="maplesu-l3-kprobe-"))
        cls.source = cls.tmp / "kprobe-ref.c"
        cls.source.write_text(REFERENCE_TU, encoding="utf-8")
        cls.clang = BUILDER.find_tool(NDK, "clang")
        cls.obj = cls.tmp / "kprobe-ref.o"
        cls.command = [str(cls.clang), *BUILDER.CLANG_FLAGS,
                       str(cls.source), "-o", str(cls.obj)]
        cls.compile = subprocess.run(cls.command, capture_output=True, text=True,
                                     errors="replace")
        cls.ids = {}
        if cls.compile.returncode == 0:
            elf = BUILDER.Elf(cls.obj)
            for key, name in (("preHandler", "maplesu_l3_ref_pre"),
                              ("postHandler", "maplesu_l3_ref_post")):
                symbol = elf.symbol(name)
                offset = elf.symbol_file_offset(symbol)
                cls.ids[key] = BUILDER.read_uint32(elf.raw, offset - 4)
        cls.builder_ids = BUILDER.kprobe_callback_ids()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_the_reference_tu_compiles_with_the_published_flags(self):
        self.assertEqual(0, self.compile.returncode,
                         self.compile.stdout + self.compile.stderr)
        self.assertIn("-fsanitize=kcfi", BUILDER.CLANG_FLAGS)
        # Same flags as the module: the prefix is emitted under exactly this set.
        self.assertEqual(["-c"], BUILDER.CLANG_FLAGS[-1:])

    def test_02_it_reproduces_both_kernel_ids(self):
        self.assertEqual(PRE_HANDLER_ID, self.ids.get("preHandler"),
                         "clang derives %r for int (*)(struct kprobe *, "
                         "struct pt_regs *); the kernel compares 0x%08x"
                         % (self.ids.get("preHandler"), PRE_HANDLER_ID))
        self.assertEqual(POST_HANDLER_ID, self.ids.get("postHandler"))
        self.assertEqual(PRE_HANDLER_ID, self.builder_ids["preHandler"])
        self.assertEqual(POST_HANDLER_ID, self.builder_ids["postHandler"])

    def test_03_a_guessed_spelling_would_hash_differently(self):
        # `struct maplesu_pt_regs *` is the same layout but a different spelling,
        # and clang hashes the spelling -- the reason the callback must use the
        # kernel's names. This is the measurement behind that sentence.
        shim = self.tmp / "shim.c"
        shim.write_text(
            "struct kprobe;\nstruct maplesu_pt_regs;\n\n"
            "int shim_pre(struct kprobe *p, struct maplesu_pt_regs *regs)\n"
            "{\n\t(void)p;\n\t(void)regs;\n\treturn 0;\n}\n"
            "void *shim_taken[1] = { (void *)shim_pre };\n", encoding="utf-8")
        obj = self.tmp / "shim.o"
        result = subprocess.run([str(self.clang), *BUILDER.CLANG_FLAGS,
                                 str(shim), "-o", str(obj)],
                                capture_output=True, text=True, errors="replace")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        elf = BUILDER.Elf(obj)
        offset = elf.symbol_file_offset(elf.symbol("shim_pre"))
        self.assertNotEqual(PRE_HANDLER_ID, BUILDER.read_uint32(elf.raw, offset - 4),
                            "the shim spelling hashes to the same id; the "
                            "prototype-spelling argument in the source would be "
                            "wrong and this test would need updating")


class KprobeArtifactTest(unittest.TestCase):
    """The built module: emitted prefix, no traps, no write primitive, no token."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="maplesu-l3-kprobe-artifact-"))
        out_dir = cls.tmp / "l3"
        cls.result = subprocess.run(
            [PYTHON, str(BUILDER_PATH), "--module", "maplesu_l3",
             "--contract", str(CONTRACT), "--out-dir", str(out_dir)],
            cwd=str(ROOT), capture_output=True, text=True, errors="replace")
        cls.module = out_dir / "maplesu_l3.ko"
        cls.elf = BUILDER.Elf(cls.module) if cls.module.is_file() else None
        cls.record = json.loads((out_dir / "build.json").read_text(encoding="utf-8")) if cls.elf else {}
        cls.source = BUILDER.L3_SOURCE.read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_the_build_is_green_so_there_is_an_artifact(self):
        self.assertEqual(0, self.result.returncode,
                         self.result.stdout + self.result.stderr)
        self.assertTrue(self.module.is_file())
        self.assertIn("RESULT: all gates pass", self.result.stdout)

    def test_02_the_emitted_prefix_is_the_kernel_pre_handler_id(self):
        symbol = self.elf.symbol("maplesu_l3_pre")
        self.assertIsNotNone(symbol)
        offset = self.elf.symbol_file_offset(symbol)
        prefix = BUILDER.read_uint32(self.elf.raw, offset - 4)
        self.assertEqual(PRE_HANDLER_ID, prefix,
                         "the module emits 0x%08x; the kernel compares 0x%08x -- "
                         "and this build patches nothing into that slot"
                         % (prefix, PRE_HANDLER_ID))
        self.assertEqual(0xD503233F, BUILDER.read_uint32(self.elf.raw, offset + 4),
                         "the callback's entry is paciasp")

    def test_03_no_brk_and_no_surviving_kcfi_check(self):
        scanned = 0
        traps, sites = [], []
        for section in self.elf.sections:
            if not section["flags"] & BUILDER.SHF_EXECINSTR:
                continue
            blob = self.elf.section_bytes(section)
            scanned += len(blob)
            for index in range(len(blob) // 4):
                word = struct.unpack_from("<I", blob, index * 4)[0]
                if _brk(word) is not None:
                    traps.append("%s+0x%x" % (section["name"], index * 4))
            sites.extend("%s+0x%x" % (section["name"], site["instruction"])
                         for site in kcfi_sites(blob))
        self.assertEqual([], traps, "a BRK in module text is a panic on this image")
        self.assertEqual([], sites,
                         "a surviving kCFI check is a trap waiting for an id to "
                         "drift; every indirect call belongs in a NOCFI helper")
        self.assertGreater(scanned, 0x400)

    def test_04_three_imports_and_no_kernel_image_writer(self):
        self.assertEqual(IMPORTS, set(self.elf.imports()))
        raw = self.elf.raw
        for needle in (b"sys_call_table", b"text_poke", b"aarch64_insn_patch_text", b"/data/"):
            self.assertTrue(needle not in raw, "forbidden kernel-image primitive/path: %r" % needle)
        bridge = self.record["facts"].get("modulePolicyBridge")
        for name in ("set_memory_rw", "set_memory_ro"):
            self.assertTrue(name not in BUILDER.strip_c_comments(self.source),
                            "the original Root gate remains read-only")
            if bridge:
                self.assertIn(name, bridge["allowedSymbols"])
                self.assertIsNotNone(self.elf.symbol("msu_policy_ioctl"))
            else:
                self.assertTrue(name.encode() not in raw, "protection helper needs the bounded bridge")

    def test_05_the_registration_is_by_name_and_the_object_survives_init(self):
        self.assertIn(PRCTL_SYMBOL.encode(), self.elf.raw)
        probe = self.elf.symbol("maplesu_probe")
        self.assertIsNotNone(probe, "the registration object must be a symbol")
        section = self.elf.symbol_section(probe)
        self.assertEqual(".bss", section["name"],
                         "the kprobe object must outlive .init.text: the kernel "
                         "keeps a pointer to it while the hook is installed")
        self.assertGreaterEqual(section["size"], 0x80,
                                "struct kprobe is 0x80 bytes on this image; a "
                                "shorter object would be overrun by register_kprobe")
        normalized = " ".join(self.source.split())
        self.assertIn("maplesu_probe.symbol_name = MAPLESU_L3_SYMBOL", normalized)
        self.assertIn("register_kprobe(&maplesu_probe)", normalized)
        self.assertIn("unregister_kprobe(&maplesu_probe)", normalized)

    def test_06_the_callback_keeps_the_kernel_prototype_spelling(self):
        normalized = " ".join(self.source.split())
        self.assertIn("int maplesu_l3_pre(struct kprobe *p, struct pt_regs *regs)",
                      normalized)
        self.assertIn("struct kprobe;", self.source)
        self.assertIn("struct pt_regs;", self.source)
        self.assertFalse(BUILDER.nocfi_covers(self.source, "maplesu_l3_pre"),
                         "the callback's prefix is mandatory; no_sanitize must "
                         "not be written on it")
        for helper in ("maplesu_caller_uid", "maplesu_handover",
                       "maplesu_pool_release", "maplesu_sym"):
            self.assertTrue(BUILDER.nocfi_covers(self.source, helper),
                            "%s makes an indirect call and must be NOCFI" % helper)

    def test_07_the_arm_gate_and_the_token_rule_are_in_the_source(self):
        handler = BUILDER.function_body(self.source, "maplesu_l3_pre")
        normalized = " ".join(handler.split())
        for needle in ("maplesu_selinux->enforcing != 0", "uid != 0",
                       "owner < MAPLESU_L3_OWNER_MIN",
                       "owner >= MAPLESU_L3_OWNER_MAX", "token == 0",
                       "__sync_bool_compare_and_swap(&maplesu_armed, 0u, 1u)",
                       "__atomic_store_n(&maplesu_ready, 1u, __ATOMIC_RELEASE)"):
            self.assertIn(needle, normalized)
        self.assertLess(normalized.find("maplesu_selinux->enforcing != 0"),
                        normalized.find("__sync_bool_compare_and_swap"),
                        "the window is checked before the gate is claimed")
        stripped = BUILDER.strip_c_comments(self.source)
        self.assertNotRegex(stripped, r"(?:->|\.)enforcing\s*=(?!=)",
                            "this module reads the enforcing byte; writing it is "
                            "maplesu_root's and the helper's job")
        for call in BUILDER.printk_calls(self.source):
            self.assertNotRegex(call, r"token|suToken|%016",
                                "a printk argument mentions the token")
        self.assertNotIn(b"suToken", self.elf.raw)
        self.assertNotIn(b"%016llx", self.elf.raw)
        self.assertIn(b"armed owner=%u pool=%u", self.elf.raw,
                      "the ARM evidence line is what the helper copies out of the "
                      "ring buffer")

    def test_08_the_magic_is_abi_v2_and_the_callback_never_writes_the_frame(self):
        # ABI v2's numbers, read off the source independently of the builder's
        # L3_ABI table: option 4 is PR_SET_DUMPABLE, 0/1 are its two arg2 values.
        self.assertIn("#define MAPLESU_L3_OPTION\t4u", self.source)
        self.assertIn("#define MAPLESU_L3_OP_ARM\t0u", self.source)
        self.assertIn("#define MAPLESU_L3_OP_SU\t1u", self.source)
        self.assertNotIn("0x4d535503", self.source.lower(),
                         "the retired v1 magic must not survive anywhere")
        handler = BUILDER.function_body(self.source, "maplesu_l3_pre")
        self.assertTrue(handler)
        normalized = " ".join(handler.split())
        # The magic is option 4 plus the two token halves, before the op dispatch.
        self.assertIn("option != MAPLESU_L3_OPTION", normalized)
        self.assertIn("MAPLESU_L3_MAGIC(argp->regs[2], argp->regs[3])", normalized)
        self.assertIn("MAPLESU_L3_TOKEN(argp->regs[2], argp->regs[3])", normalized)
        self.assertLess(normalized.find("MAPLESU_L3_MAGIC"),
                        normalized.find("op = (u32)argp->regs[1]"),
                        "the magic is decided before the op is dispatched")
        # Own scan (not the builder's gate): a pre-handler that stores into the
        # frame rewrites the syscall's arguments or its return slot.
        stripped = BUILDER.strip_c_comments(handler)
        stores = re.findall(
            r"(?:->|\.)\s*regs\s*\[[^\]]*\]\s*(?:[-+*/%&|^]|<<|>>|\+\+|--)?=(?!=)",
            stripped)
        self.assertEqual([], stores, "a store reaches a regs field")
        self.assertEqual([], re.findall(r"\(\s*struct maplesu_pt_regs\s*\*\)",
                                        stripped),
                         "a non-const pt_regs cast exists in the callback")
        self.assertEqual(2, len(re.findall(r"\(const struct maplesu_pt_regs \*\)",
                                           stripped)),
                         "both frame pointers are const")
        returns = [match.group(1).strip() for match in
                   re.finditer(r"\breturn\b\s*([^;]*);", stripped)]
        self.assertTrue(returns)
        self.assertEqual([], [value for value in returns
                              if value != "0" and not value.startswith("maplesu_deny(")],
                         "the callback returns 0 (continue) or any deny (also 0)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
