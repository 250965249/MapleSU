"""Regressions for the IR rule engine, cave allocator and dry-run verifier.

These are synthetic images: no kernel data is used, so the tests run anywhere and
say nothing about a real release (the release assertions live in
`.analysis/ultra-baseline-2026-10-30/run_baseline.py`).

Run with:  py -m unittest discover -s tools/tests -p "test_ir_gen*.py"
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ir-gen"))

import a64                       # noqa: E402
import rules                     # noqa: E402

RET = a64.ret().to_bytes(4, "little")
PACIASP = a64.paciasp().to_bytes(4, "little")
BTI_C = a64.bti_c().to_bytes(4, "little")


def image_with_cave(size=0x4000, etext=0x3000):
    image = bytearray(b"\x1f\x20\x03\xd5" * (size // 4))   # nop everywhere
    image[0x2000:etext] = bytes(etext - 0x2000)            # zero cave at the tail
    return bytes(image)


def symbols(**overrides):
    base = {"_stext": 0x1000, "_etext": 0x3000, "_text": 0}
    base.update(overrides)
    return base


class CaveAllocatorTests(unittest.TestCase):
    def allocator(self, **kwargs):
        return rules.CaveAllocator(image_with_cave(), rules.SymbolTable(symbols()), **kwargs)

    def test_allocates_two_stubs_in_one_run_without_overlap(self):
        allocator = self.allocator()
        first = allocator.alloc(0x40, 0x1000, "first")
        second = allocator.alloc(0x40, 0x1000, "second")
        self.assertLessEqual(first.end, second.offset)
        self.assertEqual(allocator.verify(), [])

    def test_reservation_blocks_the_legacy_stub_area(self):
        allocator = self.allocator()
        allocator.reserve(0x2000, 60, "P3c.legacy")
        piece = allocator.alloc(0x40, 0x1000, "rule")
        self.assertGreaterEqual(piece.offset, 0x2000 + 60)
        with self.assertRaises(rules.RuleError):
            allocator.reserve(0x2020, 8, "overlap")

    def test_refuses_when_no_run_is_big_enough(self):
        allocator = self.allocator()
        with self.assertRaises(rules.RuleError):
            allocator.alloc(0x2000, 0x1000, "too big")

    def test_branch_range_is_enforced(self):
        allocator = rules.CaveAllocator(image_with_cave(size=0x800000, etext=0x700000),
                                        rules.SymbolTable(symbols(_etext=0x700000)),
                                        scan_window=0x800000)
        with self.assertRaises(rules.RuleError):
            allocator.alloc(0x40, 0xFFFFFFFF, "unreachable")

    def test_missing_etext_fails_closed(self):
        with self.assertRaises(rules.RuleError):
            rules.CaveAllocator(image_with_cave(), rules.SymbolTable({"_stext": 0x1000}))


class FilldirVersionTests(unittest.TestCase):
    """filldir64's skip value is `int 0` below 6.1 and `bool 1` from 6.1 on."""

    def build(self, release_text):
        image = bytearray(image_with_cave())
        image[0x1000:0x1000 + 4] = PACIASP                # filldir64 entry
        table = rules.SymbolTable(symbols(filldir64=0x1000))
        allocator = rules.CaveAllocator(bytes(image), table)
        context = rules.RuleContext(bytes(image), table, release_text, None, allocator)
        return context.rule_filldir()

    def test_pre_61_returns_int_zero(self):
        outcome = self.build("5.10.226-android12-9-o")
        self.assertEqual(outcome.status, "applied")
        self.assertEqual(outcome.meta["abi"], "int 0")
        stub = next(block for block in outcome.blocks if block.id.endswith(".stub"))
        words = [int.from_bytes(stub.patched[i:i + 4], "little") for i in range(0, len(stub.patched), 4)]
        self.assertIn(a64.movz(0, 0), words)
        self.assertNotIn(a64.movz(0, 1), words)

    def test_post_61_returns_bool_one(self):
        outcome = self.build("6.6.89-android15-8")
        self.assertEqual(outcome.meta["abi"], "bool 1")
        stub = next(block for block in outcome.blocks if block.id.endswith(".stub"))
        words = [int.from_bytes(stub.patched[i:i + 4], "little") for i in range(0, len(stub.patched), 4)]
        self.assertIn(a64.movz(0, 1), words)


class RuleOutcomeTests(unittest.TestCase):
    def context(self, table_overrides=None, release="6.6.89-android15-8"):
        image = bytearray(image_with_cave())
        image[0x1000:0x1000 + 4] = PACIASP
        image[0x1400:0x1400 + 4] = PACIASP
        table = rules.SymbolTable(symbols(**(table_overrides or {})))
        allocator = rules.CaveAllocator(bytes(image), table)
        return rules.RuleContext(bytes(image), table, release,
                                 {"cred": 0x820, "cred_uid": 8, "seccomp": 0x8e8}, allocator)

    def test_execve_fails_without_struct_offsets(self):
        image = bytearray(image_with_cave())
        image[0x1000:0x1000 + 4] = PACIASP
        table = rules.SymbolTable(symbols(do_execveat_common=0x1000, init_task=0x1800,
                                          prepare_kernel_cred=0x1900, commit_creds=0x1A00))
        context = rules.RuleContext(bytes(image), table, "6.6.89", None,
                                    rules.CaveAllocator(bytes(image), table))
        outcome = context.rule_execve()
        self.assertEqual(outcome.status, "failed")
        self.assertIn("task_struct", outcome.detail)

    def test_cfi_is_not_applicable_without_cfi_check(self):
        image = bytes(bytearray(image_with_cave()) + rules.KCFI_TRAP.to_bytes(4, "little"))
        table = rules.SymbolTable(symbols())
        context = rules.RuleContext(image, table, "6.6.89", None,
                                    rules.CaveAllocator(image, table))
        outcome = context.rule_cfi()
        self.assertEqual(outcome.status, "not_applicable")
        self.assertEqual(outcome.meta["kcfiTraps"], 1)

    def test_cfi_preserves_the_landing_pad(self):
        image = bytearray(image_with_cave())
        image[0x1000:0x1000 + 8] = BTI_C + PACIASP
        image[0x1400:0x1400 + 4] = PACIASP
        table = rules.SymbolTable(symbols(__cfi_check=0x1000, __cfi_slowpath=0x1400))
        context = rules.RuleContext(bytes(image), table, "5.10.226", None,
                                    rules.CaveAllocator(bytes(image), table))
        outcome = context.rule_cfi()
        self.assertEqual(outcome.status, "applied")
        by_id = {block.id: block for block in outcome.blocks}
        self.assertEqual(by_id["R-cfi.cfi_check"].patched[:4], BTI_C)
        self.assertEqual(by_id["R-cfi.cfi_check"].patched[4:], RET)
        self.assertEqual(by_id["R-cfi.cfi_slowpath"].patched[:4],
                         rules.BTI_JC.to_bytes(4, "little"))
        self.assertEqual(by_id["R-cfi.cfi_slowpath"].patched[4:], RET)


class DryRunTests(unittest.TestCase):
    def block(self, block_id, offset, orig, patched):
        return rules.Block(block_id, offset, orig, patched, "")

    def test_detects_readback_mismatch(self):
        image = image_with_cave()
        block = self.block("X", 0x1000, PACIASP, RET)
        result = rules.dry_run(image, [block])
        self.assertFalse(result["ok"])
        self.assertTrue(any("does not read back" in problem for problem in result["problems"]))

    def test_detects_overlap(self):
        image = image_with_cave()
        first = self.block("A", 0x1000, image[0x1000:0x1008], b"\x00" * 8)
        second = self.block("B", 0x1004, image[0x1004:0x1008], b"\x00" * 4)
        result = rules.dry_run(image, [first, second])
        self.assertTrue(any("overlap" in problem for problem in result["problems"]))

    def test_detects_stub_fallthrough(self):
        image = image_with_cave()
        block = self.block("S.stub", 0x1000, image[0x1000:0x1008],
                           a64.nop().to_bytes(4, "little") * 2)
        result = rules.dry_run(image, [block])
        self.assertTrue(any("does not end in ret/b" in problem for problem in result["problems"]))

    def test_accepts_entry_hook_plus_stub(self):
        image = bytearray(image_with_cave())
        image[0x1000:0x1000 + 4] = PACIASP
        stub = a64.mov_wzr(0).to_bytes(4, "little") + RET
        image[0x2000:0x2000 + 8] = stub
        entry = a64.b(0x1000, 0x2000).to_bytes(4, "little")
        blocks = [self.block("R.entry", 0x1000, PACIASP, entry),
                  self.block("R.stub", 0x2000, stub, stub)]
        result = rules.dry_run(bytes(image), blocks, entry_blocks={"R.entry"})
        self.assertTrue(result["ok"], result["problems"])


if __name__ == "__main__":
    unittest.main()
