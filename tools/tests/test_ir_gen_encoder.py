"""Regressions for the AArch64 encoder used by tools/ir-gen.

The encoder round-trips every word through capstone, so a wrong operand spelling
is a hard failure rather than a silently wrong byte. `add_imm(..., 0)` was the
one case where the spelling was wrong: capstone prints a zero immediate as `#0`,
not `#0x0`, so any kernel whose `init_task` page offset is zero (5.10.226,
`init_task = 0x27BC000`) aborted the P3c stub builder with EncodeError.

Run with:  py -m unittest discover -s tools/tests -p "test_ir_gen*.py"
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ir-gen"))

import a64  # noqa: E402


class AddImmediateTests(unittest.TestCase):
    def test_zero_immediate_is_encodable(self):
        # The exact case that used to raise EncodeError: `add x0, x0, #0`.
        self.assertEqual(a64.add_imm(0, 0, 0), 0x91000000)
        self.assertEqual(a64.add_imm(0, 0, 0), a64.add_imm(0, 0, 0x1000 - 0x1000))

    def test_nonzero_immediate_unchanged(self):
        self.assertEqual(a64.add_imm(0, 0, 0x10), 0x91004000)
        self.assertEqual(a64.add_imm(0, 0, 0xFFF), 0x913FFC00)
        self.assertEqual(a64.add_imm(1, 2, 0x18), 0x91006041)

    def test_every_immediate_round_trips(self):
        for imm in (0, 1, 2, 0xF, 0x10, 0xFF, 0x3F0, 0x800, 0xFFF):
            word = a64.add_imm(3, 4, imm)
            self.assertEqual(word & 0x3FFC00, imm << 10, hex(imm))

    def test_out_of_range_rejected(self):
        for imm in (-1, 0x1000):
            with self.assertRaises(a64.EncodeError):
                a64.add_imm(0, 0, imm)

    def test_immediate_spelling_helper(self):
        # Capstone spells 0..9 in decimal and wider values in hex.
        self.assertEqual(a64._imm(0), "#0")
        self.assertEqual(a64._imm(9), "#9")
        self.assertEqual(a64._imm(10), "#0xa")
        self.assertEqual(a64._imm(0x1f), "#0x1f")


class ZeroPageInitTaskStubTests(unittest.TestCase):
    """The P3c stub must build when `init_task & 0xFFF == 0` (5.10.226)."""

    SYMBOLS = {
        "init_task": 0x27BC000,          # low 12 bits are zero: the failing case
        "prepare_kernel_cred": 0xE0F60,
        "commit_creds": 0xE2F98,
        "__sys_setresuid": 0x15F178,
        "avc_denied": 0x8F56F0,
        "_etext": 0x1A30000,
    }

    def build(self):
        import build_ir_spec
        return build_ir_spec.build_stub(0x1A2B448, dict(self.SYMBOLS))

    def test_stub_builds_with_zero_page_offset(self):
        stub, notes = self.build()
        self.assertEqual(len(stub), 60)
        self.assertEqual(len(notes), 15)

    def test_zipped_adrp_add_pairs_to_init_task(self):
        from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
        stub, _ = self.build()
        words = [int.from_bytes(stub[i:i + 4], "little") for i in range(0, 60, 4)]
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        # word 4 = adrp x0, page(init_task); word 5 = add x0, x0, page offset.
        adrp = list(md.disasm(words[4].to_bytes(4, "little"), a64.BASE + 0x1A2B448 + 16))[0]
        add = list(md.disasm(words[5].to_bytes(4, "little"), a64.BASE + 0x1A2B448 + 20))[0]
        self.assertEqual((adrp.mnemonic, add.mnemonic), ("adrp", "add"))
        self.assertTrue(add.op_str.endswith(", #0"), add.op_str)
        page = int(adrp.op_str.split("#")[1], 16)
        self.assertEqual(page, a64.BASE + (0x27BC000 & ~0xFFF))

    def test_missing_symbol_still_fails_closed(self):
        import build_ir_spec
        symbols = dict(self.SYMBOLS)
        del symbols["commit_creds"]
        with self.assertRaises(SystemExit):
            build_ir_spec.build_stub(0x1A2B448, symbols)


if __name__ == "__main__":
    unittest.main()
