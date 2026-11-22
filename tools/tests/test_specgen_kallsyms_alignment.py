"""The relative-base alignment must not shift kallsyms name/address pairing."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "specgen"))
from specgen.kallsyms import KallsymsError, _Probe, decode
from specgen.bootimg import kernel


class KallsymsAlignmentTest(unittest.TestCase):
    def test_even_and_odd_counts_and_zero_final_offsets(self):
        for count in (4, 5, 6, 7):
            for last in (0, 0x90):
                with self.subTest(count=count, last=last):
                    image = bytearray(1024)
                    start = 128
                    values = [i * 16 for i in range(count - 1)] + [last]
                    struct.pack_into("<%di" % count, image, start, *values)
                    base_at = (start + count * 4 + 7) & ~7
                    base = 0xFFFFFFC080000000
                    struct.pack_into("<Q", image, base_at, base)
                    probe = _Probe(bytes(image))
                    actual, relative, mode = probe.find_offsets(count, start, 4, 0)
                    self.assertEqual(start, actual)
                    self.assertEqual(base, relative)
                    self.assertTrue(mode)
                    self.assertEqual([base + v for v in values],
                                     probe.read_addresses(actual, count, relative, mode))

    def test_truncated_base_is_rejected(self):
        with self.assertRaises(KallsymsError):
            _Probe(bytes(151)).find_offsets(5, 128, 4, 0)

    def test_legacy_alignment_preserves_zero_offsets(self):
        for count in (4, 5, 6, 7):
            for last in (0, 0x90):
                with self.subTest(count=count, last=last):
                    image = bytearray(1024)
                    start = 128
                    values = [i * 16 for i in range(count - 1)] + [last]
                    struct.pack_into("<%di" % count, image, start, *values)
                    base_at = (start + count * 4 + 7) & ~7
                    base = 0xFFFFFFC080000000
                    struct.pack_into("<Q", image, base_at, base)
                    struct.pack_into("<I", image, base_at + 8, count)
                    probe = _Probe(bytes(image))
                    actual, relative, mode = probe.find_offsets_legacy(count, base_at + 8, 4)
                    self.assertEqual(start, actual)
                    self.assertEqual([base + v for v in values],
                                     probe.read_addresses(actual, count, relative, mode))

    def test_y700_public_decoder(self):
        image = Path(__file__).resolve().parents[2] / "Boot_Research/北/Original.img"
        if not image.is_file():
            self.skipTest("Y700 original fixture absent")
        symbols = decode(kernel(image))
        self.assertEqual(110447, symbols.layout["num_syms"])
        self.assertEqual(0x14CE260, int(symbols.layout["offsets"], 16))
        self.assertEqual(0, symbols.offset_of("_text"))
        self.assertEqual(0x3E7204, symbols.offset_of("do_execveat_common"))
        self.assertEqual(0x6401D0, symbols.offset_of("avc_denied"))

    def test_shifted_text_base_is_rejected(self):
        image = Path(__file__).resolve().parents[2] / "Boot_Research/北/Original.img"
        if not image.is_file():
            self.skipTest("Y700 original fixture absent")
        raw = bytearray(kernel(image))
        struct.pack_into("<i", raw, 0x14CE260, 0x10000)
        with self.assertRaisesRegex(KallsymsError, "KALLSYMS_TEXT_BASE_MISMATCH"):
            decode(bytes(raw))


if __name__ == "__main__":
    unittest.main()
