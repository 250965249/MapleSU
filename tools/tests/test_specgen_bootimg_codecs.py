"""Independent python-lz4 decoding used by real boot-image round-trip checks."""
from pathlib import Path
import struct
import sys
import unittest

import lz4.block

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'specgen'))
from specgen.bootimg import BootImageError, decode


class LegacyLz4Test(unittest.TestCase):
    def setUp(self):
        self.raw = bytes(56) + b'ARMd' + b'abcd' * 1024
        self.block = lz4.block.compress(self.raw, store_size=False)
        self.frame = b'\x02\x21\x4c\x18' + struct.pack('<I', len(self.block)) + self.block

    def test_independent_round_trip(self):
        self.assertEqual(self.raw, decode(self.frame))

    def test_multiple_blocks(self):
        second = lz4.block.compress(b'last block', store_size=False)
        self.assertEqual(self.raw + b'last block', decode(self.frame + struct.pack('<I', len(second)) + second))

    def test_truncation_and_corrupt_blocks(self):
        for value in (self.frame[:-1], self.frame + b'x', self.frame[:4] + bytes(4),
                      self.frame[:4] + struct.pack('<I', 0xffffffff),
                      self.frame[:4] + struct.pack('<I', 2) + b'\xff\xff'):
            with self.subTest(value=value[:10]), self.assertRaises(BootImageError):
                decode(value)

    def test_non_kernel_is_rejected(self):
        data = lz4.block.compress(b'not a kernel', store_size=False)
        with self.assertRaisesRegex(BootImageError, 'KERNEL_NOT_RAW_ARM64'):
            decode(self.frame[:4] + struct.pack('<I', len(data)) + data)


if __name__ == '__main__':
    unittest.main()
