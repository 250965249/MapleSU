"""Focused container field regressions; never produce a kernel patch or device result."""
import gzip
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from specgen.bootimg import BootImageError, _inspect, decode, inspect, kernel_container


def fixture(version, kernel_size=65):
    page = 2048 if version < 3 else 4096
    align = lambda value: (value + page - 1) // page * page
    ramdisk_at = align(page + kernel_size)
    after_ramdisk = align(ramdisk_at + 19)
    second_size = 17 if version < 3 else 0
    after_second = align(after_ramdisk + second_size)
    dtbo_size = 13 if 0 < version < 3 else 0
    dtb_at = align(after_second + dtbo_size)
    dtb_size = 11 if version == 2 else 0
    data = bytearray(max(dtb_at + dtb_size, after_second, after_ramdisk) + page)
    data[:8] = b"ANDROID!"
    for at, value in ((8, kernel_size), (40, version)):
        struct.pack_into("<I", data, at, value)
    if version < 3:
        struct.pack_into("<IIII", data, 12, 0x10008000, 19, 0x11000000, second_size)
        struct.pack_into("<I", data, 36, page)
        if version:
            struct.pack_into("<IQI", data, 1632, dtbo_size, after_second, (1648, 1660)[version - 1])
        if version == 2:
            struct.pack_into("<I", data, 1648, dtb_size)
    else:
        struct.pack_into("<I", data, 12, 19)
        struct.pack_into("<I", data, 20, (1580, 1584)[version - 3])
    return bytes(data), ramdisk_at, after_second, dtb_at


class ContainerFields(unittest.TestCase):
    def test_raw_and_gzip_enforce_the_shared_decoded_kernel_budget(self):
        raw = bytearray(128)
        raw[56:60] = b"ARMd"
        with patch("specgen.bootimg.MAX_KERNEL_BYTES", len(raw)):
            self.assertEqual(decode(bytes(raw)), raw)
            self.assertEqual(decode(gzip.compress(raw, mtime=0)), raw)
            with self.assertRaisesRegex(BootImageError, "KERNEL_RAW_DECODE_LIMIT"):
                decode(bytes(raw) + b"x")
            with self.assertRaisesRegex(BootImageError, "KERNEL_GZIP_DECODE_LIMIT"):
                decode(gzip.compress(bytes(raw) + b"x", mtime=0))

    def test_truncated_gzip_keeps_the_decoder_error_contract(self):
        raw = bytearray(128)
        raw[56:60] = b"ARMd"
        with self.assertRaisesRegex(BootImageError, "KERNEL_GZIP_INVALID"):
            decode(gzip.compress(raw, mtime=0)[:-1])

    def test_existing_versions_keep_real_fields(self):
        for version in range(5):
            with self.subTest(version=version):
                data, ramdisk_at, dtbo_at, dtb_at = fixture(version)
                result = _inspect(data)
                self.assertEqual(result["ramdiskSize"], 19)
                self.assertEqual(result["ramdiskOffset"], ramdisk_at)
                self.assertEqual(result["headerSize"], (1632, 1648, 1660, 1580, 1584)[version])
                if 0 < version < 3:
                    self.assertEqual(result["recoveryDtboOffset"], dtbo_at)
                if version == 2:
                    self.assertEqual(result["dtbOffset"], dtb_at)

    def test_init_boot_has_no_implicit_kernel_target(self):
        data, *_ = fixture(4, 0)
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "init_boot.img"
            path.write_bytes(data)
            self.assertEqual(inspect(path)["kernelSize"], 0)
            with self.assertRaisesRegex(BootImageError, "BOOT_KERNEL_MISSING:EXTERNAL_TARGET_REQUIRED"):
                kernel_container(path)

    def test_truncated_ramdisk_is_rejected(self):
        for version in range(5):
            data, ramdisk_at, *_ = fixture(version)
            with self.assertRaisesRegex(BootImageError, "COMPONENT_OUT_OF_RANGE"):
                _inspect(data[:ramdisk_at + 18])

    def test_bad_dtbo_offset_and_unknown_header(self):
        data = bytearray(fixture(2)[0])
        struct.pack_into("<Q", data, 1636, 0x1000000000000000)
        with self.assertRaisesRegex(BootImageError, "DTBO_OFFSET_INVALID"):
            _inspect(data)
        struct.pack_into("<I", data, 40, 5)
        with self.assertRaisesRegex(BootImageError, "HEADER_UNSUPPORTED"):
            _inspect(data)


if __name__ == "__main__":
    unittest.main()
