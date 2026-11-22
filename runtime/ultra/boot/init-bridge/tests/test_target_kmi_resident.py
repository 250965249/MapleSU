"""Exercise resident KMI qualification with parsed BTF and ARM64 ELF fixtures."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location("bridge_target_kmi", Path(__file__).parents[1] / "target_kmi.py")
kmi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kmi)


def btf_fixture(integer_bytes=8, missing=False):
    strings = b"\0module\0unsigned long\0__module_address\0"
    rows = [struct.pack("<IIII", strings.index(b"unsigned long"), 1 << 24, integer_bytes, integer_bytes * 8),
            struct.pack("<III", strings.index(b"module"), 4 << 24, 0),
            struct.pack("<III", 0, 2 << 24, 2),
            struct.pack("<IIIII", 0, (13 << 24) | 1, 3, 0, 1)]
    if not missing:
        rows.append(struct.pack("<III", strings.index(b"__module_address"), 12 << 24, 4))
    types = b"".join(rows)
    return struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings


def object_fixture(kcfi=0x240e48bf, missing=False, machine=183):
    strings = b"\0ref___module_address\0msu_native___module_address\0"
    names = b"\0.text\0.bss\0.strtab\0.symtab\0.shstrtab\0"
    text = struct.pack("<II", kcfi, 0xd65f03c0)
    symbols = bytes(24)
    if not missing:
        symbols += struct.pack("<IBBHQQ", strings.index(b"ref___module_address"), 2, 0, 1, 4, 4)
    symbols += struct.pack("<IBBHQQ", strings.index(b"msu_native___module_address"), 17, 0, 2, 0, 8)
    body = bytearray(64)
    sections = [bytes(64)]
    for name, kind, data, link, info, entry, size in (
            (b".text", 1, text, 0, 0, 0, len(text)),
            (b".bss", 8, b"", 0, 0, 0, 8),
            (b".strtab", 3, strings, 0, 0, 0, len(strings)),
            (b".symtab", 2, symbols, 3, 2, 24, len(symbols)),
            (b".shstrtab", 3, names, 0, 0, 0, len(names))):
        sections.append(struct.pack("<IIQQQQIIQQ", names.index(name), kind, 0, 0, len(body), size, link, info, 1, entry))
        body.extend(data)
    section_offset = len(body)
    body.extend(b"".join(sections))
    struct.pack_into("<16sHHIQQQIHHHHHH", body, 0, b"\x7fELF\x02\x01\x01" + bytes(9),
                     1, machine, 1, 0, 0, section_offset, 0, 64, 0, 0, 64, len(sections), 5)
    return bytes(body)


class ResidentKmiChecks(unittest.TestCase):
    def setUp(self):
        self.blobs = {"targetBtf": btf_fixture(), "buildBtf": btf_fixture(),
                      "kernelImage": struct.pack("<III", 0, 0x240e48bf, 0xd65f03c0),
                      "residentTextOwnerReference": object_fixture()}
        self.table = SimpleNamespace(all_offsets=lambda name: [8] if name == "__module_address" else [])

    def qualify(self):
        return kmi.resident_text_owner_qualification(self.blobs, self.table)

    def test_actual_parsers_accept_matching_prototype_and_kcfi(self):
        result = self.qualify()
        self.assertEqual(result["targetPrototype"], "f*smodule(i8:64;)")
        self.assertEqual(result["buildPrototype"], result["targetPrototype"])
        self.assertEqual(result["target"]["kcfi"], result["reference"]["kcfi"])
        self.assertEqual(result["target"]["offset"], 8)

    def test_missing_or_wrong_btf_prototype_is_rejected(self):
        for field in ("targetBtf", "buildBtf"):
            for data in (btf_fixture(missing=True), btf_fixture(integer_bytes=4)):
                with self.subTest(field=field, data=data):
                    old = self.blobs[field]
                    self.blobs[field] = data
                    with self.assertRaisesRegex(ValueError, "RESIDENT.*PROTOTYPE"):
                        self.qualify()
                    self.blobs[field] = old

    def test_wrong_image_or_reference_kcfi_is_rejected(self):
        for field, data in (("kernelImage", struct.pack("<III", 0, 1, 0xd65f03c0)),
                            ("residentTextOwnerReference", object_fixture(kcfi=1))):
            with self.subTest(field=field):
                old = self.blobs[field]
                self.blobs[field] = data
                with self.assertRaisesRegex(ValueError, "RESIDENT.*KCFI"):
                    self.qualify()
                self.blobs[field] = old

    def test_missing_reference_or_wrong_architecture_is_rejected(self):
        for data in (object_fixture(missing=True), object_fixture(machine=62)):
            with self.subTest(data=data):
                self.blobs["residentTextOwnerReference"] = data
                with self.assertRaisesRegex(ValueError, "RESIDENT.*REFERENCE"):
                    self.qualify()

    def test_ambiguous_or_out_of_bounds_target_is_rejected(self):
        for offsets in ([], [8, 12], [0], [1024]):
            with self.subTest(offsets=offsets):
                self.table = SimpleNamespace(all_offsets=lambda name: offsets)
                with self.assertRaisesRegex(ValueError, "RESIDENT.*SYMBOL"):
                    self.qualify()

    def test_default_and_explicit_zero_keep_old_contract_preconditions(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_path = directory / "input"
            input_path.write_bytes(b"existing bound input")
            reference = kmi.identity(input_path)
            contract = {"schema": kmi.SCHEMA, "generator": kmi.identity(Path(kmi.__file__)),
                        "sameMagic": {"policy": "skip-release-word-only-with-actual-crcs"},
                        "inputs": {"buildConfig": reference}, "profile": reference, "targetSymvers": reference}
            path = directory / "contract.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            self.assertEqual(kmi.read_contract(path), contract)
            self.assertEqual(kmi.read_contract(path, require_resident_text_owner=False), contract)
            with self.assertRaisesRegex(ValueError, "RESIDENT.*REQUIRED"):
                kmi.read_contract(path, require_resident_text_owner=True)


if __name__ == "__main__":
    unittest.main()
