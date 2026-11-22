"""Read-only capture contract using a non-runnable ELF metadata fixture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "policy_payload_target", Path(__file__).resolve().parents[1] / "policy_payload_target.py")
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class TargetConfigCapture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="maplesu-config-metadata-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "identity.json"
        self.auto = (b"# Generated auto.conf\nCONFIG_ARM64=y\nCONFIG_ARM64_4K_PAGES=y\n"
                     b"CONFIG_MODULES=y\nCONFIG_LOCALVERSION=\"fixture value\"\n")
        self.full = (b"# Full target configuration\nCONFIG_ARM64=y\n"
                     b"CONFIG_ARM64_4K_PAGES=y\n# CONFIG_DYNAMIC_SCS is not set\n"
                     b"CONFIG_MODULES=y\nCONFIG_LOCALVERSION=\"fixture value\"\n")
        for relative, data in (
            ("include/config/auto.conf", self.auto),
            ("include/config/kernel.release", b"metadata-fixture-only\n"),
            ("source/arch/arm64/include/asm/alternative.h",
             b"int apply_alternatives_module(void *start, unsigned int length);\n")):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        names = target.HOOKS + target.LOADER + ["caches_clean_inval_pou", "apply_alternatives_module"]
        base, load_offset, note_offset = 0x100000, 0x100, 0x400
        symbols = [(base + index * 16, "T", name) for index, name in enumerate(names)]
        symbols += [(base + 0x180, "r", "__alt_instructions"),
                    (base + 0x180, "r", "__alt_instructions_end")]
        (self.root / "System.map").write_text(
            "".join(f"{address:016x} {kind} {name}\n" for address, kind, name in symbols),
            encoding="utf-8")
        note = struct.pack("<III", 4, 16, 3) + b"GNU\0" + bytes(range(16))
        ident = b"\x7fELF\x02\x01\x01" + bytes(9)
        # ET_NONE, entry=0, no sections and zero-filled fingerprint bytes: this
        # is a metadata parser input, not a module or executable kernel image.
        header = struct.pack("<16sHHIQQQIHHHHHH", ident, 0, 183, 1, 0,
                             64, 0, 0, 64, 56, 2, 0, 0, 0)
        load = struct.pack("<IIQQQQQQ", 1, 5, load_offset, base, base, 0x200, 0x200, 16)
        notes = struct.pack("<IIQQQQQQ", 4, 4, note_offset, 0, 0, len(note), len(note), 4)
        image = bytearray(note_offset + len(note))
        image[:64] = header
        image[64:120] = load
        image[120:176] = notes
        image[note_offset:] = note
        (self.root / "vmlinux").write_bytes(image)

    def capture(self, full=None):
        if full is not None:
            (self.root / ".config").write_bytes(full)
        target.capture(self.root, self.output)
        return json.loads(self.output.read_text(encoding="utf-8"))

    def test_auto_conf_digest_keeps_its_existing_meaning(self):
        record = self.capture(self.full)
        self.assertEqual(record["configSha256"], sha256(self.auto))
        self.assertNotEqual(record["configSha256"], sha256(self.full))

    def test_full_config_digest_and_length_preserve_exact_bytes(self):
        full = self.full.replace(b"\n", b"\r\n")
        record = self.capture(full)
        self.assertEqual(record.get("targetConfigSha256"), sha256(full))
        self.assertEqual(record.get("targetConfigBytes"), len(full))

    def test_comments_change_full_identity_without_option_drift(self):
        first = self.capture(self.full)
        changed = self.full.replace(b"# Full target configuration", b"# Different harmless comment")
        changed += b"# Additional comment only\n"
        second = self.capture(changed)
        self.assertEqual(first["configSha256"], second["configSha256"])
        self.assertEqual(second.get("targetConfigSha256"), sha256(changed))
        self.assertNotEqual(first.get("targetConfigSha256"), second.get("targetConfigSha256"))

    def test_option_drift_is_rejected(self):
        with self.assertRaises(ValueError):
            self.capture(self.full.replace(b"CONFIG_MODULES=y", b"CONFIG_MODULES=m"))

    def test_kconfig_autoconf_unquoted_strings_keep_exact_file_identities(self):
        auto = self.auto.replace(b'"fixture value"', b'fixture value')
        (self.root / "include/config/auto.conf").write_bytes(auto)
        record = self.capture(self.full)
        self.assertEqual(record["configSha256"], sha256(auto))
        self.assertEqual(record["targetConfigSha256"], sha256(self.full))

    def test_kconfig_autoconf_unescapes_only_the_dotconfig_string_representation(self):
        full = self.full + b'CONFIG_EMPTY=""\nCONFIG_TEXT="\\"quoted\\"\\\\path"\n'
        auto = (self.auto.replace(b'"fixture value"', b'fixture value') +
                b'CONFIG_EMPTY=\nCONFIG_TEXT="quoted"\\path\n')
        (self.root / "include/config/auto.conf").write_bytes(auto)
        record = self.capture(full)
        self.assertEqual(record["targetConfigSha256"], sha256(full))
        with self.assertRaises(ValueError):
            self.capture(full.replace(b'quoted', b'changed'))

    def test_absent_full_config_keeps_legacy_metadata_shape(self):
        record = self.capture()
        self.assertEqual(record["configSha256"], sha256(self.auto))
        self.assertNotIn("targetConfigSha256", record)
        self.assertNotIn("targetConfigBytes", record)


if __name__ == "__main__":
    unittest.main()
