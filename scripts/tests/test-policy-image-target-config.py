"""Preserve embedded configuration bytes through read-only Image capture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zlib


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import policy_payload_image_target as image_target

SPEC = importlib.util.spec_from_file_location(
    "target_config_fixture", SCRIPTS / "tests/test-policy-target-config.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class ImageTargetConfigCapture(unittest.TestCase):
    def check_config(self, newline):
        metadata = fixture.TargetConfigCapture()
        metadata.setUp()
        self.addCleanup(metadata.doCleanups)
        root, base = metadata.root, 0x100000
        full = (metadata.full + b"\n# UTF-8 comment: \xc3\xa9\n").replace(b"\n", newline)
        note = (root / "vmlinux").read_bytes()[0x400:]
        # The four-byte BTF header is only a capture input, with no BTF types.
        image = b"\x9f\xeb\x01\0" + bytes(0x1fc) + note + b"Linux version metadata-fixture-only "
        image += b"IKCFG_ST" + zlib.compress(full, wbits=31) + b"IKCFG_ED"
        (root / "Image").write_bytes(image)
        rows = [(int(address, 16), kind, name)
                for address, kind, name in
                (line.split() for line in (root / "System.map").read_text().splitlines())]
        rows += [(base + 0x200, "r", "__start_notes"),
                 (base + 0x200 + len(note), "r", "__stop_notes")]
        (root / "symbols.tsv").write_text(
            "".join(f"{address - base} {kind} {name}\n" for address, kind, name in rows))
        contract = {"imagePath": "Image", "symbolsPath": "symbols.tsv",
                    "imageSha256": hashlib.sha256(image).hexdigest(), "imageBytes": len(image),
                    "kernelRelease": "metadata-fixture-only", "btf": {"magicOffset": 0, "blobBytes": 4}}
        contract_path = root / "contract.json"
        contract_path.write_text(json.dumps(contract))
        table = SimpleNamespace(text_base=base, relative_base=base, rows=rows,
            layout={"names": "0", "num_syms": len(rows), "token_table": "0",
                    "offsets": "0", "base_relative": True})
        probe = Mock()
        probe.read_names.return_value = [kind + name for _, kind, name in rows]
        probe.read_addresses.return_value = [address for address, _, _ in rows]
        output = root / "captured"
        with patch.object(image_target, "ROOT", root), \
                patch.object(image_target, "decode", return_value=table), \
                patch.object(image_target, "_Probe", return_value=probe):
            image_target.capture_image(contract_path, output, root / "source")
        self.assertEqual((output / "target.config").read_bytes(), full)
        mapping = output / "raw-image-metadata"
        self.assertEqual((mapping / ".config").read_bytes(), full)
        identity = json.loads((output / "target-identity.json").read_text())
        self.assertEqual(identity["targetConfigSha256"], hashlib.sha256(full).hexdigest())
        self.assertEqual(identity["targetConfigBytes"], len(full))
        auto = (mapping / "include/config/auto.conf").read_bytes()
        self.assertEqual(identity["configSha256"], hashlib.sha256(auto).hexdigest())
        self.assertNotEqual(identity["configSha256"], identity["targetConfigSha256"])
        self.assertEqual(identity["rawImageReference"]["sha256"], contract["imageSha256"])

    def test_lf_config_preserves_comments_and_full_identity(self):
        self.check_config(b"\n")

    def test_crlf_config_preserves_exact_bytes(self):
        self.check_config(b"\r\n")


if __name__ == "__main__":
    unittest.main()
