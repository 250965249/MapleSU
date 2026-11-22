"""Integrity contract tests; temporary inputs never alter retained sources."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_sources", ROOT / "verify_sources.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class RetainedSourceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for provider, name in (("ghostlock", "upstream-manifest.json"), ("dirtyfrag", "source-manifest.json")):
            destination = self.root / provider
            destination.mkdir()
            shutil.copyfile(ROOT / provider / name, destination / name)
            shutil.copytree(ROOT / provider / "upstream", destination / "upstream")
        self.manifest_path = self.root / "ghostlock/upstream-manifest.json"
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8-sig"))

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_original_snapshot(self):
        result = module.verify(self.root)
        self.assertEqual(result["ghostlock"]["files"], len(self.manifest["files"]))
        self.assertGreater(result["dirtyfrag"]["files"], 0)

    def test_modified_input(self):
        path = self.root / "ghostlock" / self.manifest["files"][0]["path"]
        path.write_bytes(path.read_bytes() + b"x")
        with self.assertRaisesRegex(ValueError, "identity mismatch"): module.verify(self.root)

    def test_missing_input(self):
        (self.root / "ghostlock" / self.manifest["files"][0]["path"]).unlink()
        with self.assertRaisesRegex(ValueError, "Missing ordinary"): module.verify(self.root)

    def test_unmanifested_input(self):
        (self.root / "ghostlock/upstream/extra.txt").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "Unmanifested"): module.verify(self.root)

    def test_duplicate(self):
        self.manifest["files"].append(self.manifest["files"][0])
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "duplicate"): module.verify(self.root)

    def test_traversal(self):
        self.manifest["files"][0]["path"] = "../outside.txt"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Invalid"): module.verify(self.root)

if __name__ == "__main__": unittest.main(verbosity=2)
