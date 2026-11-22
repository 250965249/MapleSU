"""Resolve source inputs using ordinary files; no toolchain invocation."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gen_manifest as G


class ManifestSourcePathsTests(unittest.TestCase):
    def test_sdk_and_repo_relative_sources_and_missing_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sdk = root / "runtime/maplesu-sdk/sdk"
            sdk.mkdir(parents=True)
            sdk_source = sdk / "src/one.cpp"
            repo_source = root / "runtime/ultra/two.cpp"
            for path in (sdk_source, repo_source):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("int fixture;", encoding="utf-8")
            with patch.object(G.S, "REPO_ROOT", root), patch.object(G.S, "SDK_DIR", sdk):
                self.assertEqual(G.resolve_source("src/one.cpp"), sdk_source)
                self.assertEqual(G.resolve_source("runtime/ultra/two.cpp"), repo_source)
                self.assertEqual(G.resolve_source("src/missing.cpp"), sdk / "src/missing.cpp")
                self.assertIsNone(G.resolve_source("../../../../outside.cpp"))

    def test_absolute_traversal_stays_inside_resolved_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sdk = root / "runtime/maplesu-sdk/sdk"
            sdk.mkdir(parents=True)
            with patch.object(G.S, "REPO_ROOT", root), patch.object(G.S, "SDK_DIR", sdk):
                self.assertIsNone(G.resolve_source(str(sdk / "../../../../outside.cpp")))


if __name__ == "__main__":
    unittest.main()
