import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("derive", ROOT / "derive.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OverlayTest(unittest.TestCase):
    def test_deterministic_overlay_and_original_bytes(self):
        paths = [ROOT / "upstream/src/core/main.cpp", ROOT / "upstream/src/core/attack/ops.cpp"]
        original = [path.read_bytes() for path in paths]
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            first = module.derive(output)
            generated = {key: (output / key).read_bytes() for key in first}
            self.assertEqual(first, module.derive(output))
            self.assertEqual(generated, {key: (output / key).read_bytes() for key in first})
            entry = generated["src/core/main.cpp"].decode()
            ops = generated["src/core/attack/ops.cpp"].decode()
            self.assertIn("int maplesu_ghostlock_upstream_main(", entry)
            self.assertNotIn("int main(", entry)
            self.assertNotIn("void write_root_script(void)", ops)
            upstream = original[1].decode()
            start = upstream.index("    void write_root_script(void) {")
            end = upstream.index("    /* Find a task through perf sample records. */")
            self.assertTrue(ops.startswith(upstream[:start]))
            self.assertTrue(ops.endswith(upstream[end:]))
            self.assertEqual(json.loads((output / "overlay.json").read_text())["upstreamCommit"],
                             "b67359641c8663e5184abba73ecdf2c456dce3e7")
        self.assertEqual(original, [path.read_bytes() for path in paths])

    def test_changed_input_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); fixture = base / "fixture"
            for relative in ["upstream-manifest.json", "upstream/src/core/main.cpp", "upstream/src/core/attack/ops.cpp"]:
                target = fixture / relative; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            path = fixture / "upstream/src/core/attack/ops.cpp"
            path.write_bytes(path.read_bytes() + b"\n")
            output = base / "out"
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                module.derive(output, fixture)
            self.assertFalse(output.exists())

    def test_output_in_source_tree_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside retained"):
            module.derive(ROOT / "upstream/generated")


if __name__ == "__main__":
    unittest.main()
