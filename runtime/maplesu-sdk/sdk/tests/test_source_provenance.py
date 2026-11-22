#!/usr/bin/env python3
"""Focused build receipt tests; no device or production-output writes."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

SDK = Path(os.environ.get("MAPLESU_TEST_SDK", Path(__file__).resolve().parents[1]))
CANDIDATE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CANDIDATE / "tools"), str(SDK / "tools")]
import source_provenance as P


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "main.cpp"
        self.source.write_text('#include "one.h"\n', encoding="utf-8")
        self.header = self.root / "one.h"
        self.header.write_text("int one;\n", encoding="utf-8")
        self.obj = self.root / "main.o"
        self.obj.write_bytes(b"fixture object")

    def make_dependencies(self):
        P.depfile_path(self.obj).write_text("maplesu_object: main.cpp one.h\n", encoding="utf-8")
        argv = ["fixture-clang", "-c", str(self.source), "-o", str(self.obj)]
        def scan(command, **kwargs):
            Path(command[command.index("-MF") + 1]).write_text(
                "maplesu_object: main.cpp one.h\n", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(P.S, "run", side_effect=scan):
            before = P.precompile_snapshot(argv, self.source, self.obj, self.root, self.root)
        return P.dependency_receipt(self.source, self.obj, self.root, self.root, precompile=before)

    def make_unit(self):
        return {"idx": 48, "name": "su.o", "source": "main.cpp", "build_source": "main.cpp",
                "object": "main.o", "bytes": self.obj.stat().st_size,
                "sha256": hashlib.sha256(self.obj.read_bytes()).hexdigest(), **self.make_dependencies()}

    def test_depfile_escaping(self):
        text = "maplesu_object: C:/code/main.cpp C:/code/a\\ b.h \\\n C:/code/hash\\#x.h C:/code/$$cache.h C\\:/code/path.h dir\\\\file.h\n"
        self.assertEqual(P.parse_depfile(text), ["C:/code/main.cpp", "C:/code/a b.h",
                         "C:/code/hash#x.h", "C:/code/$cache.h", "C:/code/path.h", "dir\\file.h"])

    def test_bad_target_is_rejected(self):
        with self.assertRaises(ValueError):
            P.parse_depfile("C:/wrong.o: main.cpp")

    def test_dependency_closure_contains_only_actual_inputs(self):
        (self.root / "unused.h").write_text("int unused;", encoding="utf-8")
        receipt = self.make_dependencies()
        self.assertTrue(receipt["dependency_complete"])
        self.assertEqual([row["path"] for row in receipt["dependencies"]], ["main.cpp", "one.h"])

    def test_header_change_changes_hash(self):
        before = self.make_dependencies()["dependencies"]
        self.header.write_text("int changed;", encoding="utf-8")
        after = self.make_dependencies()["dependencies"]
        self.assertNotEqual(before[1]["sha256"], after[1]["sha256"])

    def test_missing_depfile_is_incomplete(self):
        receipt = P.dependency_receipt(self.source, self.obj, self.root, self.root)
        self.assertFalse(receipt["dependency_complete"])
        self.assertEqual(receipt["dependency_kind"], "compiler-mmd")

    def test_depfile_must_contain_the_actual_source(self):
        (self.root / "other.cpp").write_text("int other;\n", encoding="utf-8")
        P.depfile_path(self.obj).write_text("maplesu_object: other.cpp one.h\n", encoding="utf-8")
        receipt = P.dependency_receipt(self.source, self.obj, self.root, self.root)
        self.assertFalse(receipt["dependency_complete"])
        self.assertIn("depfile does not contain the compiled source", receipt["dependency_errors"][0])

    def test_ir_is_an_explicit_input_not_header_recovery(self):
        ir = self.root / "main.ll"
        ir.write_text("; lowered source\n", encoding="utf-8")
        self.assertEqual(P.dependency_flags(ir, self.obj), [])
        before = P.precompile_snapshot(["fixture-clang", "-c", str(ir), "-o", str(self.obj)],
                                       ir, self.obj, self.root, self.root)
        receipt = P.dependency_receipt(ir, self.obj, self.root, self.root, precompile=before)
        self.assertTrue(receipt["dependency_complete"])
        self.assertEqual(receipt["dependency_kind"], "ir-source")
        self.assertEqual([row["path"] for row in receipt["dependencies"]], ["main.ll"])
        proof = P.build_receipt([{"source": "main.ll", "object": "main.o",
            "bytes": self.obj.stat().st_size, "sha256": hashlib.sha256(self.obj.read_bytes()).hexdigest(),
            **receipt}], [], self.root)
        self.assertTrue(proof["closure_complete"])
        self.assertFalse(proof["runtime_acceptance"])
        self.assertEqual(proof["translation_units"][0]["dependency_kind"], "ir-source")

    def test_merged_receipt_uses_same_dependency_records(self):
        unit = self.make_unit()
        receipt = P.build_receipt([unit], [(self.header, "generated_header")], self.root)
        self.assertEqual(receipt["translation_units"][0]["dependencies"],
                         [row["path"] for row in unit["dependencies"]])
        self.assertEqual(receipt["inputs"][1]["roles"], ["generated_header", "header"])
        self.assertTrue(receipt["closure_complete"])
        self.assertFalse(receipt["runtime_acceptance"])

    def test_header_changed_after_dependency_snapshot_is_incomplete(self):
        unit = self.make_unit()
        self.header.write_text("int changed;", encoding="utf-8")
        receipt = P.build_receipt([unit], [], self.root)
        self.assertFalse(receipt["closure_complete"])
        self.assertIn("input changed since build snapshot: one.h", receipt["incomplete_reasons"])

    def test_missing_recorded_header_is_incomplete(self):
        unit = self.make_unit()
        self.header.unlink()
        receipt = P.build_receipt([unit], [], self.root)
        self.assertFalse(receipt["closure_complete"])
        self.assertTrue(any(reason.startswith("input one.h:") for reason in receipt["incomplete_reasons"]))

    def test_child_inputs_are_revalidated_without_parent_overlap(self):
        child = P.build_receipt([], [(self.header, "header")], self.root)
        self.header.write_text("int changed;", encoding="utf-8")
        receipt = P.build_receipt([], [], self.root, children=[child])
        self.assertFalse(receipt["closure_complete"])
        self.assertIn("input changed since build snapshot: one.h", receipt["incomplete_reasons"])

    def test_object_changed_after_compile_snapshot_is_incomplete(self):
        unit = self.make_unit()
        self.obj.write_bytes(b"changed object")
        receipt = P.build_receipt([unit], [], self.root)
        self.assertFalse(receipt["closure_complete"])
        self.assertIn("object changed since build snapshot: main.o", receipt["incomplete_reasons"])

    def test_missing_object_is_incomplete(self):
        unit = self.make_unit()
        self.obj.unlink()
        receipt = P.build_receipt([unit], [], self.root)
        self.assertFalse(receipt["closure_complete"])
        self.assertTrue(any(reason.startswith("object main.o:") for reason in receipt["incomplete_reasons"]))

    def test_missing_object_identity_is_incomplete(self):
        unit = self.make_unit()
        del unit["sha256"]
        receipt = P.build_receipt([unit], [], self.root)
        self.assertFalse(receipt["closure_complete"])
        self.assertIn("object identity receipt missing: main.o", receipt["incomplete_reasons"])

    def test_child_object_is_revalidated(self):
        child = P.build_receipt([self.make_unit()], [], self.root)
        self.obj.write_bytes(b"changed object")
        receipt = P.build_receipt([], [], self.root, children=[child])
        self.assertFalse(receipt["closure_complete"])
        self.assertIn("object changed since build snapshot: main.o", receipt["incomplete_reasons"])

    def test_conflicting_child_snapshot_is_visible(self):
        child = P.build_receipt([], [(self.header, "header")], self.root)
        self.header.write_text("int changed;", encoding="utf-8")
        receipt = P.build_receipt([], [(self.header, "header")], self.root, children=[child])
        self.assertFalse(receipt["closure_complete"])
        self.assertIn("input changed", receipt["incomplete_reasons"][0])

    def test_dependency_flags_do_not_change_target_or_output(self):
        flags = P.dependency_flags(self.source, self.obj)
        self.assertEqual(flags, ["-MMD", "-MF", str(self.obj) + ".d", "-MT", "maplesu_object"])


class PayloadHeaderPathsTests(unittest.TestCase):
    def test_cross_drive_log_preserves_all_generated_bytes(self):
        path = CANDIDATE / "tools" / "gen_payload_headers.py"
        spec = importlib.util.spec_from_file_location("candidate_payload_headers", path)
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            out = root / "headers"
            assets.mkdir()
            records = []
            for index, (name, *_rest) in enumerate(generator.TABLE):
                blob = b"\x7fELF" + bytes([index])
                (assets / name).write_bytes(blob)
                records.append({"asset": name, "size": len(blob),
                                "sha256": hashlib.sha256(blob).hexdigest()})
            (assets / "ASSETS.json").write_text(json.dumps({"assets": records}), encoding="utf-8")
            produced, table, errors, _ = generator.build(str(assets))
            self.assertFalse(errors)
            with patch.object(generator.os.path, "relpath", side_effect=ValueError("different drives")):
                with contextlib.redirect_stdout(io.StringIO()) as log:
                    code = generator.main(["--assets", str(assets), "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertIn(str(out), log.getvalue())
            expected = produced + [(generator.UMBRELLA, generator.render_umbrella(table)),
                                   (generator.SIZES_HEADER, generator.render_sizes(table))]
            for name, text in expected:
                self.assertEqual((out / name).read_bytes(), text.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
