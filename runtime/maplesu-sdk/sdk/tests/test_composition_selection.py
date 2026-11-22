"""Source-composition lock tests using ordinary files and no build execution."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]
sys.path[:0] = [str(SDK / "tools"), str(ROOT / "scripts")]
import source_provenance as P
import build_helper as H
import source_sdk_delivery as D

spec = importlib.util.spec_from_file_location("composition_build", SDK / "build.py")
B = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = B
spec.loader.exec_module(B)


class CompositionSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sdk-composition-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.write("src/fixture.ll", "; ordinary provenance fixture\n")
        self.lock = self.root / "source-selection.json"
        self.write_lock()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")
        return path

    def write_lock(self, value=None):
        value = (dict(schema="maplesu-sdk-source-selection/1", files=[P.file_record(self.source, self.root)])
                 if value is None else value)
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        return value

    def minimal_report(self):
        selection = B.capture_source_selection(self.lock, self.root)
        snapshots = [{**selection["manifest"], "roles": ["source_selection"]},
                     *[{**item, "roles": ["selected_source"]} for item in selection["files"]]]
        obj = self.root / "fixture.o"
        obj.write_bytes(b"ordinary object identity fixture")
        before = P.precompile_snapshot(["fixture-only", "-c", str(self.source), "-o", str(obj)],
                                       self.source, obj, self.root, self.root)
        unit = dict(idx=0, name="fixture.o", source="src/fixture.ll", build_source="src/fixture.ll",
                    object="fixture.o", bytes=obj.stat().st_size, sha256=P.file_record(obj, self.root)["sha256"],
                    stage="compile", **P.dependency_receipt(self.source, obj, self.root, self.root, precompile=before))
        toolchain = dict(ndk_root="fixture-only", ndk_version="fixture-only", target="fixture-only",
                         versions={name: "fixture-only" for name in ("clang", "llvm-ar", "ld.lld")})
        proof = P.build_receipt([unit], [(self.lock, "source_selection"), (self.source, "selected_source")],
                                self.root, toolchain=toolchain, input_snapshots=snapshots)
        proof["optional_inputs"] = [dict(path="absent-optional.json", role="build_rule", present=False)]
        report = dict(source_selection=selection, provenance=proof, stages_run=["gate"],
                      compile=dict(rows=[dict(idx=0, name="fixture.o", outputs=[unit])]), compose=dict(rows=[]))
        return report

    def test_capture_exact_selection_and_cli_option_without_build(self):
        captured = B.capture_source_selection(self.lock, self.root)
        self.assertEqual(captured["manifest"], P.file_record(self.lock, self.root))
        self.assertEqual(captured["files"], [P.file_record(self.source, self.root)])
        args = B.parse_args(["--source-selection", str(self.lock), "--report"])
        self.assertEqual(args.source_selection, self.lock)

    def test_capture_rejects_source_changed_since_lock(self):
        self.source.write_text("; changed source\n", encoding="utf-8")
        with self.assertRaisesRegex(B.StageError, "selected input changed"):
            B.capture_source_selection(self.lock, self.root)

    def test_capture_rejects_lock_changed_during_capture(self):
        file_record = P.file_record
        def mutate(path, root):
            value = file_record(path, root)
            if Path(path).resolve() == self.source:
                self.lock.write_text(self.lock.read_text() + "\n", encoding="utf-8")
            return value
        with patch.object(P, "file_record", side_effect=mutate):
            with self.assertRaisesRegex(B.StageError, "selection changed during capture"):
                B.capture_source_selection(self.lock, self.root)

    def test_capture_rejects_duplicate_and_escaping_selected_paths(self):
        row = P.file_record(self.source, self.root)
        for name in (row["path"], "../outside.ll", self.source.as_posix()):
            with self.subTest(path=name):
                duplicate = dict(row, path=name)
                self.write_lock(dict(schema="maplesu-sdk-source-selection/1", files=[row, duplicate]))
                with self.assertRaises(B.StageError):
                    B.capture_source_selection(self.lock, self.root)

    def test_capture_rejects_non_object_bad_schema_missing_and_malformed_files(self):
        row = P.file_record(self.source, self.root)
        invalid = [[], "text", 1, dict(schema="bad", files=[row]),
                   dict(schema="maplesu-sdk-source-selection/1", files=[]),
                   dict(schema="maplesu-sdk-source-selection/1", files=[None]),
                   dict(schema="maplesu-sdk-source-selection/1", files=[{}]),
                   dict(schema="maplesu-sdk-source-selection/1", files=[dict(row, path="missing.ll")])]
        for value in invalid:
            with self.subTest(value=value):
                self.write_lock(value)
                with self.assertRaises(B.StageError):
                    B.capture_source_selection(self.lock, self.root)

    def test_capture_rejects_missing_or_external_lock(self):
        with self.assertRaises(B.StageError):
            B.capture_source_selection(self.root / "missing-lock.json", self.root)
        with tempfile.TemporaryDirectory(prefix="sdk-external-lock-") as directory:
            outside = Path(directory) / "selection.json"
            outside.write_bytes(self.lock.read_bytes())
            with self.assertRaises(B.StageError):
                B.capture_source_selection(outside, self.root)

    def test_selected_source_or_lock_change_after_capture_blocks_receipt(self):
        for change_source in (True, False):
            with self.subTest(change_source=change_source):
                self.source.write_text("; ordinary provenance fixture\n", encoding="utf-8")
                self.write_lock()
                report = self.minimal_report()
                path = self.source if change_source else self.lock
                path.write_text(path.read_text() + "\n", encoding="utf-8")
                receipt = P.build_receipt([], [(self.lock, "source_selection"), (self.source, "selected_source")],
                                          self.root, input_snapshots=report["provenance"]["input_snapshots"])
                self.assertFalse(receipt["closure_complete"])
                self.assertTrue(any("input changed" in item for item in receipt["incomplete_reasons"]))

    def test_minimal_v2_validator_binds_lock_source_roles_and_pre_snapshots(self):
        report = self.minimal_report()
        self.assertTrue(report["provenance"]["closure_complete"])
        self.assertEqual(D.verify_build_provenance(report, self.root), report["provenance"]["inputs"])

    def test_v2_validator_rejects_selected_source_role_or_snapshot_missing(self):
        report = self.minimal_report()
        for missing in ("role", "snapshot"):
            with self.subTest(missing=missing):
                altered = copy.deepcopy(report)
                source = "src/fixture.ll"
                if missing == "role":
                    row = next(item for item in altered["provenance"]["inputs"] if item["path"] == source)
                    row["roles"].remove("selected_source")
                    row = next(item for item in altered["provenance"]["input_snapshots"] if item["path"] == source)
                    row["roles"] = ["tu"]
                else:
                    altered["provenance"]["input_snapshots"] = [item for item in altered["provenance"]["input_snapshots"]
                                                               if item["path"] != source]
                with self.assertRaisesRegex(AssertionError, "SOURCE_SDK_SELECTION_"):
                    D.verify_build_provenance(altered, self.root)

    def test_v2_validator_rejects_selection_content_or_file_tampering(self):
        report = self.minimal_report()
        altered = copy.deepcopy(report)
        altered["source_selection"]["files"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(AssertionError, "SOURCE_SDK_SELECTION_CONTENT"):
            D.verify_build_provenance(altered, self.root)
        self.lock.write_text(self.lock.read_text() + "\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "SOURCE_SDK_STALE"):
            D.verify_build_provenance(report, self.root)

    def test_v2_validator_rejects_malformed_duplicate_and_external_selected_records(self):
        report = self.minimal_report()
        row = copy.deepcopy(report["source_selection"]["files"][0])
        invalid = [None, dict(row, size=True), dict(row, path="../outside.ll"), dict(row, path="src/../src/fixture.ll"),
                   dict(row, path=self.source.as_posix()), dict(row, sha256="bad")]
        for value in invalid:
            with self.subTest(value=value):
                altered = copy.deepcopy(report)
                selected = dict(schema="maplesu-sdk-source-selection/1", files=[value])
                self.write_lock(selected)
                self.rebind_lock(altered)
                altered["source_selection"]["files"] = selected["files"]
                with self.assertRaisesRegex(AssertionError, "SOURCE_SDK_SELECTION_(RECORD|PATH|CANONICAL_PATH)"):
                    D.verify_build_provenance(altered, self.root)
        self.write_lock(dict(schema="maplesu-sdk-source-selection/1", files=[row, row]))
        altered = copy.deepcopy(report)
        self.rebind_lock(altered)
        altered["source_selection"]["files"] = [row, row]
        with self.assertRaisesRegex(AssertionError, "SOURCE_SDK_SELECTION_PATH"):
            D.verify_build_provenance(altered, self.root)
        self.write_lock()
        for path in (self.lock.as_posix(), "unused/../source-selection.json"):
            with self.subTest(lock_path=path):
                altered = self.minimal_report()
                original = altered["source_selection"]["manifest"]["path"]
                altered["source_selection"]["manifest"]["path"] = path
                for rows in (altered["provenance"]["inputs"], altered["provenance"]["input_snapshots"]):
                    for item in rows:
                        if item["path"] == original:
                            item["path"] = path
                with self.assertRaisesRegex(AssertionError, "SOURCE_SDK_SELECTION_"):
                    D.verify_build_provenance(altered, self.root)

    def rebind_lock(self, report):
        """Keep identity checks valid so malformed-record validation is reached."""
        new = P.file_record(self.lock, self.root)
        report["source_selection"]["manifest"] = new
        for rows in (report["provenance"]["inputs"], report["provenance"]["input_snapshots"]):
            for row in rows:
                if row["path"] == new["path"]:
                    row.update(new)

    def test_historical_v1_without_selection_keeps_original_validation(self):
        report = self.minimal_report()
        del report["source_selection"]
        report["provenance"]["schema"] = "maplesu-sdk-source-provenance/1"
        del report["provenance"]["input_snapshots"]
        for unit in [report["provenance"]["translation_units"][0], report["compile"]["rows"][0]["outputs"][0]]:
            for name in ("precompile", "precompile_complete", "precompile_errors"):
                unit.pop(name)
        D.verify_build_provenance(report, self.root)
        report["source_selection"] = B.capture_source_selection(self.lock, self.root)
        with self.assertRaisesRegex(AssertionError, "SELECTION_PROVENANCE_VERSION"):
            D.verify_build_provenance(report, self.root)


class HelperManifestParseIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sdk-helper-manifest-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sdk = self.root / "runtime/maplesu-sdk/sdk"
        self.sdk.mkdir(parents=True)
        self.source = self.sdk / "fixture.cpp"
        self.source.write_text("int fixture;", encoding="utf-8")
        self.manifest = self.sdk / "helper.json"
        self.manifest.write_text(json.dumps(dict(sources=["fixture.cpp"], flagsProfile="core-oz-elf")), encoding="utf-8")
        self.patches = [patch.object(H, "SDK_DIR", self.sdk), patch.object(H.S, "REPO_ROOT", self.root)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_load_manifest_keeps_parse_time_identity_and_missing_file_errors(self):
        before = P.file_record(self.manifest, self.root)
        loaded = H.load_manifest(self.manifest)
        self.assertEqual(loaded["_manifest_input_snapshot"], before)
        self.assertEqual(loaded["_resolved_sources"], [self.source])
        with self.assertRaises(H.HelperBuildError) as caught:
            H.load_manifest(self.sdk / "missing.json")
        self.assertEqual(caught.exception.code, H.EXIT_MANIFEST)

    def test_load_manifest_rejects_change_between_read_and_recheck(self):
        file_record = P.file_record
        calls = []
        def mutate(path, root):
            if Path(path) == self.manifest:
                calls.append(path)
                if len(calls) == 2:
                    self.manifest.write_text(self.manifest.read_text() + "\n", encoding="utf-8")
            return file_record(path, root)
        with patch.object(P, "file_record", side_effect=mutate):
            with self.assertRaisesRegex(H.HelperBuildError, "changed during parsing"):
                H.load_manifest(self.manifest)

    def test_build_helper_rejects_missing_or_stale_parse_identity_before_tools(self):
        for stale in (False, True):
            with self.subTest(stale=stale):
                loaded = H.load_manifest(self.manifest)
                if stale:
                    self.manifest.write_text(self.manifest.read_text() + "\n", encoding="utf-8")
                else:
                    loaded.pop("_manifest_input_snapshot")
                with patch.object(H, "_run", side_effect=AssertionError("compile boundary must not run")):
                    with self.assertRaisesRegex(H.HelperBuildError, "changed since parsing" if stale else "snapshot is missing"):
                        H.build_helper(None, self.root / "out/helper", record=loaded)


if __name__ == "__main__":
    unittest.main()
