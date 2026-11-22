#!/usr/bin/env python3
"""Focused host regression tests for candidate isolation and actual payload inputs."""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SDK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK / "tools"))
import build_payloads as BP
import extract_payloads as EP

spec = importlib.util.spec_from_file_location("sdk_build_inputs", SDK / "build.py")
B = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = B
spec.loader.exec_module(B)

TEST_ROOT = SDK / "build" / "p1-build-input-tests"
GLOBALS = ("BUILD_DIR", "OBJ_DIR", "PAYLOAD_GEN_DIR", "TU_DIR", "OUT_DIR", "LINK_DIR",
           "LOG_DIR", "REPORT_DIR", "ARCHIVE_OUT", "HELPER_OUT", "SOURCE_HELPER_OUT",
           "ASSETS_OUT", "SOURCE_PAYLOADS")


def installers(kind="ir"):
    entries = []
    for idx in (48, 49, 50, 52):
        data = json.loads(next((SDK / "manifest").glob(f"{idx:04d}_*.json")).read_text(encoding="utf-8"))
        if kind == "ir":
            original = Path(data["sourceMigration"]["from"])
            source = (Path("reference/restoration/installers") /
                      ("installer_ir" if idx == 48 else "") / original.name).as_posix()
        else:
            source = "src/maplesu_assets/" + data["name"][:-2] + ".cpp"
        data["sources"][0] = source
        if data.get("compose"):
            data["compose"][0]["input"] = source
            data["compose"][0]["tool"] = "clang" if kind == "ir" else "clang++"
            data["compose"][0]["argv"] = ["--target=aarch64-linux-android21", "-Oz", "-fPIC"]
            if kind == "ir":
                data["compose"][0]["argv"] += ["-x", "ir"]
        entries.append(B.ManifestEntry(
            idx, data["name"], [SDK / source for source in data["sources"]],
            data["sources"], data["flagsProfile"], data["status"], data["layout"],
            extra_flags=data.get("extraFlags", []), compose=data.get("compose", [])))
    return entries


class BuildInputTests(unittest.TestCase):
    def setUp(self):
        TEST_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="candidate-", dir=TEST_ROOT)
        self.root = Path(self.temp.name).resolve()
        self.original = {name: getattr(B, name) for name in GLOBALS}
        toolchain = mock.patch.object(B.P, "toolchain_record", return_value={"test_fixture": True})
        toolchain.start()
        self.addCleanup(toolchain.stop)

    def tearDown(self):
        for name, value in self.original.items():
            setattr(B, name, value)
        B.PAYLOAD_SOURCE_OVERRIDES.clear()
        self.temp.cleanup()

    def configure(self):
        with mock.patch.object(B.S, "resolve_toolchain", return_value=SimpleNamespace()), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(B.main(["--report", "--reference-payloads", "--build-dir", str(self.root)]), 0)

    def test_main_build_dir_rebases_headers_and_both_helpers(self):
        self.configure()
        self.assertEqual(B.PAYLOAD_GEN_DIR, self.root / "assets-gen")
        self.assertEqual(B.HELPER_OUT, self.root / "out/helper/autorun_bootstrap")
        self.assertEqual(B.SOURCE_HELPER_OUT, self.root / "out/source/helper/autorun_bootstrap")

    def test_manifest_stage_rebases_all_three_generated_catalog_outputs(self):
        result = SimpleNamespace(ok=True, errors=[], missing_idx=[], summary=lambda: {})
        with mock.patch.object(B.S, "resolve_toolchain", return_value=SimpleNamespace()), \
                mock.patch.object(B.gen_manifest, "generate", return_value=result) as generate, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(B.main(["--gen-manifest", "--build-dir", str(self.root)]), 0)
        for name in ("out_path", "coverage_path", "catalog_path"):
            self.assertTrue(generate.call_args.kwargs[name].is_relative_to(self.root))

    def test_reference_mode_copies_four_assets_without_resolving_a_toolchain(self):
        with mock.patch.object(BP.S, "resolve_toolchain", side_effect=AssertionError("compiler requested")):
            result = BP.build_all(None, self.root / "out/assets", None, reference_only=True)
        self.assertEqual(result["input_mode"], "reference")
        self.assertEqual(result["summary"], {"programs": 4, "built": 0, "reference_copy": 4, "failed": 0})
        for program in result["programs"]:
            self.assertEqual((self.root / "out/assets" / program["asset"]).read_bytes(),
                             (SDK / "assets" / program["asset"]).read_bytes())
        for name in ("build_root", "log_root", "asset_root"):
            self.assertTrue((B.REPO_ROOT / result[name]).resolve().is_relative_to(self.root))

    def test_all_original_ir_arrays_match_the_pinned_assets(self):
        for entry, row in zip(installers(), B.PH.TABLE):
            asset, _name, _header, symbol, member = row
            self.assertEqual(entry.name, member)
            source = next(path for path in entry.sources if path.suffix == ".ll")
            text = source.read_text(encoding="utf-8")
            expected = (SDK / "assets" / asset).read_bytes()
            rewritten, count = B.replace_payload_ir(text, symbol, expected, expected)
            self.assertEqual(rewritten, text)
            self.assertEqual(count, 0)

    def test_rewrite_resizes_arrays_and_all_allocation_copy_publish_lengths(self):
        selected = bytes(range(256)) + b"payload-with-a-new-size"
        for entry, row in zip(installers(), B.PH.TABLE):
            asset, _name, _header, symbol, _member = row
            source = next(path for path in entry.sources if path.suffix == ".ll")
            reference = (SDK / "assets" / asset).read_bytes()
            rewritten, count = B.replace_payload_ir(source.read_text(encoding="utf-8"), symbol,
                                                     reference, selected)
            self.assertEqual(B.payload_ir_array(rewritten, symbol)[1], selected)
            self.assertEqual(count, 1 if entry.idx == 49 else 4)
            self.assertNotIn(str(len(reference)), rewritten)

    def test_prepare_changes_actual_compile_and_compose_inputs_only_in_candidate(self):
        self.configure()
        B.SOURCE_PAYLOADS = True
        BP.build_all(None, B.ASSETS_OUT, None, reference_only=True)
        entries = installers()
        original_hashes = {path: B.S.sha256_file(path) for entry in entries for path in entry.sources}
        for index, row in enumerate(B.PH.TABLE):
            asset = row[0]
            payload = (SDK / "assets" / asset).read_bytes() if index == 3 else b"new-source-payload-" + bytes([index])
            (B.ASSETS_OUT / asset).write_bytes(payload)
        report = {}
        B.prepare_payload_sources(entries, report)
        self.assertEqual(len(B.PAYLOAD_SOURCE_OVERRIDES), 3)
        tc = SimpleNamespace(tool=lambda name: name, has=lambda name: True)
        vendor = B.VendorRules.load(B.VENDOR_RULES_PATH)
        for entry in entries:
            source = entry.sources[0]
            command = B.compile_command(entry, source, self.root / "unit.o", tc, vendor, False)
            actual = Path(command[command.index("-c") + 1])
            self.assertEqual(actual, B.PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source))
        calls = []

        def execute(command, **_kwargs):
            calls.append([str(part) for part in command])
            target = Path(command[command.index("-o") + 1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"object")
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(B.S, "run", side_effect=execute):
            problems = []
            self.assertIsNotNone(B._run_compose_steps(entries[0], tc, problems))
            self.assertEqual(problems, [])
        self.assertIn(str(B.PAYLOAD_SOURCE_OVERRIDES[entries[0].sources[0].resolve()]), calls[0])
        self.assertEqual(original_hashes, {path: B.S.sha256_file(path) for path in original_hashes})

    def test_missing_source_manifest_fails_instead_of_claiming_reference_as_source(self):
        self.configure()
        B.SOURCE_PAYLOADS = True
        with self.assertRaises(B.StageError):
            B.ensure_payload_headers(argparse.Namespace())

    def test_cpp_installers_consume_generated_headers_in_compile_and_compose(self):
        self.configure()
        B.ensure_payload_headers(argparse.Namespace())
        tc = SimpleNamespace(tool=lambda name: name, has=lambda name: True)
        vendor = B.VendorRules.load(B.VENDOR_RULES_PATH)
        native_installers = {
            49: "resetprop_install.cpp",
            50: "webui_loader_install.cpp",
            52: "bootstrap_install.cpp",
        }
        for native in (False, True):
            entries = installers("cxx")
            if native:
                for entry in entries:
                    if entry.idx in native_installers:
                        source = "src/maplesu/install/" + native_installers[entry.idx]
                        entry.sources[0] = SDK / source
                        entry.source_raw[0] = source
            report = {}
            B.prepare_payload_sources(entries, report)
            self.assertEqual(B.PAYLOAD_SOURCE_OVERRIDES, {})
            self.assertEqual(len(report["payload_inputs"]["members"]), 4)
            for entry, row in zip(entries, report["payload_inputs"]["members"]):
                command = B.compile_command(entry, entry.sources[0], self.root / "unit.o", tc, vendor, False)
                self.assertIn("-DMAPLESU_PAYLOAD_ASSETS=1", command)
                self.assertIn(str(B.PAYLOAD_GEN_DIR), command)
                self.assertEqual(row["source_kind"], "cxx")
                self.assertEqual(len(row["generated_headers"]), 6)
                for header in row["generated_headers"]:
                    path = B.REPO_ROOT / header["path"]
                    self.assertEqual(header["sha256"], B.S.sha256_file(path))
                self.assertEqual(row["sha256"], B.S.sha256_file(B.REPO_ROOT / row["asset_path"]))
            publisher = entries[0].sources[1]
            self.assertEqual(B.payload_cpp_flags(entries[0], publisher), [])
            calls = []

            def execute(command, **_kwargs):
                command = [str(part) for part in command]
                if "-c" in command:
                    calls.append(command)
                if "-MF" in command:
                    dep = Path(command[command.index("-MF") + 1])
                    dep.parent.mkdir(parents=True, exist_ok=True)
                    source = (Path(command[command.index("-c") + 1]) if "-c" in command else
                              next(Path(part) for part in command if Path(part).is_file()
                                   and Path(part).suffix in {".cpp", ".c", ".S"}))
                    escaped = str(source).replace("\\", "/").replace(" ", "\\ ").replace("#", "\\#").replace("$", "$$")
                    dep.write_text("maplesu_object: " + escaped + "\n", encoding="utf-8")
                if "-E" not in command:
                    target = Path(command[command.index("-o") + 1])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"object")
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(B.S, "run", side_effect=execute):
                problems = []
                self.assertIsNotNone(B._run_compose_steps(entries[0], tc, problems))
                self.assertEqual(problems, [])
            self.assertEqual(len(calls), 2)
            self.assertIn("-DMAPLESU_PAYLOAD_ASSETS=1", calls[0])
            self.assertNotIn("-DMAPLESU_PAYLOAD_ASSETS=1", calls[1])

    def test_cpp_installers_reject_missing_generated_headers(self):
        self.configure()
        with self.assertRaisesRegex(B.StageError, "generated payload header missing"):
            B.prepare_payload_sources(installers("cxx"), {})

    def test_reference_assets_use_the_pinned_helper_without_a_second_build(self):
        self.configure()
        BP.build_all(None, B.ASSETS_OUT, None, reference_only=True)
        snapshot = SimpleNamespace(root=self.root / "freeze", archive_sha256="reference",
                                   helper_sha256="reference-helper", backends=[])
        report = {}
        with mock.patch.object(B.HB, "build_helper", side_effect=AssertionError("unexpected helper build")):
            B.stage_assets(argparse.Namespace(), report, snapshot, SimpleNamespace())
        reference = (SDK / "assets/autorun_bootstrap.bin").read_bytes()
        self.assertEqual(B.HELPER_OUT.read_bytes(), reference)
        self.assertEqual((B.ASSETS_OUT / "autorun_bootstrap.bin").read_bytes(), reference)
        self.assertFalse(B.SOURCE_HELPER_OUT.exists())
        self.assertEqual(report["assets"]["helper"]["origin"], "reference-copy")

    def test_real_archive_count_preserves_three_duplicate_patch_base_members(self):
        archive = SDK / "build/r8/out/libkernel_module_kit_static.a"
        members = EP.parse_ar_members(archive.read_bytes())
        self.assertEqual(len(members), 260)
        self.assertEqual(sum(member.name == "patch_base.o" for member in members), 3)
        self.assertEqual(len({member.name for member in members}), 258)

    def test_sample_link_pairs_new_memory_code_with_its_source_executor(self):
        self.configure()
        B.OBJ_DIR.mkdir(parents=True, exist_ok=True)
        B.LOG_DIR.mkdir(parents=True, exist_ok=True)
        reference = self.root / "frozen.a"
        reference.write_bytes(b"frozen archive")
        entries = [B.ManifestEntry(idx, name, [], [], "core-oz-elf", "complete", "elf")
                   for idx, name in {**B.SAMPLE_NAMES,
                                    25: "module_base_kernel_func_executor.o"}.items()]
        names = [entry.name for entry in entries]
        commands = []

        def execute(_stage, _what, argv, *_args):
            command = list(map(str, argv))
            commands.append(command)
            if "-o" in command:
                Path(command[command.index("-o") + 1]).write_bytes(b"fixture output")

        tc = SimpleNamespace(tool=lambda name: name)
        report = {}
        with mock.patch.object(B.S, "find_freeze", return_value=SimpleNamespace(archive=reference)), \
                mock.patch.object(B.S, "llvm_ar_list", side_effect=[names, []]), \
                mock.patch.object(B, "run_checked", side_effect=execute), \
                mock.patch.object(B.P, "dependency_receipt", return_value={}), \
                contextlib.redirect_stdout(io.StringIO()):
            B.stage_link_sample(entries, tc, argparse.Namespace(archive=None), report)
        executor = next(entry for entry in entries if entry.idx == 25)
        self.assertIn(str(executor.object_path), commands[-1])
        self.assertIn(executor.name, commands[0])
        self.assertIn(executor.name, report["residual_archive"]["removed"])
        self.assertEqual(reference.read_bytes(), b"frozen archive")

    def gate_receipt(self, allow):
        source = self.root / "receipt.ll"
        source.write_text("@fixture = global i32 0\n", encoding="utf-8")
        obj = self.root / "receipt.o"
        precompile = B.P.precompile_snapshot([], source, obj, self.root, B.S.REPO_ROOT)
        obj.write_bytes(b"fixture object\n")
        record = B.P.file_record(obj, B.S.REPO_ROOT)
        source_path = B.P.canonical_path(source, B.S.REPO_ROOT)
        unit = {"source": source_path, "build_source": source_path,
                "object": record["path"], "bytes": record["size"], "sha256": record["sha256"]}
        unit.update(B.P.dependency_receipt(source, obj, self.root, B.S.REPO_ROOT,
                                         precompile=precompile))
        return B.collect_build_provenance(
            argparse.Namespace(manifest=str(self.root / "absent.jsonl"), gate_allow=allow),
            {"stages_run": ["gate"], "compile": {"rows": [{"outputs": [unit]}]}},
            SimpleNamespace())

    def test_absent_optional_gate_allow_is_recorded_without_missing_input(self):
        missing = self.root / "optional-allow.json"
        with mock.patch.object(B, "GATE_ALLOW_PATH", missing):
            receipt = self.gate_receipt(None)
        self.assertTrue(receipt["closure_complete"], receipt["incomplete_reasons"])
        path = B.P.canonical_path(missing, B.S.REPO_ROOT)
        self.assertIn({"path": path, "role": "build_rule", "present": False},
                      receipt["optional_inputs"])
        self.assertNotIn(path, [row["path"] for row in receipt["inputs"]])
        baseline = B.P.canonical_path(B.member_gate.DEFAULT_BASELINE, B.S.REPO_ROOT)
        self.assertIn(baseline, [row["path"] for row in receipt["inputs"]
                                if "build_rule" in row["roles"]])

    def test_custom_gate_allow_records_the_selected_file(self):
        selected = self.root / "selected-allow.json"
        selected.write_text('{"entries": []}\n', encoding="utf-8")
        default = self.root / "default-allow.json"
        with mock.patch.object(B, "GATE_ALLOW_PATH", default):
            receipt = self.gate_receipt(str(selected))
        self.assertTrue(receipt["closure_complete"], receipt["incomplete_reasons"])
        paths = [row["path"] for row in receipt["inputs"] if "build_rule" in row["roles"]]
        self.assertIn(B.P.canonical_path(selected, B.S.REPO_ROOT), paths)
        self.assertNotIn(B.P.canonical_path(default, B.S.REPO_ROOT), paths)

    def test_missing_explicit_gate_allow_is_incomplete(self):
        missing = self.root / "selected-absent.json"
        receipt = self.gate_receipt(str(missing))
        self.assertFalse(receipt["closure_complete"])
        self.assertTrue(any("selected gate allow file is missing:" in reason
                            for reason in receipt["incomplete_reasons"]))

    def test_extraction_checks_the_actual_embedded_bytes(self):
        archive = SDK / "build/r8/out/libkernel_module_kit_static.a"
        blob = archive.read_bytes()
        members = EP.parse_ar(blob)
        target = EP.TARGETS[0]
        matching = EP.extract_one(*target, blob, members, expected_assets=SDK / "assets")
        self.assertNotIn("error", matching)
        (self.root / "su.bin").write_bytes(b"different source payload")
        mismatch = EP.extract_one(*target, blob, members, expected_assets=self.root)
        self.assertIn("differs from selected asset", mismatch["error"])
        self.assertFalse(mismatch["expected_asset"]["matches"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
