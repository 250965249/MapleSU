"""Exercise build provenance with fake compiler/archive boundaries only."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]
sys.path[:0] = [str(SDK / "tools"), str(ROOT / "scripts")]
import source_provenance as P
import source_backend as SB
import build_payloads as BP
import source_sdk_delivery as D

spec = importlib.util.spec_from_file_location("candidate_build_boundary", SDK / "build.py")
B = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = B
spec.loader.exec_module(B)
stage_spec = importlib.util.spec_from_file_location("candidate_sdk_stage", ROOT / "scripts/stage-source-sdk.py")
ST = importlib.util.module_from_spec(stage_spec)
stage_spec.loader.exec_module(ST)


def done(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def escape_dep(path):
    return str(path).replace("\\", "/").replace(" ", "\\ ").replace("#", "\\#").replace("$", "$$")


class FileCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sdk-boundary-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.write("src/main.cpp", '#include "one.h"\n')
        self.header = self.write("src/one.h", "int one;\n")
        self.obj = self.root / "output/main.o"
        self.obj.parent.mkdir()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def compiler(self, argv, **kwargs):
        argv = list(map(str, argv))
        if "-MF" in argv:
            dep = Path(argv[argv.index("-MF") + 1])
            dep.parent.mkdir(parents=True, exist_ok=True)
            source = (Path(argv[argv.index("-c") + 1]) if "-c" in argv else
                      next((Path(value) for value in argv if Path(value).is_file()
                            and Path(value).suffix in {".cpp", ".c", ".S"}), self.source))
            paths = [source] + ([self.header] if source.suffix not in P.IR_SUFFIXES else [])
            dep.write_text("maplesu_object: " + " ".join(map(escape_dep, paths)) + "\n", encoding="utf-8")
        if "-E" not in argv:
            output = Path(argv[argv.index("-o") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"BC\xc0\xdefixture" if "-emit-llvm" in argv else b"\x7fELFfixture")
        return done()

    def receipt(self, source=None, obj=None):
        source, obj = source or self.source, obj or self.obj
        argv = ["fixture-clang", *P.dependency_flags(source, obj), "-c", str(source), "-o", str(obj)]
        with patch.object(P.S, "run", side_effect=self.compiler):
            before = P.precompile_snapshot(argv, source, obj, self.root, self.root)
            self.compiler(argv)
        return before, P.dependency_receipt(source, obj, self.root, self.root, precompile=before)

    def unit(self, source=None, obj=None):
        source, obj = source or self.source, obj or self.obj
        before, receipt = self.receipt(source, obj)
        return dict(source=P.canonical_path(source, self.root), build_source=P.canonical_path(source, self.root),
                    object=P.canonical_path(obj, self.root), bytes=obj.stat().st_size,
                    sha256=P.file_record(obj, self.root)["sha256"], stage="compile", **receipt)


class PrecompileBoundaryTests(FileCase):
    def test_stable_before_after_and_distinct_depfiles(self):
        before, receipt = self.receipt()
        self.assertTrue(receipt["precompile_complete"])
        self.assertTrue(before["complete"])
        self.assertIn("-E", before["scan_command"])
        self.assertNotIn("-c", before["scan_command"])
        self.assertEqual(Path(before["scan_command"][before["scan_command"].index("-MF") + 1]),
                         Path(str(self.obj) + ".precompile.d"))
        self.assertTrue(P.depfile_path(self.obj).is_file())
        self.assertEqual(before["stability_scope"], "before-after-observation-not-atomic-freeze")

    def test_persistent_source_and_header_edits_are_incomplete(self):
        for path in (self.source, self.header):
            with self.subTest(path=path.name):
                before, _ = self.receipt()
                path.write_text("changed " + path.read_text(), encoding="utf-8")
                receipt = P.dependency_receipt(self.source, self.obj, self.root, self.root, precompile=before)
                self.assertFalse(receipt["precompile_complete"])
                self.assertTrue(any("input changed during compilation" in row for row in receipt["precompile_errors"]))

    def test_actual_dependencies_differ_from_precompile(self):
        before, _ = self.receipt()
        P.depfile_path(self.obj).write_text("maplesu_object: src/main.cpp\n", encoding="utf-8")
        receipt = P.dependency_receipt(self.source, self.obj, self.root, self.root, precompile=before)
        self.assertFalse(receipt["precompile_complete"])
        self.assertIn("compiler dependencies differ from precompile snapshot", receipt["precompile_errors"])

    def test_failed_scan_and_scan_without_source_are_incomplete(self):
        argv = ["fixture-clang", "-c", str(self.source), "-o", str(self.obj)]
        with patch.object(P.S, "run", return_value=done(7, stderr="fixture first error")):
            before = P.precompile_snapshot(argv, self.source, self.obj, self.root, self.root)
        self.assertFalse(before["complete"])
        self.assertIn("exit 7", before["errors"][0])
        def omit(argv, **kwargs):
            Path(argv[argv.index("-MF") + 1]).write_text("maplesu_object: src/one.h\n", encoding="utf-8")
            return done()
        with patch.object(P.S, "run", side_effect=omit):
            before = P.precompile_snapshot(argv, self.source, self.obj, self.root, self.root)
        self.assertFalse(before["complete"])
        self.assertIn("does not contain", before["errors"][0])

    def test_missing_or_misbound_precompile_blocks_closure(self):
        unit = self.unit()
        del unit["precompile"]
        unit["precompile_complete"] = True
        proof = P.build_receipt([unit], [], self.root)
        self.assertFalse(proof["closure_complete"])
        self.assertIn("precompile input snapshot missing", proof["incomplete_reasons"])
        unit = self.unit()
        unit["precompile"]["object"] = "other.o"
        proof = P.build_receipt([unit], [], self.root)
        self.assertFalse(proof["closure_complete"])
        self.assertIn("precompile source/object selection differs", proof["incomplete_reasons"])

    def test_two_stage_ir_and_child_object_identity(self):
        first = self.unit(obj=self.obj.with_suffix(".bc"))
        final = self.unit(source=self.obj.with_suffix(".bc"))
        final["source"] = P.canonical_path(self.source, self.root)
        final["compile_steps"] = [first]
        proof = P.build_receipt([final], [], self.root)
        self.assertTrue(proof["closure_complete"], proof["incomplete_reasons"])
        self.assertEqual(proof["translation_units"][0]["dependency_kind"], "ir-source")
        self.assertFalse(proof["runtime_acceptance"])
        self.obj.with_suffix(".bc").write_bytes(b"changed intermediate")
        changed = P.build_receipt([], [], self.root, children=[proof])
        self.assertFalse(changed["closure_complete"])
        self.assertTrue(any("object changed" in row for row in changed["incomplete_reasons"]))

    def test_explicit_generator_input_snapshot_detects_execution_edit(self):
        generator = self.write("generate.py", "# fixture original\n")
        before = P.snapshot_inputs([(generator, "build_script")], self.root)
        generator.write_text("# fixture changed\n", encoding="utf-8")
        proof = P.build_receipt([], [(generator, "build_script")], self.root, input_snapshots=before)
        self.assertFalse(proof["closure_complete"])
        self.assertTrue(any("input changed" in row for row in proof["incomplete_reasons"]))

    def test_delivery_requires_observed_precompile_and_explicit_input_snapshots(self):
        unit = self.unit()
        unit.update(idx=0, name="fixture.o")
        generator = self.write("generate.py", "# fixture original\n")
        snapshots = P.snapshot_inputs([(generator, "build_script")], self.root)
        toolchain = dict(ndk_root="fixture-ndk", ndk_version="fixture", target="fixture-target",
                         versions={name: "fixture version" for name in ("clang", "llvm-ar", "ld.lld")})
        proof = P.build_receipt([unit], [(generator, "build_script")], self.root,
                                toolchain=toolchain, input_snapshots=snapshots)
        proof["optional_inputs"] = [dict(path="optional.json", present=False, role="build_rule")]
        report = dict(provenance=proof, stages_run=["gate"],
                      compile=dict(rows=[dict(idx=0, name="fixture.o", outputs=[unit])]), compose=dict(rows=[]))
        D.verify_build_provenance(report, self.root)
        historical = copy.deepcopy(report)
        historical["provenance"]["schema"] = "maplesu-sdk-source-provenance/1"
        historical["provenance"].pop("input_snapshots")
        for row in [historical["provenance"]["translation_units"][0],
                    historical["compile"]["rows"][0]["outputs"][0]]:
            for name in ("precompile", "precompile_complete", "precompile_errors", "compile_steps"):
                row.pop(name, None)
        D.verify_build_provenance(historical, self.root)
        for field in ("input_snapshots",):
            broken = copy.deepcopy(report)
            del broken["provenance"][field]
            with self.assertRaisesRegex(AssertionError, "EXECUTION_INPUT_SNAPSHOTS"):
                D.verify_build_provenance(broken, self.root)
        broken = copy.deepcopy(report)
        broken["provenance"]["translation_units"][0]["precompile"]["inputs"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(AssertionError, "PRECOMPILE_SNAPSHOT"):
            D.verify_build_provenance(broken, self.root)

    def test_payload_spec_loader_and_new_staging_schema_boundary(self):
        payloads = self.root / "payloads"
        payloads.mkdir()
        with patch.object(BP, "PAYLOAD_SRC_DIR", payloads):
            self.assertEqual(BP.load_specs(), [])
            self.write("payloads/one/program.json", '{}')
            self.assertEqual(BP.load_specs({"other"}), [])
            loaded = BP.load_specs({"one"})
            self.assertEqual([(row["name"], row["asset"]) for row in loaded], [("one", "one.bin")])
        build = self.root / "build"
        self.write("build/report/build-report.json", json.dumps(dict(provenance=dict(schema="maplesu-sdk-source-provenance/1"))))
        with patch.object(ST, "ROOT", self.root), patch.object(ST, "source_inputs", side_effect=AssertionError("legacy staging passed schema guard")):
            with self.assertRaisesRegex(AssertionError, "current compile-boundary provenance"):
                ST.stage(build, self.root / "candidate", self.root / "base")
        self.assertFalse((self.root / "candidate").exists())


class BuildBoundaryTests(FileCase):
    def setUp(self):
        super().setUp()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in {"OBJ_DIR": self.root / "obj", "TU_DIR": self.root / "tu",
                            "LOG_DIR": self.root / "logs", "OUT_DIR": self.root / "out",
                            "LINK_DIR": self.root / "link"}.items():
            value.mkdir()
            self.stack.enter_context(patch.object(B, name, value))
        self.stack.enter_context(patch.object(B.S, "REPO_ROOT", self.root))
        self.stack.enter_context(patch.object(B, "rel", side_effect=lambda path: P.canonical_path(path, self.root)))
        self.stack.enter_context(patch.object(B, "log"))
        self.tc = SimpleNamespace(tool=lambda name: Path(name), has=lambda name: True)
        self.vendor = SimpleNamespace(for_member=lambda name: None)
        self.args = SimpleNamespace(jobs=1, werror=False, ar_chunk=8)

    def entry(self, sources=None, two_stage=False):
        return B.ManifestEntry(idx=0, name="fixture.o", sources=sources or [self.source],
                               source_raw=[str(self.source)], flags_profile="core-oz-elf", status="complete",
                               layout="elf", recipe={"stages": 2 if two_stage else 1})

    def test_bootstrap_preserves_partial_stage_receipts_and_first_error(self):
        installers = [SimpleNamespace(name=row[4], sources=[self.source]) for row in B.PH.TABLE]
        stages = ("compile", "compose", "pack")
        for failed in stages:
            with self.subTest(stage=failed), contextlib.ExitStack() as stack:
                report = {}
                first = B.StageError("fixture first " + failed,
                                     B.EXIT_ARCHIVE if failed == "pack" else B.EXIT_COMPILE)
                observed = {}

                def stage(name):
                    def run(*args):
                        partial = args[3]
                        observed[name] = partial
                        partial[name] = {"rows": [{"idx": 0, "status": "ok"}],
                                         "failures": [{"idx": 1}] if name == failed else []}
                        if name == failed:
                            raise first
                    return run

                stack.enter_context(patch.object(B.SB, "bundle_inputs", return_value=[]))
                calls = {name: stack.enter_context(patch.object(B, "stage_" + name,
                                                                side_effect=stage(name)))
                         for name in stages}
                copy_headers = stack.enter_context(patch.object(B.shutil, "copytree"))
                backend = stack.enter_context(patch.object(B.SB, "build_backend"))
                args = SimpleNamespace(policy_bundle_source=self.source)
                with self.assertRaises(B.StageError) as error:
                    B.stage_source_bootstrap([self.entry(), *installers], self.tc, args, report, self.vendor)
                self.assertIs(error.exception, first)
                partial = report["bootstrap"]
                self.assertIs(partial, observed[failed])
                self.assertEqual(partial[failed]["failures"], [{"idx": 1}])
                for name in stages[:stages.index(failed) + 1]:
                    self.assertIs(observed[name], partial)
                    self.assertEqual(partial[name]["rows"], [{"idx": 0, "status": "ok"}])
                for name in stages[stages.index(failed) + 1:]:
                    calls[name].assert_not_called()
                copy_headers.assert_not_called()
                backend.assert_not_called()
                report["failure"] = {"message": str(first), "exit_code": first.code}
                with patch.object(B, "REPORT_DIR", self.root / "reports" / failed), \
                     patch.object(B, "collect_build_provenance", return_value={"closure_complete": False}):
                    saved = B.write_report(args, report, B.time.monotonic())
                persisted = json.loads(saved.read_text(encoding="utf-8"))
                self.assertEqual(persisted["bootstrap"], partial)
                self.assertEqual(persisted["failure"], {"message": str(first), "exit_code": first.code})
                self.assertFalse(persisted["provenance"]["closure_complete"])

    def test_single_and_two_stage_compile_capture_real_fake_boundaries(self):
        for two_stage in (False, True):
            with self.subTest(two_stage=two_stage), patch.object(B.S, "run", side_effect=self.compiler):
                report = {}
                B.stage_compile([self.entry(two_stage=two_stage)], self.tc, self.args, report, self.vendor)
                output = report["compile"]["rows"][0]["outputs"][0]
                proof = P.build_receipt([output], [], self.root)
                self.assertTrue(proof["closure_complete"], proof["incomplete_reasons"])
                self.assertEqual(bool(output.get("compile_steps")), two_stage)

    def test_ir_failure_retains_compiler_diagnostic_in_report_and_log(self):
        def failed_ir(argv, **kwargs):
            if "-E" in argv:
                return self.compiler(argv, **kwargs)
            return done(27, stdout="fixture partial stdout", stderr="fixture first IR diagnostic")

        report = {}
        with patch.object(B.S, "run", side_effect=failed_ir):
            with self.assertRaises(B.StageError) as error:
                B.stage_compile([self.entry(two_stage=True)], self.tc, self.args, report, self.vendor)
        self.assertEqual(error.exception.code, B.EXIT_COMPILE)
        failure = report["compile"]["failures"][0]
        self.assertEqual((failure["stage"], failure["exit"]), ("ir", 27))
        diagnostic = (self.root / failure["log"]).read_text(encoding="utf-8")
        self.assertIn("[exit code] 27", diagnostic)
        self.assertIn("fixture partial stdout", diagnostic)
        self.assertIn("fixture first IR diagnostic", diagnostic)
        self.assertIn(failure["log"], str(error.exception))

    def test_partial_bootstrap_provenance_keeps_units_without_duplicate_merged_rows(self):
        core = self.unit()
        core.update(idx=0, name="core.o")
        installer = self.unit(obj=self.root / "output/installer.o")
        installer.update(idx=1, name="installer.o")
        core_row = {"idx": 0, "outputs": [core]}
        installer_row = {"idx": 1, "outputs": [installer]}
        args = SimpleNamespace(manifest=self.root / "absent.jsonl", manifest_dir=None, gate_allow=None)
        for main_rows, count in ((None, 1), ([installer_row], 2), ([core_row, installer_row], 2)):
            with self.subTest(main_rows=main_rows):
                report = {"bootstrap": {"compile": {"rows": [core_row]},
                                        "compose": {"rows": [{"idx": 0, "object": core["object"],
                                                               "bytes": core["bytes"], "sha256": "a" * 64}]}},
                          "failure": {"message": "fixture first error", "exit_code": B.EXIT_COMPILE}}
                if main_rows is not None:
                    report["compile"] = {"rows": main_rows}
                with patch.object(B, "SOURCE_PAYLOADS", False):
                    proof = B.collect_build_provenance(args, report, None)
                self.assertEqual(len(proof["translation_units"]), count)
                self.assertFalse(proof["closure_complete"])
                self.assertIn("build invocation failed; receipt covers only captured inputs", proof["incomplete_reasons"])
                self.assertTrue(any("compose object changed since snapshot" in reason
                                    for reason in proof["incomplete_reasons"]))

    def test_old_object_and_depfile_do_not_survive_empty_successful_compiler(self):
        entry = self.entry()
        entry.object_path.parent.mkdir(parents=True)
        entry.object_path.write_bytes(b"old object")
        P.depfile_path(entry.object_path).write_text("maplesu_object: old.cpp\n", encoding="utf-8")
        def empty(argv, **kwargs):
            if "-E" in list(map(str, argv)):
                return self.compiler(argv, **kwargs)
            self.assertFalse(entry.object_path.exists())
            self.assertFalse(P.depfile_path(entry.object_path).exists())
            return done()
        with patch.object(B.S, "run", side_effect=empty):
            with self.assertRaises(B.StageError):
                B.stage_compile([entry], self.tc, self.args, {}, self.vendor)

    def test_compose_recipe_keeps_prelink_input_identities(self):
        extra = self.write("src/extra.cpp", "int extra;\n")
        entry = self.entry([self.source, extra])
        entry.compose = [dict(tool="clang++", input=str(path), output=str(path.with_suffix(".o")), argv=[])
                         for path in entry.sources]
        def compiler(argv, **kwargs):
            argv = list(map(str, argv))
            if "-c" in argv and Path(argv[argv.index("-c") + 1]) == extra:
                with patch.object(self, "source", extra):
                    return self.compiler(argv, **kwargs)
            return self.compiler(argv, **kwargs)
        report = {}
        with patch.object(B.S, "run", side_effect=compiler):
            B.stage_compose([entry], self.tc, self.args, report)
        row = report["compose"]["rows"][0]
        self.assertEqual(row["mode"], "compose-steps")
        self.assertEqual(row["object_inputs"], [dict(path=x["object"], size=x["bytes"], sha256=x["sha256"])
                                                for x in row["outputs"]])
        self.assertTrue(all(x["precompile_complete"] for x in row["outputs"]))

    def test_empty_successful_compose_link_does_not_reuse_old_final_object(self):
        extra = self.write("src/extra.cpp", "int extra;\n")
        entry = self.entry([self.source, extra])
        entry.compose = [dict(tool="clang++", input=str(path), output=str(path.with_suffix(".o")), argv=[])
                         for path in entry.sources]
        entry.object_path.parent.mkdir(parents=True)
        entry.object_path.write_bytes(b"old composed object")
        def empty_link(argv, **kwargs):
            if str(argv[0]) == "ld.lld":
                self.assertFalse(entry.object_path.exists())
                return done()
            return self.compiler(argv, **kwargs)
        with patch.object(B.S, "run", side_effect=empty_link):
            with self.assertRaises(B.StageError):
                B.stage_compose([entry], self.tc, self.args, {})
        self.assertFalse(entry.object_path.exists())

    def test_pack_rejects_changed_composed_object_before_ar(self):
        entry = self.entry()
        entry.object_path.parent.mkdir(parents=True)
        entry.object_path.write_bytes(b"new bytes")
        report = {"compose": {"rows": [dict(idx=0, sha256="a" * 64, bytes=5)]}}
        with patch.object(B, "run_checked", side_effect=AssertionError("ar must not run")):
            with self.assertRaisesRegex(B.StageError, "changed before pack"):
                B.stage_pack([entry], self.tc, self.args, report, self.root / "packed.a")

    def test_pack_rejects_object_mutation_during_ar(self):
        entry = self.entry()
        entry.object_path.parent.mkdir(parents=True)
        entry.object_path.write_bytes(b"\x7fELFold")
        original = entry.object_path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        member = SimpleNamespace(name=entry.name, sha256=digest, size=len(original), layout="elf")
        parsed = SimpleNamespace(names=[entry.name], members=[member], size=100, sha256="b" * 64,
                                 duplicate_groups=lambda: [])
        def mutate(stage, what, argv, *args, **kwargs):
            if "qc" in list(map(str, argv)):
                entry.object_path.write_bytes(b"\x7fELFnew")
            return done()
        with patch.object(B, "run_checked", side_effect=mutate), patch.object(B.S, "read_archive", return_value=parsed):
            with self.assertRaisesRegex(B.StageError, "archive problem"):
                B.stage_pack([entry], self.tc, self.args, {}, self.root / "packed.a")

    def test_harness_uses_same_precompile_boundary_with_no_tool_execution(self):
        entries = []
        for idx in B.SAMPLE_IDX:
            entry = self.entry()
            entry.idx = idx
            entry.name = "fixture%d.o" % idx
            entries.append(entry)
        reference = self.root / "frozen-fixture.a"
        reference.write_bytes(b"fixture reference archive")
        def checked(stage, what, argv, *args, **kwargs):
            if "-o" in list(map(str, argv)):
                return self.compiler(argv, **kwargs)
            return done()
        report = {}
        with patch.object(B.S, "find_freeze", return_value=SimpleNamespace(archive=reference)), \
             patch.object(B.S, "llvm_ar_list", side_effect=[[entry.name for entry in entries], []]), \
             patch.object(B, "HARNESS_SOURCE", self.source), patch.object(B, "run_checked", side_effect=checked), \
             patch.object(B.S, "run", side_effect=self.compiler):
            B.stage_link_sample(entries, self.tc, SimpleNamespace(archive=None), report)
        output = report["link_sample"]["outputs"][0]
        self.assertTrue(output["precompile_complete"])
        self.assertEqual(output["stage"], "link-sample")


class DeliveryChainTests(FileCase):
    def fixture(self):
        source = self.write("runtime/maplesu-sdk/sdk/src/first.cpp", "int first;\n")
        obj = self.root / "output/first.o"
        obj.write_bytes(b"first object")
        identity = P.file_record(obj, self.root)
        name = "same.o"
        src = source.relative_to(self.root).as_posix()
        source_identity = dict(source=src, source_sha256=P.file_record(source, self.root)["sha256"],
                               build_source=src, build_source_sha256=P.file_record(source, self.root)["sha256"])
        output = dict(source=src, object=identity["path"], bytes=identity["size"], sha256=identity["sha256"])
        entry = dict(idx=0, name=name, sources=["src/first.cpp"])
        compiled = dict(idx=0, name=name, sources=[src], outputs=[output])
        composed = dict(idx=0, name=name, object=identity["path"], bytes=identity["size"], sha256=identity["sha256"],
                        inputs=[source_identity], object_inputs=[identity], mode="single-tu")
        packed = dict(idx=0, name=name, object=identity["path"], object_bytes=identity["size"],
                      object_sha256=identity["sha256"], sources=[source_identity])
        member = dict(name=name, size=identity["size"], sha256=identity["sha256"])
        return [entry], dict(compile=dict(rows=[compiled]), compose=dict(rows=[composed]),
                             pack=dict(member_inputs=[packed])), [member]

    def test_manifest_compile_compose_pack_chain_accepts_exact_inputs(self):
        entries, build, members = self.fixture()
        D.verify_member_source_chain(entries, build, members, self.root)

    def test_wrong_ordinal_duplicate_source_tu_and_pack_identity_are_rejected(self):
        cases = [
            ("ordinal", lambda e,b,m: e[0].update(idx=1)),
            ("duplicate", lambda e,b,m: b["compile"]["rows"].append(copy.deepcopy(b["compile"]["rows"][0]))),
            ("source", lambda e,b,m: b["compile"]["rows"][0].update(sources=["unselected.cpp"])),
            ("tu", lambda e,b,m: b["compose"]["rows"][0]["object_inputs"][0].update(sha256="f"*64)),
            ("pack", lambda e,b,m: b["pack"]["member_inputs"][0].update(object="other.o")),
        ]
        for label, mutate in cases:
            with self.subTest(case=label):
                entries, build, members = self.fixture()
                mutate(entries, build, members)
                with self.assertRaises(AssertionError):
                    D.verify_member_source_chain(entries, build, members, self.root)

    def test_two_stage_recipe_requires_connected_intermediate_identity(self):
        entries, build, members = self.fixture()
        ir = self.root / "output/first.bc"
        ir.write_bytes(b"fixture generated IR")
        identity = P.file_record(ir, self.root)
        entries[0]["recipe"] = dict(stages=2)
        output = build["compile"]["rows"][0]["outputs"][0]
        output.update(build_source=identity["path"], build_source_sha256=identity["sha256"],
                      precompile=dict(inputs=[identity]),
                      compile_steps=[dict(source=output["source"], build_source=output["source"], object=identity["path"],
                                          bytes=identity["size"], sha256=identity["sha256"])])
        D.verify_member_source_chain(entries, build, members, self.root)
        for change in ("missing", "link", "sha", "precompile", "first-source"):
            with self.subTest(change=change):
                altered = copy.deepcopy(build)
                output = altered["compile"]["rows"][0]["outputs"][0]
                if change == "missing":
                    output.pop("compile_steps")
                elif change == "link":
                    output["compile_steps"][0]["object"] = "other.bc"
                elif change == "sha":
                    output["compile_steps"][0]["sha256"] = "f" * 64
                elif change == "first-source":
                    output["compile_steps"][0]["build_source"] = "unselected.cpp"
                else:
                    output["precompile"]["inputs"][0]["size"] += 1
                with self.assertRaises(AssertionError):
                    D.verify_member_source_chain(entries, altered, members, self.root)

    def test_compose_steps_reject_unselected_source_and_build_source(self):
        entries, build, members = self.fixture()
        compiled = build["compile"]["rows"][0]["outputs"][0]
        compiled["build_source"] = compiled["source"]
        composed = build["compose"]["rows"][0]
        composed.update(mode="compose-steps", outputs=[copy.deepcopy(compiled)], tus=[compiled["object"]])
        D.verify_member_source_chain(entries, build, members, self.root)
        for field in ("source", "build_source"):
            with self.subTest(field=field):
                altered = copy.deepcopy(build)
                altered["compose"]["rows"][0]["outputs"][0][field] = "unselected.cpp"
                with self.assertRaises(AssertionError):
                    D.verify_member_source_chain(entries, altered, members, self.root)


class BackendBoundaryTests(FileCase):
    def test_windows_cmake_include_and_define_quotes_preserve_single_arguments(self):
        row = dict(command='"C:\\fixture tools\\clang++.exe" --target=aarch64-linux-android31 '
                           '-isystem "C:\\sdk include" -I"C:\\repo headers" '
                           '-DVALUE="a b" -c "C:\\code path\\main.cpp" -o "obj path/main.o"')
        argv = SB.command_arguments(row)
        self.assertEqual(argv[0], "C:\\fixture tools\\clang++.exe")
        self.assertIn("-IC:\\repo headers", argv)
        self.assertIn("-DVALUE=a b", argv)
        self.assertEqual(argv[argv.index("-o") + 1], "obj path/main.o")
        self.assertEqual(SB.compiler_target([row]), "aarch64-linux-android31")

    def test_existing_object_rejected_before_ninja_and_spaced_argv_preserved(self):
        import policy_backend_identity
        output = self.root / "backend output"
        build = output / "cmake"
        source = self.write("runtime/ultra/backend source.cpp", "int backend;\n")
        obj = build / "CMakeFiles/maplesu_policy_boot.dir/object with spaces.o"
        bundle = self.write("backend/policy-bundles.cpp", "int bundle;\n")
        self.write("backend/policy-bundles.json", "{}")
        self.write("runtime/CMakeLists.txt", "# fixture cmake\n")
        self.write("scripts/policy_backend_identity.py", "# fixture identity\n")
        self.write("sdk/lib/arm64-v8a/libkernel_module_kit_static.a", "fixture archive")
        tc = SimpleNamespace(ndk=self.root / "fake ndk", versions={})
        cmd = ['"fixture clang"', '--target=aarch64-linux-android31', '-c', '"' + str(source) + '"',
               '-o', '"' + str(obj.relative_to(build)) + '"']
        commands = []
        def configure(argv, **kwargs):
            commands.append(list(map(str, argv)))
            if "-B" in commands[-1]:
                build.mkdir(parents=True, exist_ok=True)
                (build / "compile_commands.json").write_text(json.dumps([dict(command=" ".join(cmd),
                    directory=str(build), file=str(source))]), encoding="utf-8")
                obj.parent.mkdir(parents=True, exist_ok=True)
                obj.write_bytes(b"old object")
                return done()
            raise AssertionError("Ninja must not run with an existing object")
        with patch.object(SB.S, "REPO_ROOT", self.root), patch.object(SB, "bundle_inputs", return_value=[]), \
             patch.object(SB.S, "run", side_effect=configure):
            with self.assertRaisesRegex(ValueError, "new object output"):
                SB.build_backend(tc, self.root / "sdk", bundle, output, cmake=self.root / "tools/cmake.exe")
        self.assertEqual(len(commands), 1)

    def test_spaced_backend_command_keeps_precompile_and_actual_dep_identity(self):
        import policy_backend_identity
        output = self.root / "backend output"
        build = output / "cmake"
        source = self.write("runtime/ultra/backend source.cpp", "int backend;\n")
        relative_object = "CMakeFiles/maplesu_policy_boot.dir/object with spaces.o"
        obj = build / relative_object
        bundle = self.write("backend/policy-bundles.cpp", "int bundle;\n")
        self.write("backend/policy-bundles.json", "{}")
        self.write("runtime/CMakeLists.txt", "# fixture cmake\n")
        self.write("scripts/policy_backend_identity.py", "# fixture identity\n")
        self.write("sdk/lib/arm64-v8a/libkernel_module_kit_static.a", "fixture archive")
        tc = SimpleNamespace(ndk=self.root / "fake ndk", versions={})
        sdk_header = self.write("sdk/include/system-style.h", "int sdk_header;\n")
        ndk_header = self.write("fake ndk/include/stdlib.h", "int ndk_header;\n")
        command = ('"fixture clang" --target=aarch64-linux-android31 -isystem "' + str(sdk_header.parent)
                   + '" -c "' + str(source) + '" -o "' + relative_object + '"')
        observed_scan = []
        def boundary(argv, **kwargs):
            argv = list(map(str, argv))
            if "-B" in argv:
                build.mkdir(parents=True)
                (build / "compile_commands.json").write_text(json.dumps([dict(command=command,
                    directory=str(build), file=str(source))]), encoding="utf-8")
            elif "-E" in argv:
                observed_scan.append(argv)
                Path(argv[argv.index("-MF") + 1]).write_text(
                    "maplesu_object: " + " ".join(map(escape_dep, [source, sdk_header, ndk_header])) + "\n", encoding="utf-8")
            elif "-t" in argv:
                if argv[-1] == "deps":
                    return done(stdout=relative_object + ": #deps 3, deps mtime 1 (VALID)\n    "
                                + "\n    ".join(map(str, [source, sdk_header, ndk_header])) + "\n")
            else:
                obj.parent.mkdir(parents=True, exist_ok=True)
                obj.write_bytes(b"fixture backend object")
                (build / "libmaplesu_policy_boot.so").write_bytes(b"fixture backend binary")
            return done()
        identity = dict(fileName="fixture-backend.so")
        toolchain = dict(ndk_root="fixture-ndk", ndk_version="fixture", target="unused", versions={})
        with patch.object(SB.S, "REPO_ROOT", self.root), patch.object(SB, "bundle_inputs", return_value=[]), \
             patch.object(SB.S, "run", side_effect=boundary), patch.object(P, "toolchain_record", return_value=toolchain), \
             patch.object(policy_backend_identity, "describe_backend", return_value=identity), \
             patch.object(policy_backend_identity, "write_identity"):
            report = SB.build_backend(tc, self.root / "sdk", bundle, output, cmake=self.root / "tools/cmake.exe")
        self.assertEqual(len(observed_scan), 1)
        self.assertEqual(observed_scan[0][0], "fixture clang")
        self.assertIn("-MD", observed_scan[0])
        self.assertNotIn("-MMD", observed_scan[0])
        unit = report["provenance"]["translation_units"][0]
        self.assertTrue(report["provenance"]["closure_complete"])
        self.assertTrue(unit["precompile_complete"])
        self.assertEqual(unit["source"], source.relative_to(self.root).as_posix())
        self.assertIn(sdk_header.relative_to(self.root).as_posix(), unit["dependencies"])
        self.assertNotIn(ndk_header.relative_to(self.root).as_posix(), unit["dependencies"])


if __name__ == "__main__":
    unittest.main()
