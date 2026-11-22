"""Run the two AST-isolated collectors against dictionary/mock boundaries only."""

import argparse
import ast
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


PARSER = argparse.ArgumentParser()
PARSER.add_argument("--builder", type=Path,
    default=Path(__file__).resolve().parents[1] / "build-ultra-manager-claim.py")
ARGS, UNITTEST_ARGS = PARSER.parse_known_args()
FUNCTIONS = {"core_pending_abi", "core_named_layout", "collect_core_lifecycle_abi",
    "host_runtime_pending_abi", "collect_host_runtime_abi"}
TREE = ast.parse(ARGS.builder.read_text(encoding="utf-8-sig"))
CODE = compile(ast.Module(body=[node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS], type_ignores=[]),
    str(ARGS.builder), "exec")


def mock_btf():
    return SimpleNamespace(types=[], function=Mock(return_value="f()"),
        function_parameter=Mock(return_value="*f()"), member_function=Mock(return_value="*f()"),
        variable=Mock(return_value="*f()"), named_structure_selected=Mock(
            side_effect=lambda name, members: {"bytes": 16, "members": {
                member: {"offset": index * 8, "bytes": 8}
                for index, member in enumerate(members)}}))


class MissingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {"coreSourceSelection": "core", "coreRuntimeSourceSelection": "runtime",
            "hostDeploymentSourceSelection": "host", "hostDurableSourceSelection": "durable",
            "hostInitializationSourceSelection": "initialization"}
        self.task_layout = [0] * 53
        self.task_layout[7:11] = [16, 8, 0, 8]
        self.uid_facts = {"schema": 1, "readerFenceBytes": 16, "readerFenceAlign": 8,
            "readerFenceOwnerOffset": 0, "readerFenceOwnerBytes": 8,
            "readerFenceEnterOffset": 8, "readerFenceEnterBytes": 8}
        self.btf = mock_btf()
        self.env = {
            "json": json, "core_public_selection": lambda: "core",
            "core_runtime_public_selection": lambda: "runtime",
            "host_deployment_public_selection": lambda: "host",
            "HOST_DURABLE_SELECTION": "durable", "HOST_INITIALIZATION_SELECTION": "initialization",
            "SU_COMPONENT_METADATA_SELECTION": "su",
            "CORE_OBJECTS": ("manager_management", "manager_task_state"),
            "CORE_PROBES": ("manager_core_facts", "manager_core_uid_facts", "manager_core_callback_types"),
            "CORE_FACTS": ("schema", "taskStateVerified", "profileDomainVerified"),
            "CORE_UID_FACTS": tuple(self.uid_facts),
            "CORE_LAYOUT_TYPES": {"readerFence": ("msu_uid_reader_fence",
                "manager_core_uid_facts", ("owner", "enter"))},
            "CORE_FUNCTIONS": {"manager_management": ("local_function",)},
            "CORE_CALLBACK_PARAMETERS": {"reader": ("manager_management", "local_function", 0)},
            "CORE_TASK_LAYOUTS": {"task": ("task_struct", 7, 8, {"owner": (9, 10)})},
            "HOST_RUNTIME_OBJECTS": ("runtime",), "SOURCES": (Path("runtime.c"),),
            "HOST_RUNTIME_LAYOUT_TYPES": {"authority": ("authority", ("owner",)),
                "fsnotify": ("fsnotify_ops", ("event",))},
            "HOST_RUNTIME_EXTRA_FUNCTIONS": {"runtime": ("callback",)},
            "HOST_RUNTIME_NATIVE_CALLBACKS": {"runtime": {"callback": ("fsnotify_ops", "event")}},
            "HOST_RUNTIME_NATIVE_FUNCTIONS": ("native_function",),
            "sha": Mock(return_value="mock-sha256"),
            "identity": Mock(side_effect=lambda path: {"path": str(path), "sha256": "mock-sha256"}),
            "object_provenance": Mock(return_value={"sourceIdentity": {"sha256": "mock-sha256"},
                "dependencies": [{"path": "mock-dependency"}]}),
            "selected_native_source": Mock(side_effect=lambda name: Path(name)),
            "core_callback_type_source": Mock(return_value="probe"),
            "core_probe_source": Mock(return_value="probe"),
            "host_runtime_probe_source": Mock(return_value="probe"),
            "object_btf": Mock(return_value=self.btf),
            "core_cfi_policy": Mock(return_value={"kcfiEnabled": False, "normalizeIntegers": False}),
            "core_function_entries": Mock(return_value=({"callback": {"available": True}}, {"callback": 1})),
            "core_native_functions": Mock(),
            "core_layout_record": Mock(side_effect=lambda target, payload, name, *args:
                {"layoutValues": self.task_layout[:] if name == "manager_task_state" else [0] * 26}),
            "object_words": Mock(side_effect=lambda path, symbol:
                list(self.uid_facts.values()) if path.name == "manager_core_uid_facts.o" else
                [1, 0, 0] if symbol == "msu_core_build_facts" else [1] + [0] * 8),
        }
        exec(CODE, self.env)

    def collect(self, name, reference=None):
        def read_text(path, **kwargs):
            return json.dumps({"managementConfig": {}} if path.name == "msu_resolver_build_config.json"
                else self.inputs)

        with patch.object(Path, "read_text", read_text), patch.object(Path, "read_bytes", return_value=b"probe"):
            return self.env[name](Path("MOCK_TARGET"), b"", reference)

    def assert_incomplete(self, record):
        for key in ("metadataComplete", "kernelMetadataComplete", "targetQualified", "taskStateQualified",
                "profileDomainQualified", "factoryBound", "lifecycleQualified"):
            if key in record:
                self.assertIs(record[key], False, key)
        self.env["core_native_functions"].assert_not_called()

    def test_core_missing_reference_retains_local_facts(self):
        record = self.collect("collect_core_lifecycle_abi")
        self.assert_incomplete(record)
        self.assertEqual(record["missing"][-1], "ValueError: CORE linked vmlinux reference ABI is missing")
        for key in ("sourceIdentities", "objectIdentities", "commandIdentities", "dependencyReceiptIdentities"):
            self.assertEqual(len(record[key]), 5, key)
        for key in ("inlineDependencies", "compiledFacts", "uidCompiledFacts", "compiledLayouts",
                "localFunctionAbi", "callbackParameters", "readerFenceAbi", "entrypoints", "entryCfi"):
            self.assertTrue(record[key], key)
        self.assertEqual(record["taskState"]["layoutValues"], self.task_layout)
        self.assertEqual(record["taskState"]["targetLayouts"], {})
        self.assertEqual(record["credentialDomain"]["layoutValues"], [0] * 26)

    def test_core_missing_reference_with_no_task_layouts(self):
        self.env["CORE_TASK_LAYOUTS"] = {}
        record = self.collect("collect_core_lifecycle_abi")
        self.assert_incomplete(record)
        self.assertEqual(record["missing"][-1], "ValueError: CORE linked vmlinux reference ABI is missing")

    def test_host_missing_reference_retains_local_facts(self):
        record = self.collect("collect_host_runtime_abi")
        self.assert_incomplete(record)
        self.assertEqual(record["missing"], ["ValueError: Host runtime linked vmlinux reference ABI is missing"])
        for key in ("sourceIdentities", "objectIdentities", "commandIdentities", "dependencyReceiptIdentities"):
            self.assertEqual(len(record[key]), 2, key)
        self.assertTrue(record["inlineDependencies"])
        self.assertEqual(set(record["compiledLayouts"]), {"authority", "fsnotify"})

    def test_source_checks_precede_reference_check(self):
        for collector, selection, error in (
                ("collect_core_lifecycle_abi", "coreSourceSelection", "selected frozen source"),
                ("collect_host_runtime_abi", "hostDeploymentSourceSelection", "exact source selection")):
            with self.subTest(collector=collector):
                original = self.inputs[selection]
                self.inputs[selection] = "wrong"
                record = self.collect(collector)
                self.inputs[selection] = original
                self.assert_incomplete(record)
                self.assertIn(error, record["missing"][-1])

    def test_cfi_checks_precede_reference_check(self):
        self.env["core_cfi_policy"].side_effect = lambda path: {
            "kcfiEnabled": path.name == ".manager_management.o.cmd", "normalizeIntegers": False}
        for collector, error in (("collect_core_lifecycle_abi", "inconsistent actual CFI policies"),
                ("collect_host_runtime_abi", "actual management CFI policies differ")):
            with self.subTest(collector=collector):
                record = self.collect(collector)
                self.assert_incomplete(record)
                self.assertIn(error, record["missing"][-1])

    def test_reference_present_keeps_existing_comparisons(self):
        for collector, complete in (("collect_core_lifecycle_abi", "kernelMetadataComplete"),
                ("collect_host_runtime_abi", "metadataComplete")):
            with self.subTest(collector=collector):
                self.env["core_native_functions"].reset_mock()
                record = self.collect(collector, mock_btf())
                self.assertIs(record[complete], True, record["missing"])
                self.assertIs(record["targetQualified"], False)
                self.env["core_native_functions"].assert_called_once()

    def test_reference_layout_mismatches_remain_errors(self):
        for collector, error in (("collect_core_lifecycle_abi", "task compiled/reference type mismatch"),
                ("collect_host_runtime_abi", "callback container target layout differs")):
            with self.subTest(collector=collector):
                reference = mock_btf()
                reference.named_structure_selected.side_effect = lambda *args: {"bytes": 32, "members": {}}
                record = self.collect(collector, reference)
                self.assert_incomplete(record)
                self.assertIn(error, record["missing"][-1])

    def test_reference_callback_mismatch_remains_error(self):
        reference = mock_btf()
        reference.member_function.return_value = "*different()"
        record = self.collect("collect_host_runtime_abi", reference)
        self.assert_incomplete(record)
        self.assertIn("callback definition/declaration/target differs", record["missing"][-1])


if __name__ == "__main__":
    unittest.main(argv=[__file__, *UNITTEST_ARGS])
