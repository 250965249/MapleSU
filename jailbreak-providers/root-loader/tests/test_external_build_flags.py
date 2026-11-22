"""Keep clean builds independent of earlier build.json compiler records."""
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


BUILDER = Path(__file__).resolve().parents[1] / "build_root_module.py"
spec = importlib.util.spec_from_file_location("root_build_flags_test_builder", BUILDER)
builder = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = builder
spec.loader.exec_module(builder)


class ExternalBuildFlagsTest(unittest.TestCase):
    def test_current_compile_flags_reach_external_gate_on_first_build(self):
        context = SimpleNamespace(module=Path("fresh/maplesu_root.ko"),
            image_path=Path("kernel"), contract_path=Path("contract.json"),
            header=Path("kernel_compat.h"), cflags=["-fsanitize=kcfi", "-ffixed-x18"])
        result = {"ok": True, "gates": [], "imports": [], "result": "all gates pass"}
        runner = Mock(return_value=result)
        self.assertIs(result, builder.run_external_gates(runner, context))
        runner.assert_called_once_with(context.module, context.image_path,
            context.contract_path, root=True, header_path=context.header,
            build_flags=context.cflags)

    def test_external_failure_is_not_overridden(self):
        context = SimpleNamespace(module=Path("fresh/maplesu_root.ko"),
            image_path=Path("kernel"), contract_path=Path("contract.json"),
            header=Path("kernel_compat.h"), cflags=["-ffixed-x18"])
        result = {"ok": False, "gates": [{"id": "G6", "ok": False}],
                  "imports": [], "result": "gate failure: G6"}
        self.assertIs(result, builder.run_external_gates(Mock(return_value=result), context))


if __name__ == "__main__":
    unittest.main()
