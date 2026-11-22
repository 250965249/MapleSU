"""Build-to-APK regression for Ultra on a 6.12 kernel."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_dirtyfrag_compatibility import builder, package


class L3FamiliesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def module(self, family):
        path = self.directory / family / "maplesu_l3.ko"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(family.encode())
        return {"path": str(path), "sha256": package.sha(path),
                "bytes": path.stat().st_size, "kmi": family,
                "kernelRelease": {"android12-5.10": "5.10.226-android12-9",
                                  "android13-5.15": "5.15.167-android13-8",
                                  "android16-6.12": "6.12.58-android16-6"}.get(family, "6.6.89-android15-8")}

    def test_build_includes_all_measured_cfi_families(self):
        calls = []

        def build(command, **kwargs):
            contract = command[command.index("--contract") + 1]
            body = json.loads(Path(contract).read_text())
            family = builder.kmi_of(body["kernelRelease"])
            calls.append(family)
            module = self.module(family)
            output = Path(command[command.index("--out-dir") + 1])
            output.mkdir(parents=True, exist_ok=True)
            (output / "build.json").write_text(json.dumps({
                "modulePath": module["path"], "sha256": module["sha256"],
                "bytes": module["bytes"], "kernelRelease": body["kernelRelease"],
                "gateResult": {"ok": True}}))
            return subprocess.CompletedProcess(command, 0, "", "")

        report = {}
        contract = builder.ROOT / "root-loader/contracts/6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k.json"
        with patch.object(builder.subprocess, "run", side_effect=build):
            self.assertEqual(0, builder.build_root_l3_product(self.directory, self.directory, report, contract))
        expected = {"android12-5.10", "android13-5.15", "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18"}
        self.assertEqual(expected, set(calls))
        self.assertEqual(expected, set(report["l3"]["modules"]))

    def test_packaging_keeps_510_bytes_and_identity(self):
        self.check_packaging("android12-5.10")

    def test_packaging_keeps_515_bytes_and_identity(self):
        self.check_packaging("android13-5.15")

    def test_packaging_keeps_612_bytes_and_identity(self):
        self.check_packaging("android16-6.12")

    def check_packaging(self, family):
        primary = self.module("android15-6.6")
        other = self.module(family)
        ir = self.directory / "ir.ko"
        ir.write_bytes(b"ir-fixture")
        spec = self.directory / "fixture.spec"
        spec.write_bytes(b"spec")
        report = {"ir": {"build": {"module": str(ir), "sha256": package.sha(ir)},
                         "specs": [{"path": str(spec), "sha256": package.sha(spec), "release": "fixture"}]},
                  "l3": {"state": "BUILT", "module": primary,
                         "modules": {"android15-6.6": primary, family: other}}}
        assets = self.directory / "assets"
        result = package.stage_ir(report, assets)
        selected = result["l3Modules"][family]
        self.assertEqual(other["sha256"], selected["sha256"])
        self.assertEqual(family.encode(), (assets / selected["asset"]).read_bytes())
        Path(other["path"]).write_bytes(b"corrupt")
        with self.assertRaises(SystemExit):
            package.stage_ir(report, assets)


if __name__ == "__main__":
    unittest.main()
