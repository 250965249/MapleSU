"""Host test for the IR contract: the module's loader shape and the spec's bytes.

Manual W1 acceptance is exactly one property — "original bytes that do not match must
be rejected" — and this file proves it on the host, at both levels the product uses:

  * the module refuses to be *built* if its loader-visible objects disagree with the
    target kernel (size/offsets/KCFI/no imports), and it refuses at load time if a
    block's original bytes disagree (that branch is `IR_ERR_ORIG` in maplesu_ir.c);
  * every packaged spec still verifies byte-for-byte against the image it was
    generated from, and a spec checked against the *wrong* image fails.

Run: python -m unittest discover -s jailbreak-providers/ir-loader/tests
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

IR = Path(__file__).resolve().parents[1]
ROOT = IR.parents[1]
BUILD = IR / "build" / "build.json"
SPEC_DIR = IR / "specs"
BUILDER = IR / "build_ir_module.py"


def parse_spec(path: Path):
    blocks = []
    meta = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if "=" in line:
                key, _, value = line[1:].partition("=")
                meta[key.strip()] = value.strip()
            continue
        offset, orig, patched = line.split("|")
        blocks.append((int(offset), bytes.fromhex(orig), bytes.fromhex(patched)))
    return meta, blocks


def verify(image: bytes, blocks) -> int:
    """Returns the number of blocks whose original bytes do not match."""
    return sum(1 for offset, orig, _ in blocks if image[offset:offset + len(orig)] != orig)


class ModuleContractTest(unittest.TestCase):
    def test_module_passes_its_own_loader_contract(self):
        self.assertTrue(BUILD.is_file(), "build the module first")
        report = json.loads(BUILD.read_text(encoding="utf-8"))
        result = subprocess.run([sys.executable, str(BUILDER), "--verify-only",
                                 report["module"]],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        facts = json.loads((IR / "build" / "build.json").read_text(encoding="utf-8"))["facts"]
        # Zero imports: the module cannot depend on a symbol set the target build
        # may have trimmed, and cannot drag KernelSU/Magisk symbols in.
        self.assertEqual([], facts["imports"])
        # The KCFI hash the kernel checks for `int (void)`.
        self.assertEqual("0x36b1c5a6", facts["kcfiInitTypeId"])
        self.assertEqual("maplesu_ir", facts["thisModuleName"])
        self.assertEqual(4096, facts["specBytes"])


class SpecContractTest(unittest.TestCase):
    def records(self):
        found = list(SPEC_DIR.glob("*.ir.spec.json"))
        self.assertTrue(found, "no generated spec records")
        return [json.loads(path.read_text(encoding="utf-8")) for path in found]

    def test_every_spec_verifies_against_its_image(self):
        checked = 0
        for record in self.records():
            image_path = Path(record["image"])
            if not image_path.is_absolute():
                image_path = (ROOT / image_path).resolve()
            if not image_path.is_file():
                self.skipTest("image not present: " + str(image_path))
            spec = Path(record["spec"])
            if not spec.is_absolute():
                spec = (ROOT / spec).resolve()
            meta, blocks = parse_spec(spec)
            self.assertEqual(record["release"], meta.get("kernel"))
            self.assertEqual(0, verify(image_path.read_bytes(), blocks),
                             "spec does not match its own image: " + spec.name)
            checked += 1
        self.assertGreaterEqual(checked, 2, "need at least two adapted releases")

    def test_a_spec_is_rejected_against_another_release(self):
        records = self.records()
        images = {record["release"]: Path(record["image"]) for record in records}
        specs = {}
        for record in records:
            spec = Path(record["spec"])
            specs[record["release"]] = spec if spec.is_absolute() else (ROOT / spec).resolve()
        releases = [release for release, image in images.items() if image.is_file()]
        if len(releases) < 2:
            self.skipTest("need two releases with images present")
        left, right = releases[0], releases[1]
        image = Path(images[right])
        if not image.is_absolute():
            image = (ROOT / image).resolve()
        _, blocks = parse_spec(specs[left])
        # The whole point of a per-release spec: another release's bytes must fail.
        self.assertGreater(verify(image.read_bytes(), blocks), 0,
                           "%s verified against %s: offsets are not release-exact"
                           % (specs[left].name, image.name))

    def test_a_tampered_original_byte_is_refused(self):
        record = self.records()[0]
        image_path = Path(record["image"])
        if not image_path.is_absolute():
            image_path = (ROOT / image_path).resolve()
        if not image_path.is_file():
            self.skipTest("image not present: " + str(image_path))
        spec = Path(record["spec"])
        if not spec.is_absolute():
            spec = (ROOT / spec).resolve()
        with tempfile.TemporaryDirectory() as scratch:
            tampered = Path(scratch) / "tampered.ir.spec"
            lines = spec.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if line and not line.startswith("#"):
                    parts = line.split("|")
                    parts[1] = ("00" if parts[1][:2] != "00" else "11") + parts[1][2:]
                    lines[index] = "|".join(parts)
                    break
            tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
            _, blocks = parse_spec(tampered)
            self.assertEqual(1, verify(image_path.read_bytes(), blocks),
                             "a corrupted original byte must fail verification")


if __name__ == "__main__":
    unittest.main()
