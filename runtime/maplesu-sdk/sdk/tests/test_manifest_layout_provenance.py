#!/usr/bin/env python3
"""Frozen layout provenance and the current output layout are distinct."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gen_manifest as G


class LayoutProvenanceTests(unittest.TestCase):
    def record(self, layout="elf"):
        return {
            "idx": 0, "name": "fixture.o", "status": "complete", "layout": layout,
            "sources": ["fixture.cpp"], "flagsProfile": "core-oz-elf-fexceptions",
            "recovery": {"functions": 1, "recovered": 1, "unrecovered": []},
            "original": {"sha256": "a" * 64, "bytes": 4},
            "evidence": ["fixture-receipt.json"],
        }

    def validate(self, raw):
        reference = G.RefIndex.build({0: {
            "idx": 0, "name": "fixture.o", "sha256": "a" * 64,
            "bytes": 4, "layout": "bitcode",
        }})
        with patch.object(G, "expected_members", return_value=1), \
             patch.object(G, "resolve_source", return_value=Path(__file__)):
            return G.validate_record(raw, "fixture.json", reference)

    def errors(self, issues):
        return [issue.code for issue in issues if issue.level == "error"]

    def test_explicit_frozen_layout_allows_current_output_conversion(self):
        raw = self.record()
        raw["original"]["layout"] = "bitcode"
        member, issues = self.validate(raw)
        self.assertEqual(self.errors(issues), [])
        self.assertEqual(member.layout, "elf")
        self.assertEqual(member.original["layout"], "bitcode")
        self.assertIn("layout-transition", [issue.code for issue in issues])

    def test_declared_original_layout_must_match_the_frozen_header(self):
        raw = self.record("bitcode")
        raw["original"]["layout"] = "elf"
        _member, issues = self.validate(raw)
        self.assertIn("original-layout-mismatch", self.errors(issues))

    def test_explicit_original_layout_rejects_invalid_values(self):
        for value in (None, "", "native", 1, [], {}):
            with self.subTest(value=value):
                raw = self.record("bitcode")
                raw["original"]["layout"] = value
                _member, issues = self.validate(raw)
                self.assertIn("bad-original-layout", self.errors(issues))

    def test_legacy_record_still_rejects_a_layout_flip(self):
        _member, issues = self.validate(self.record())
        self.assertIn("layout-mismatch", self.errors(issues))

    def test_a_reference_copy_cannot_claim_a_source_format_conversion(self):
        raw = self.record()
        raw.update(status="vendor-copy", sources=[])
        raw["original"]["layout"] = "bitcode"
        _member, issues = self.validate(raw)
        self.assertIn("layout-transition-no-source", self.errors(issues))

    def test_legacy_record_preserves_its_original_jsonl_shape(self):
        member, issues = self.validate(self.record("bitcode"))
        self.assertEqual(self.errors(issues), [])
        self.assertEqual(member.to_jsonl()["original"], {"sha256": "a" * 64, "bytes": 4})

    def test_jsonl_preserves_explicit_original_layout(self):
        member = G.MemberRecord(idx=0, name="fixture.o", status="complete", layout="elf",
                                original={"sha256": "a" * 64, "bytes": 4, "layout": "bitcode"})
        self.assertEqual(member.to_jsonl()["original"]["layout"], "bitcode")

    def test_conversion_keeps_original_identity_checks(self):
        for field, value, error in (("sha256", "b" * 64, "name-mismatch"),
                                    ("bytes", 8, "original-bytes-mismatch")):
            with self.subTest(field=field):
                raw = self.record()
                raw["original"]["layout"] = "bitcode"
                raw["original"][field] = value
                _member, issues = self.validate(raw)
                self.assertIn(error, self.errors(issues))

    def test_explicit_provenance_keeps_output_layout_validation(self):
        raw = self.record("native")
        raw["original"]["layout"] = "bitcode"
        _member, issues = self.validate(raw)
        self.assertIn("bad-layout", self.errors(issues))

    def test_missing_output_layout_still_defaults_to_frozen_layout(self):
        raw = self.record()
        del raw["layout"]
        raw["original"]["layout"] = "bitcode"
        member, issues = self.validate(raw)
        self.assertEqual(self.errors(issues), [])
        self.assertEqual(member.layout, "bitcode")


if __name__ == "__main__":
    unittest.main()
