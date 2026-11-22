"""Keep declared header inputs when collecting member metadata."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gen_manifest as G


class ManifestHeaderInputsTests(unittest.TestCase):
    def record(self):
        return {
            "idx": 0, "name": "fixture.o", "status": "complete", "layout": "elf",
            "sources": ["fixture.cpp"], "flagsProfile": "core-oz-elf-fexceptions",
            "recovery": {"functions": 1, "recovered": 1, "unrecovered": []},
            "original": {"sha256": "a" * 64, "bytes": 4},
            "evidence": ["fixture-receipt.json"],
        }

    def validate(self, raw):
        reference = G.RefIndex.build({0: {
            "idx": 0, "name": "fixture.o", "sha256": "a" * 64,
            "bytes": 4, "layout": "elf",
        }})
        with patch.object(G, "expected_members", return_value=1), \
             patch.object(G, "resolve_source", return_value=Path(__file__)):
            return G.validate_record(raw, "fixture.json", reference)

    def test_declared_headers_survive_the_jsonl_producer(self):
        raw = self.record()
        raw.update(headers=["include/public.h"], privateHeaders=["src/compat.h"])
        member, issues = self.validate(raw)
        self.assertEqual([item.code for item in issues if item.level == "error"], [])
        generated = member.to_jsonl()
        self.assertEqual(generated["headers"], raw["headers"])
        self.assertEqual(generated["privateHeaders"], raw["privateHeaders"])
        raw["headers"].append("later.h")
        generated["privateHeaders"].append("later.h")
        self.assertEqual(member.to_jsonl()["headers"], ["include/public.h"])
        self.assertEqual(member.to_jsonl()["privateHeaders"], ["src/compat.h"])

    def test_omitted_headers_keep_the_legacy_jsonl_shape(self):
        member, _issues = self.validate(self.record())
        self.assertNotIn("headers", member.to_jsonl())
        self.assertNotIn("privateHeaders", member.to_jsonl())

    def test_explicit_empty_header_lists_are_preserved(self):
        raw = self.record()
        raw.update(headers=[], privateHeaders=[])
        member, issues = self.validate(raw)
        self.assertEqual([item.code for item in issues if item.level == "error"], [])
        self.assertEqual(member.to_jsonl()["headers"], [])
        self.assertEqual(member.to_jsonl()["privateHeaders"], [])

    def test_malformed_header_lists_are_reported(self):
        for key in ("headers", "privateHeaders"):
            for value in (None, "one.h", {}, [None], [""], ["  "], [1]):
                with self.subTest(key=key, value=value):
                    raw = self.record()
                    raw[key] = value
                    _member, issues = self.validate(raw)
                    self.assertIn("bad-headers", [item.code for item in issues
                                                  if item.level == "error"])


if __name__ == "__main__":
    unittest.main()
