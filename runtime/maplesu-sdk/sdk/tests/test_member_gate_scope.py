#!/usr/bin/env python3
"""Gate membership follows the selected freeze, including its tail members."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import member_gate as G


class FreezeScopeTests(unittest.TestCase):
    def run_gate(self, reference_count, selected=None, declared=None, changed=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            new_path = root / "new.a"
            new_path.touch()
            ref_path = root / "ref.a"
            selected = list(range(reference_count)) if selected is None else selected
            declared = selected if declared is None else declared
            manifest = root / "manifest.jsonl"
            manifest.write_text("".join(json.dumps({"idx": idx, "name": f"m{idx}.o",
                "status": "complete", "sources": [f"m{idx}.cpp"]}) + "\n"
                for idx in declared), encoding="utf-8")

            def archive(path, indices):
                return G.S.Archive(path, "fixture", 0, [
                    G.S.ArchiveMember(pos, f"m{idx}.o", b"\x7fELF", 0)
                    for pos, idx in enumerate(indices)])

            ref = archive(ref_path, range(reference_count))
            new = archive(new_path, selected)

            def measure(_tc, archive, _work, **_kwargs):
                return {(member.name, 0): G.MemberFacts(member.idx, member.name, 0,
                    "fixture", 4, "elf", t=frozenset(["entry"]),
                    u=frozenset(["changed"]) if archive is new and member.name == changed
                    else frozenset()) for member in archive.members}

            with patch.object(G.S, "resolve_toolchain", return_value=object()), \
                 patch.object(G.S, "find_freeze", return_value=SimpleNamespace(
                     root=root, archive=ref_path)), \
                 patch.object(G.S, "read_archive", side_effect=lambda path:
                     ref if path == ref_path else new), \
                 patch.object(G, "measure_archive", side_effect=measure):
                return G.run_gate(new_path, out_path=root / "report.json",
                    manifest_path=manifest, allow_path=root / "no-allow.json",
                    baseline_path=root / "no-baseline.json", quiet=True)

    def test_current_freeze_compares_all_260_members(self):
        result = self.run_gate(260)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["expected_members"], 260)
        self.assertEqual(result["summary"]["compared"], 260)
        self.assertEqual(result["summary"]["extra"], 0)

    def test_historical_freeze_keeps_258_member_contract(self):
        result = self.run_gate(258)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["expected_members"], 258)
        self.assertEqual(result["summary"]["compared"], 258)

    def test_full_manifest_detects_missing_tail_members(self):
        result = self.run_gate(260, selected=list(range(258)), declared=list(range(260)))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["summary"]["missing"], 2)

    def test_historical_freeze_detects_extra_tail_members(self):
        result = self.run_gate(258, selected=list(range(260)))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["summary"]["extra"], 2)

    def test_partial_manifest_includes_selected_tail_members(self):
        result = self.run_gate(260, selected=[0, 258, 259])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["scope"], "partial")
        self.assertEqual(result["summary"]["compared"], 3)
        self.assertEqual(result["summary"]["deferred"], 257)

    def test_258_of_260_declared_members_are_partial(self):
        result = self.run_gate(260, selected=list(range(258)))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["scope"], "partial")
        self.assertEqual(result["summary"]["deferred"], 2)

    def test_tail_symbol_difference_remains_a_failure(self):
        result = self.run_gate(260, changed="m259.o")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["summary"]["fail"], 1)
        self.assertEqual(result["summary"]["u_extra_total"], 1)


if __name__ == "__main__":
    unittest.main()
