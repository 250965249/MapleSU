import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_source_export import check_export


class SourceExportTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "-q")
        self.write("release/source-policy.json", json.dumps({
            "excluded_prefixes": [".handoff/", "work/"],
            "excluded_files": ["docs/internal.md"],
            "required_files": ["README.md"],
        }))
        self.write("README.md", "Public source\n")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args])

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self):
        self.git("add", "-f", ".")
        self.git("-c", "user.name=Source export test", "-c", "user.email=export@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD").decode().strip()

    def test_force_added_private_files_are_excluded_from_archive(self):
        self.write(".gitignore", ".handoff/\nwork/\n")
        self.write(".gitattributes", ".handoff/ export-ignore\nwork/ export-ignore\ndocs/internal.md export-ignore\n")
        self.write(".handoff/verification.json", "private")
        self.write("work/notes.txt", "research")
        self.write("docs/internal.md", "internal")
        self.commit()
        result = check_export(self.root)
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(4, result["files_checked"])

    def test_missing_export_attribute_rejects_private_file(self):
        self.write(".handoff/verification.json", "private")
        self.commit()
        errors = check_export(self.root)["errors"]
        self.assertEqual(["excluded path in source archive: .handoff/verification.json"], errors)

    def test_excluded_individual_file_is_checked(self):
        self.write("docs/internal.md", "internal")
        self.commit()
        self.assertIn("excluded path in source archive: docs/internal.md", check_export(self.root)["errors"])

    def test_missing_required_document_is_rejected(self):
        self.write(".gitattributes", "README.md export-ignore\n")
        self.commit()
        self.assertIn("missing required file in source archive: README.md", check_export(self.root)["errors"])

    def test_uncommitted_files_do_not_change_committed_export(self):
        commit = self.commit()
        self.write(".handoff/uncommitted.txt", "local")
        self.write("work/local.txt", "local")
        result = check_export(self.root)
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(commit, result["source_commit"])

    def test_selected_revision_supplies_its_own_policy(self):
        commit = self.commit()
        self.write("release/source-policy.json", json.dumps({"required_files": ["missing.md"]}))
        self.commit()
        self.assertTrue(check_export(self.root, commit)["passed"])
        self.assertFalse(check_export(self.root)["passed"])

    def native_input(self):
        self.write("sdk/library.a", "fixed SDK")
        self.write("release/native-inputs.json", json.dumps({"files": [{
            "path": "sdk/library.a", "bytes": 9,
            "sha256": hashlib.sha256(b"fixed SDK").hexdigest(),
        }]}))
        self.write("release/source-policy.json", json.dumps({
            "native_input_manifest": "release/native-inputs.json",
        }))

    def test_native_input_is_verified_from_committed_archive(self):
        self.native_input()
        self.commit()
        self.write("sdk/library.a", "local change")
        result = check_export(self.root)
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(1, result["native_inputs_checked"])

    def test_excluded_sdk_library_is_rejected(self):
        self.native_input()
        self.write(".gitattributes", "sdk/ export-ignore\n")
        self.commit()
        self.assertIn("missing native build input in source archive: sdk/library.a",
                      check_export(self.root)["errors"])

    def test_changed_sdk_library_is_rejected(self):
        self.native_input()
        self.write("sdk/library.a", "other SDK")
        self.commit()
        self.assertIn("native build input differs in source archive: sdk/library.a",
                      check_export(self.root)["errors"])


if __name__ == "__main__":
    unittest.main()
