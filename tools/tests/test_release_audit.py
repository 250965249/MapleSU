import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_audit import audit, audit_files, git_candidates


class ReleaseAuditTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, data):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def test_forced_staged_ignored_credentials_are_audited(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write(".gitignore", b"secret.pem\n")
        self.write("secret.pem", b"-----BEGIN " + b"PRIVATE KEY-----\n" + b"A" * 160 + b"\n")
        subprocess.run(["git", "-C", str(self.root), "add", "-f", "secret.pem"], check=True)
        names = git_candidates(self.root)
        self.assertIn("secret.pem", names)
        self.assertTrue(any("credential content" in e for e in audit_files(self.root, names, {})))

    def test_a_parser_marker_is_not_itself_a_private_key(self):
        self.write("parser.py", b'header = "-----BEGIN RSA PRIVATE KEY-----"')
        self.assertEqual([], audit_files(self.root, ["parser.py"], {}))

    def test_nested_repositories_expand_sources_not_git_metadata(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        child = self.root / "vendor"
        subprocess.run(["git", "init", "-q", str(child)], check=True)
        self.write("vendor/source.c", b"int fixture;")
        self.assertIn("vendor/source.c", git_candidates(self.root))
        self.assertFalse(any(".git/" in p for p in git_candidates(self.root)))

    def test_public_test_keys_are_allowed_only_at_the_pinned_digest(self):
        data = b"publicly documented fixture"
        self.write("fixture.pem", data)
        policy = {"public_test_keys": {"fixture.pem": hashlib.sha256(data).hexdigest()}}
        self.assertEqual([], audit_files(self.root, ["fixture.pem"], policy))
        self.write("fixture.pem", b"changed")
        self.assertTrue(any("digest changed" in e for e in audit_files(self.root, ["fixture.pem"], policy)))

    def test_ignored_existing_files_do_not_satisfy_public_doc_links(self):
        self.write("README.md", b"[private](docs/internal.md)\n")
        self.write("docs/internal.md", b"local only")
        errors = audit_files(self.root, ["README.md"], {})
        self.assertTrue(any("missing candidate document target" in e for e in errors))
        self.assertEqual([], audit_files(self.root, ["README.md", "docs/internal.md"], {}))

    def test_extensionless_native_binaries_are_detected(self):
        self.write("native/tool", b"\x7fELFfixture")
        self.assertTrue(any("binary/artifact" in e for e in audit_files(self.root, ["native/tool"], {})))

    def test_excluded_and_outside_paths_are_detected(self):
        self.write("work/note.md", b"internal")
        errors = audit_files(self.root, ["work/note.md", "../outside"], {"excluded_prefixes": ["work/"]})
        self.assertEqual(2, len(errors))

    def test_strict_mode_rejects_unresolved_backend_even_with_clean_files(self):
        self.write("release/source-policy.json", json.dumps({"release_blockers": [
            {"id": "backend", "resolved": False, "detail": "source replacement pending"}]}).encode())
        self.assertTrue(audit(self.root, ["release/source-policy.json"], False)["passed"])
        self.assertFalse(audit(self.root, ["release/source-policy.json"], True)["passed"])

    def test_strict_mode_requires_boolean_resolution(self):
        name = "release/source-policy.json"
        for value in ("false", "true", 1, True):
            with self.subTest(value=value):
                self.write(name, json.dumps({"release_blockers": [
                    {"id": "acceptance", "resolved": value}]}).encode())
                self.assertEqual(value is True, audit(self.root, [name], True)["passed"])

    def test_retained_native_library_requires_matching_bytes(self):
        data = b"\x7fELFretained SDK"
        self.write("sdk/library.a", data)
        self.write("release/native-inputs.json", json.dumps({"files": [{
            "path": "sdk/library.a", "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }]}).encode())
        policy = {"native_input_manifest": "release/native-inputs.json"}
        self.assertEqual([], audit_files(self.root, ["sdk/library.a"], policy))
        self.write("sdk/library.a", b"\x7fELFchanged SDK!")
        self.assertTrue(any("digest changed" in e for e in
                            audit_files(self.root, ["sdk/library.a"], policy)))

    def test_omitted_native_library_is_rejected(self):
        self.write("release/native-inputs.json", json.dumps({"files": [{
            "path": "sdk/library.a", "bytes": 16, "sha256": "0" * 64,
        }]}).encode())
        errors = audit_files(self.root, [], {"native_input_manifest": "release/native-inputs.json"})
        self.assertIn("missing native build input: sdk/library.a", errors)


if __name__ == "__main__":
    unittest.main()
