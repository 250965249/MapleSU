from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import ghostsam_payload_profile as m  # noqa: E402


def mk_elf(machine: int = m.EM_AARCH64, extra: bytes = b"") -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    struct.pack_into("<H", hdr, 18, machine)
    return bytes(hdr) + extra


def mk_ksud(code: int = m.EXPECTED_VERSION_CODE, machine: int = m.EM_AARCH64, late: bool = True) -> bytes:
    extra = b"\x00" + f"KSU_NO_NEW_PRIVS{code}".encode() + b"\x00"
    if late:
        extra += b" ... late-load ..."
    return mk_elf(machine, extra)


class PayloadProfileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="gs-test-profile-")
        self.root = Path(self._tmp.name)
        self.ksud = self.root / "ksud"
        self.ksud.write_bytes(mk_ksud())
        self.lkm = self.root / "lkm"
        self.lkm.mkdir()
        (self.lkm / "android12-5.10_kernelsu.ko").write_bytes(mk_elf(extra=b"ko"))
        (self.lkm / "android16-6.12_kernelsu.ko").write_bytes(mk_elf(extra=b"ko"))
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"identity": {
            "packageName": m.EXPECTED_MANAGER_PACKAGE,
            "expectedHash": m.EXPECTED_CERT_SHA256,
            "expectedSize": m.EXPECTED_CERT_SIZE,
        }}), encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    # ---- positive path + CLI contract ----
    def test_build_verify_cli_and_profile_fields(self):
        prof_path = self.root / "profile.json"
        side_path = self.root / "profile.sidecar.json"
        rc = m.main(["build", "--ksud", str(self.ksud), "--ko-dir", str(self.lkm),
                     "--manager-manifest", str(self.manifest), "--out", str(prof_path),
                     "--sidecar", str(side_path)])
        self.assertEqual(0, rc)
        prof = json.loads(prof_path.read_text(encoding="utf-8"))
        self.assertEqual("ghostsam-external-payload-profile", prof["kind"])
        self.assertEqual(m.EXPECTED_VERSION_CODE, prof["ksud"]["version_code"])
        self.assertEqual("AArch64", prof["ksud"]["elf"]["machine"])
        self.assertEqual("dev.maplesu.manager", prof["manager"]["package"])
        self.assertEqual(772, prof["manager"]["cert_der_size"])
        self.assertFalse(prof["built"])
        self.assertEqual({"android12-5.10", "android16-6.12"}, {k["kmi"] for k in prof["kos"]})
        # verify subcommand re-checks hashes + sidecar
        rc2 = m.main(["verify", "--profile", str(prof_path), "--ksud", str(self.ksud),
                      "--ko-dir", str(self.lkm), "--manager-manifest", str(self.manifest),
                      "--sidecar", str(side_path)])
        self.assertEqual(0, rc2)
        # self-test entry
        self.assertEqual(0, m.main(["--self-test"]))

    # ---- fail-closed negatives ----
    def test_wrong_machine_rejected(self):
        p = self.root / "x"; p.write_bytes(mk_ksud(machine=62))
        with self.assertRaises(m.ProfileError):
            m.validate_ksud(p)

    def test_missing_late_load_rejected(self):
        p = self.root / "x"; p.write_bytes(mk_ksud(late=False))
        with self.assertRaises(m.ProfileError):
            m.validate_ksud(p)

    def test_wrong_version_rejected(self):
        p = self.root / "x"; p.write_bytes(mk_ksud(code=32651))
        with self.assertRaises(m.ProfileError):
            m.validate_ksud(p)

    def test_missing_kmi_rejected(self):
        d = self.root / "lkm14"; d.mkdir()
        (d / "android14-6.1_kernelsu.ko").write_bytes(mk_elf(extra=b"ko"))
        with self.assertRaises(m.ProfileError):
            m.collect_kos(d, m.DEFAULT_REQUIRED_KMIS)

    def test_manager_identity_negative(self):
        bad = self.root / "bad.json"
        bad.write_text(json.dumps({"identity": {"packageName": "dev.maplesu.manager",
                                                "expectedHash": "0" * 64,
                                                "expectedSize": 772}}), encoding="utf-8")
        with self.assertRaises(m.ProfileError):
            m.validate_manager_manifest(bad)
        with self.assertRaises(m.ProfileError):
            m.validate_manager_manifest(None)

    def test_sidecar_mismatch_rejected(self):
        prof = m.build_profile(self.ksud, self.lkm, self.manifest)
        side = m.build_sidecar(prof)
        side["files"]["ksud"]["sha256"] = "0" * 64
        with self.assertRaises(m.ProfileError):
            m.verify_sidecar(side, prof)


if __name__ == "__main__":
    unittest.main()
