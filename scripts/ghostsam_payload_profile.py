#!/usr/bin/env python3
"""GhostSam 外部 payload profile 生成/校验工具（MapleSU Normal 专用）。

本工具只做**离线静态校验与清单生成**：不构建 APK/LKM、不生成或伪造任何签名、不触设备/网络、
不读取密钥。它把一套 MapleSU Normal 产物（ksud ELF + per-KMI kernelsu.ko + manager 身份字段）
校验成一个 GhostSam 外部 payload profile（供后续独立适配层使用），并对缺失/错误输入 fail-closed。

校验项（全部硬性）
- ksud：arm64 ELF64 小端（e_machine=183）、含 ASCII ``late-load``、固定版本戳 ``KSU_NO_NEW_PRIVS32650``；
- ko：文件名形如 ``<kmi>_kernelsu.ko``，每个都是 arm64 ELF；必须覆盖所需 KMI（默认
  ``android12-5.10`` 与 ``android16-6.12``，对应 GhostSam s22 与 s26/zf8）；
- SHA256/sidecar：为 ksud 与每个 ko 记录 sha256+size；提供 sidecar 时逐项比对，必须一致；
- manager 身份：package == ``dev.maplesu.manager``，cert DER size == 772，
  cert DER sha256 == ``30bafb57e3604afe93da13a1285516e043feb82b56a861a157b53ccaa27c3506``。
  只校验**公开身份字段**；若给 ``--manager-apk``，只记录其 sha256/size 且 ``signature_verified=false``，
  绝不由本工具“验证/伪造”签名（真实签名校验需 apksigner + 已签名 APK，本机不具备）。

用法
----
    py -3 scripts/ghostsam_payload_profile.py --self-test
    py -3 scripts/ghostsam_payload_profile.py build --ksud ksud --ko-dir lkm \
        --manager-manifest manifest.json --out profile.json [--sidecar profile.sidecar.json]
    py -3 scripts/ghostsam_payload_profile.py verify --profile profile.json \
        --ksud ksud --ko-dir lkm [--manager-manifest manifest.json] [--sidecar profile.sidecar.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import tempfile
from pathlib import Path

EXPECTED_MANAGER_PACKAGE = "dev.maplesu.manager"
EXPECTED_CERT_SHA256 = "30bafb57e3604afe93da13a1285516e043feb82b56a861a157b53ccaa27c3506"
EXPECTED_CERT_SIZE = 772
EXPECTED_VERSION_CODE = 32650
DEFAULT_REQUIRED_KMIS = ("android12-5.10", "android16-6.12")

EM_AARCH64 = 183
KMI_RE = re.compile(r"^(?P<kmi>android\d+-\d+\.\d+)_kernelsu\.ko$")
STAMP_RE = re.compile(rb"KSU_NO_NEW_PRIVS(\d{5})")


class ProfileError(RuntimeError):
    pass


def _self_check_constants() -> None:
    if len(EXPECTED_CERT_SHA256) != 64 or any(c not in "0123456789abcdef" for c in EXPECTED_CERT_SHA256):
        raise ProfileError("internal constant: EXPECTED_CERT_SHA256 must be 64 lowercase hex chars")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_arm64_elf(data: bytes) -> dict:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ProfileError("not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class != 2:
        raise ProfileError(f"not ELF64 (EI_CLASS={ei_class})")
    if ei_data != 1:
        raise ProfileError(f"not little-endian (EI_DATA={ei_data})")
    (e_machine,) = struct.unpack_from("<H", data, 18)
    if e_machine != EM_AARCH64:
        raise ProfileError(f"not AArch64 (e_machine={e_machine}, want {EM_AARCH64})")
    return {"class": "ELF64", "endian": "LE", "machine": "AArch64"}


def detect_version_code(data: bytes) -> int:
    codes = sorted({int(m.group(1)) for m in STAMP_RE.finditer(data)})
    if not codes:
        raise ProfileError("no KSU_NO_NEW_PRIVS<code> build stamp found")
    if len(codes) > 1:
        raise ProfileError(f"ambiguous build stamps: {codes}")
    return codes[0]


def validate_ksud(path: Path, required_version: int = EXPECTED_VERSION_CODE) -> dict:
    if not path.is_file():
        raise ProfileError(f"ksud not found: {path}")
    data = path.read_bytes()
    elf = parse_arm64_elf(data)
    if b"late-load" not in data:
        raise ProfileError("ksud lacks ASCII 'late-load' marker")
    code = detect_version_code(data)
    if code != required_version:
        raise ProfileError(f"ksud version stamp {code} != required {required_version}")
    return {"file": path.name, "size": len(data), "sha256": sha256_bytes(data), "elf": elf, "version_code": code, "late_load": True}


def validate_ko(path: Path) -> dict:
    if not path.is_file():
        raise ProfileError(f"ko not found: {path}")
    m = KMI_RE.match(path.name)
    if not m:
        raise ProfileError(f"ko filename must be <kmi>_kernelsu.ko: {path.name}")
    data = path.read_bytes()
    elf = parse_arm64_elf(data)
    return {"file": path.name, "kmi": m.group("kmi"), "size": len(data), "sha256": sha256_bytes(data), "elf": elf}


def collect_kos(ko_dir: Path, required_kmis: tuple[str, ...]) -> list[dict]:
    if not ko_dir.is_dir():
        raise ProfileError(f"ko dir not found: {ko_dir}")
    kos = [validate_ko(p) for p in sorted(ko_dir.iterdir()) if p.is_file() and KMI_RE.match(p.name)]
    if not kos:
        raise ProfileError(f"no <kmi>_kernelsu.ko files in {ko_dir}")
    present = {k["kmi"] for k in kos}
    missing = [k for k in required_kmis if k not in present]
    if missing:
        raise ProfileError(f"missing required KMI(s): {missing}; present={sorted(present)}")
    return kos


def validate_manager_manifest(path: Path | None) -> dict:
    if path is None:
        raise ProfileError("manager identity not supplied (--manager-manifest required for fail-closed validation)")
    if not path.is_file():
        raise ProfileError(f"manager manifest not found: {path}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    ident = doc.get("identity", doc)
    pkg = ident.get("packageName") or ident.get("managerPackage")
    hashv = (ident.get("expectedHash") or "").lower()
    sizev = ident.get("expectedSize")
    if pkg != EXPECTED_MANAGER_PACKAGE:
        raise ProfileError(f"manager package {pkg!r} != {EXPECTED_MANAGER_PACKAGE}")
    if hashv != EXPECTED_CERT_SHA256:
        raise ProfileError(f"manager cert sha256 {hashv!r} != pinned {EXPECTED_CERT_SHA256}")
    if int(sizev) != EXPECTED_CERT_SIZE:
        raise ProfileError(f"manager cert DER size {sizev} != {EXPECTED_CERT_SIZE}")
    return {"package": pkg, "cert_sha256": hashv, "cert_der_size": int(sizev)}


def validate_manager_from_constants(manager: dict | None) -> dict:
    """Fail-closed re-check of profile['manager'] against the pinned MapleSU constants.

    Used by verify_profile when no --manager-manifest is supplied, so a tampered profile
    manager block cannot pass silently (F3).
    """
    if not isinstance(manager, dict):
        raise ProfileError("profile missing 'manager' identity (fail-closed)")
    pkg = manager.get("package")
    hashv = (manager.get("cert_sha256") or "").lower()
    sizev = manager.get("cert_der_size")
    if pkg != EXPECTED_MANAGER_PACKAGE:
        raise ProfileError(f"profile manager package {pkg!r} != {EXPECTED_MANAGER_PACKAGE}")
    if hashv != EXPECTED_CERT_SHA256:
        raise ProfileError(f"profile manager cert sha256 {hashv!r} != pinned {EXPECTED_CERT_SHA256}")
    if int(sizev) != EXPECTED_CERT_SIZE:
        raise ProfileError(f"profile manager cert DER size {sizev} != {EXPECTED_CERT_SIZE}")
    return {"package": pkg, "cert_sha256": hashv, "cert_der_size": int(sizev)}


def _fingerprint(path: Path | None) -> dict | None:
    if path is None:
        return None
    if not path.is_file():
        raise ProfileError(f"manager apk not found: {path}")
    return {"file": path.name, "size": path.stat().st_size, "sha256": sha256_file(path), "signature_verified": False}


def build_sidecar(profile: dict) -> dict:
    files = {}
    for e in [profile["ksud"]] + profile["kos"]:
        files[e["file"]] = {"sha256": e["sha256"], "size": e["size"]}
    return {"schema": 1, "files": files}


def disk_files(ks: dict, kos: list[dict]) -> dict[str, dict]:
    """Rebuild the {file: {sha256,size}} map from the on-disk validated entries."""
    out: dict[str, dict] = {ks["file"]: {"sha256": ks["sha256"], "size": ks["size"]}}
    for k in kos:
        out[k["file"]] = {"sha256": k["sha256"], "size": k["size"]}
    return out


def verify_sidecar(side: dict, profile: dict, disk: dict[str, dict] | None = None) -> None:
    files = (side or {}).get("files")
    if not isinstance(files, dict) or not files:
        raise ProfileError("sidecar missing 'files' map")
    for e in [profile["ksud"]] + profile["kos"]:
        rec = files.get(e["file"])
        if rec is None:
            raise ProfileError(f"sidecar missing entry for {e['file']}")
        if rec.get("sha256") != e["sha256"] or int(rec.get("size", -1)) != e["size"]:
            raise ProfileError(f"sidecar mismatch for {e['file']}")
    # Fail-closed against the actual files on disk (not just the profile): a tampered
    # ko/ksud whose profile still carries the old hash must be rejected here.
    if disk is not None:
        for name, rec in disk.items():
            got = files.get(name)
            if got is None:
                raise ProfileError(f"sidecar missing on-disk file entry: {name}")
            if got.get("sha256") != rec["sha256"] or int(got.get("size", -1)) != rec["size"]:
                raise ProfileError(f"sidecar does not match on-disk {name} (tampered?)")


def build_profile(ksud: Path, ko_dir: Path, manager_manifest: Path | None,
                  required_kmis: tuple[str, ...] = DEFAULT_REQUIRED_KMIS,
                  manager_apk: Path | None = None) -> dict:
    _self_check_constants()
    return {
        "schema": 1,
        "kind": "ghostsam-external-payload-profile",
        "variant": "maplesu-normal",
        "ksud": validate_ksud(ksud),
        "kos": collect_kos(ko_dir, required_kmis),
        "required_kmi": list(required_kmis),
        "manager": validate_manager_manifest(manager_manifest),
        "manager_apk": _fingerprint(manager_apk),
        "built": False,
        "note": "静态清单；未构建 APK/LKM；manager APK 若提供仅记录指纹，signature_verified=false",
    }


def verify_profile(profile: dict, ksud: Path, ko_dir: Path, manager_manifest: Path | None,
                   sidecar: Path | None = None,
                   required_kmis: tuple[str, ...] = DEFAULT_REQUIRED_KMIS) -> dict:
    _self_check_constants()
    ks = validate_ksud(ksud)
    pks = profile.get("ksud") or {}
    if ks["sha256"] != pks.get("sha256") or int(ks["size"]) != int(pks.get("size", -1)) or ks["version_code"] != pks.get("version_code"):
        raise ProfileError("ksud size/sha256/version changed vs profile")

    disk_kos = collect_kos(ko_dir, required_kmis)
    prof_kos = profile.get("kos")
    if not isinstance(prof_kos, list) or not prof_kos:
        raise ProfileError("profile has no 'kos' entries (fail-closed)")
    prof_by_file = {e.get("file"): e for e in prof_kos}
    disk_by_file = {k["file"]: k for k in disk_kos}
    if set(prof_by_file) != set(disk_by_file):
        raise ProfileError(
            f"ko file set differs: profile={sorted(prof_by_file)} disk={sorted(disk_by_file)}")
    for name, k in disk_by_file.items():
        e = prof_by_file[name]
        if k["kmi"] != e.get("kmi"):
            raise ProfileError(f"{name}: kmi {k['kmi']} != profile {e.get('kmi')!r}")
        if int(k["size"]) != int(e.get("size", -1)):
            raise ProfileError(f"{name}: size {k['size']} != profile {e.get('size')} (tampered?)")
        if k["sha256"] != e.get("sha256"):
            raise ProfileError(f"{name}: sha256 changed vs profile (tampered?)")

    # manager identity: always re-check profile block against pinned constants; if a manifest
    # is given, validate it too. Never skip when the flag is absent (F3).
    validate_manager_from_constants(profile.get("manager"))
    if manager_manifest is not None:
        validate_manager_manifest(manager_manifest)

    disk = disk_files(ks, disk_kos)
    if sidecar is not None:
        side = json.loads(sidecar.read_text(encoding="utf-8"))
        verify_sidecar(side, profile, disk=disk)
    return {"verified": True, "ksud_sha256": ks["sha256"], "ko_count": len(disk_kos)}


# --------------------------------------------------------------------------- self-test
def _mk_elf(machine: int = EM_AARCH64, extra: bytes = b"") -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2   # ELF64
    hdr[5] = 1   # LE
    hdr[6] = 1   # version
    struct.pack_into("<H", hdr, 18, machine)
    return bytes(hdr) + extra


def _mk_ksud(code: int = 32650, machine: int = EM_AARCH64, late_load: bool = True) -> bytes:
    extra = b"\x00" + f"KSU_NO_NEW_PRIVS{code}".encode() + b"\x00"
    if late_load:
        extra += b" ... late-load --kmi ..."
    return _mk_elf(machine, extra)


def _mk_ko(machine: int = EM_AARCH64) -> bytes:
    return _mk_elf(machine, b"kernelsu-module")


def self_test() -> int:
    _self_check_constants()
    failures: list[str] = []

    def expect_ok(name, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}: unexpected failure: {exc}")

    def expect_fail(name, fn, needle=None):
        try:
            fn()
        except ProfileError as exc:
            if needle and needle not in str(exc):
                failures.append(f"{name}: wrong error ({exc!r})")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}: non-ProfileError {exc!r}")
        else:
            failures.append(f"{name}: expected fail-closed but passed")

    with tempfile.TemporaryDirectory(prefix="gs-profile-selftest-") as td:
        root = Path(td)
        ksud = root / "ksud"; ksud.write_bytes(_mk_ksud())
        lkm = root / "lkm"; lkm.mkdir()
        (lkm / "android12-5.10_kernelsu.ko").write_bytes(_mk_ko())
        (lkm / "android16-6.12_kernelsu.ko").write_bytes(_mk_ko())
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"identity": {"packageName": EXPECTED_MANAGER_PACKAGE,
                                                     "expectedHash": EXPECTED_CERT_SHA256,
                                                     "expectedSize": EXPECTED_CERT_SIZE}}), encoding="utf-8")

        expect_ok("build", lambda: build_profile(ksud, lkm, manifest))
        prof = build_profile(ksud, lkm, manifest)
        side = build_sidecar(prof)
        sidep = root / "profile.sidecar.json"; sidep.write_text(json.dumps(side), encoding="utf-8")
        expect_ok("verify", lambda: verify_profile(prof, ksud, lkm, manifest, sidep))

        (root / "x86").write_bytes(_mk_ksud(machine=62))
        expect_fail("ksud-x86", lambda: validate_ksud(root / "x86"), "AArch64")
        (root / "nolateload").write_bytes(_mk_ksud(late_load=False))
        expect_fail("ksud-no-lateload", lambda: validate_ksud(root / "nolateload"), "late-load")
        (root / "badver").write_bytes(_mk_ksud(code=32651))
        expect_fail("ksud-badver", lambda: validate_ksud(root / "badver"), "32651")
        (root / "nostamp").write_bytes(_mk_elf(EM_AARCH64, b"late-load but no build stamp"))
        expect_fail("ksud-nostamp", lambda: validate_ksud(root / "nostamp"), "stamp")
        lkm2 = root / "lkm2"; lkm2.mkdir(); (lkm2 / "android14-6.1_kernelsu.ko").write_bytes(_mk_ko())
        expect_fail("ko-missing-kmi", lambda: collect_kos(lkm2, DEFAULT_REQUIRED_KMIS), "missing required KMI")
        bad = root / "lkm3"; bad.mkdir()
        (bad / "android12-5.10_kernelsu.ko").write_bytes(b"not-elf")
        (bad / "android16-6.12_kernelsu.ko").write_bytes(_mk_ko())
        expect_fail("ko-non-elf", lambda: collect_kos(bad, DEFAULT_REQUIRED_KMIS), "ELF")
        m2 = root / "m2.json"; m2.write_text(json.dumps({"identity": {"packageName": "me.weishu.kernelsu", "expectedHash": EXPECTED_CERT_SHA256, "expectedSize": EXPECTED_CERT_SIZE}}), encoding="utf-8")
        expect_fail("manager-pkg", lambda: validate_manager_manifest(m2), "package")
        m3 = root / "m3.json"; m3.write_text(json.dumps({"identity": {"packageName": EXPECTED_MANAGER_PACKAGE, "expectedHash": "0"*64, "expectedSize": EXPECTED_CERT_SIZE}}), encoding="utf-8")
        expect_fail("manager-hash", lambda: validate_manager_manifest(m3), "cert sha256")
        m4 = root / "m4.json"; m4.write_text(json.dumps({"identity": {"packageName": EXPECTED_MANAGER_PACKAGE, "expectedHash": EXPECTED_CERT_SHA256, "expectedSize": 771}}), encoding="utf-8")
        expect_fail("manager-size", lambda: validate_manager_manifest(m4), "DER size")
        expect_fail("manager-missing", lambda: validate_manager_manifest(None), "not supplied")
        badside = json.loads(json.dumps(side)); badside["files"]["ksud"]["sha256"] = "0"*64
        expect_fail("sidecar-mismatch", lambda: verify_sidecar(badside, prof), "mismatch")

        # F2 regression: tamper a ko on disk -> verify MUST fail (with and without sidecar).
        lkm_ok = root / "lkm_ok"; lkm_ok.mkdir()
        (lkm_ok / "android12-5.10_kernelsu.ko").write_bytes(_mk_ko())
        (lkm_ok / "android16-6.12_kernelsu.ko").write_bytes(_mk_ko())
        prof_ok = build_profile(ksud, lkm_ok, manifest)
        (lkm_ok / "android12-5.10_kernelsu.ko").write_bytes(_mk_elf(EM_AARCH64, b"kernelsu-module-TAMPERED"))
        expect_fail("verify-tampered-ko", lambda: verify_profile(prof_ok, ksud, lkm_ok, manifest, None), "tampered")
        expect_fail("verify-tampered-ko-sidecar", lambda: verify_profile(prof_ok, ksud, lkm_ok, manifest, sidep), "tampered")

        # F3 regression: tampered profile['manager'] must fail even without --manager-manifest.
        lkm_ok2 = root / "lkm_ok2"; lkm_ok2.mkdir()
        (lkm_ok2 / "android12-5.10_kernelsu.ko").write_bytes(_mk_ko())
        (lkm_ok2 / "android16-6.12_kernelsu.ko").write_bytes(_mk_ko())
        prof_ok2 = build_profile(ksud, lkm_ok2, manifest)
        prof_mgr = json.loads(json.dumps(prof_ok2)); prof_mgr["manager"]["cert_sha256"] = "0" * 64
        expect_fail("manager-profile-hash-no-manifest", lambda: verify_profile(prof_mgr, ksud, lkm_ok2, None, None), "manager cert sha256")
        prof_mgr2 = json.loads(json.dumps(prof_ok2)); prof_mgr2["manager"]["cert_der_size"] = 1
        expect_fail("manager-profile-size-no-manifest", lambda: verify_profile(prof_mgr2, ksud, lkm_ok2, None, None), "manager cert DER size")
        prof_nomgr = json.loads(json.dumps(prof_ok2)); prof_nomgr.pop("manager", None)
        expect_fail("manager-profile-missing", lambda: verify_profile(prof_nomgr, ksud, lkm_ok2, None, None), "manager")

    if failures:
        print("[FAIL] self-test failures:")
        for f in failures:
            print("  -", f)
        return 1
    print("[OK] self-test passed: positive build/verify + 18 fail-closed cases (incl. tampered ko & manager)")
    print("[OK] constants: package=%s cert=%s size=%d version=%d" % (EXPECTED_MANAGER_PACKAGE, EXPECTED_CERT_SHA256, EXPECTED_CERT_SIZE, EXPECTED_VERSION_CODE))
    return 0


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="运行内置正反例自测并退出")
    sub = ap.add_subparsers(dest="cmd")

    b = sub.add_parser("build", help="构建外部 payload profile 清单 + sidecar")
    b.add_argument("--ksud", type=Path, required=True)
    b.add_argument("--ko-dir", type=Path, required=True)
    b.add_argument("--manager-manifest", type=Path, required=True)
    b.add_argument("--manager-apk", type=Path, default=None)
    b.add_argument("--kmi", action="append", default=None, help="required KMI（默认 s22/s26）")
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--sidecar", type=Path, default=None)

    v = sub.add_parser("verify", help="对已有 profile 重新校验")
    v.add_argument("--profile", type=Path, required=True)
    v.add_argument("--ksud", type=Path, required=True)
    v.add_argument("--ko-dir", type=Path, required=True)
    v.add_argument("--manager-manifest", type=Path, default=None)
    v.add_argument("--sidecar", type=Path, default=None)
    v.add_argument("--kmi", action="append", default=None)

    args = ap.parse_args(argv)
    if args.self_test or args.cmd is None:
        return self_test()
    try:
        kmis = tuple(args.kmi) if args.kmi else DEFAULT_REQUIRED_KMIS
        if args.cmd == "build":
            prof = build_profile(args.ksud, args.ko_dir, args.manager_manifest, kmis, args.manager_apk)
            args.out.write_text(json.dumps(prof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"[OK] profile written: {args.out} (ksud sha256={prof['ksud']['sha256']}, ko={len(prof['kos'])})")
            if args.sidecar:
                side = build_sidecar(prof)
                args.sidecar.write_text(json.dumps(side, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                print(f"[OK] sidecar written: {args.sidecar}")
            return 0
        if args.cmd == "verify":
            prof = json.loads(args.profile.read_text(encoding="utf-8"))
            res = verify_profile(prof, args.ksud, args.ko_dir, args.manager_manifest, args.sidecar, kmis)
            print(f"[OK] profile verified: ksud sha256={res['ksud_sha256']}, ko={res['ko_count']}")
            return 0
    except ProfileError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
