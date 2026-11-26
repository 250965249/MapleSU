#!/usr/bin/env python3
"""Dry-run validator for .github/workflows/ghostsam-build.yml (t38).

Checks (no network, no build):
  * YAML parses cleanly;
  * workflow triggers include workflow_dispatch AND branch push;
  * workflow env carries KSU_EXPECTED_SIZE / KSU_EXPECTED_HASH that EXACTLY match
    the committed public test cert (keystore/ghostsam-test.cer): DER length + sha256;
  * all local paths referenced by the workflow exist in the tree;
  * the manager job signs with keystore/ghostsam-test.keystore and publishes the
    fixed-name artifact MapleSU-Manager-ghostsam-test.apk;
  * the LKM/ksud job drives build_lkm.sh (KSU_EXPECTED_* env channel) + build_ksud.sh.

Exit 0 only if every check passes. Prints a [OK]/[FAIL] line per check.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # maplesu-normal repo root
WORKFLOW = ROOT / ".github" / "workflows" / "ghostsam-build.yml"
CERT = ROOT / "keystore" / "ghostsam-test.cer"
KEYSTORE = ROOT / "keystore" / "ghostsam-test.keystore"

REQUIRED_PATHS = [
    "keystore/ghostsam-test.keystore",
    "keystore/ghostsam-test.cer",
    "keystore/README.md",
    "third_party/kernelsu/scripts/build_lkm.sh",
    "third_party/kernelsu/scripts/build_ksud.sh",
    "third_party/kernelsu/patches/7k/series-ghostsam",
    "scripts/ghostsam_patch_dryrun.py",
    "gradlew.bat",
    "manager/build.gradle.kts",
    "requirements-native.txt",
]

failures = 0


def ok(msg: str) -> None:
    print(f"[OK] {msg}")


def fail(msg: str) -> None:
    global failures
    failures += 1
    print(f"[FAIL] {msg}")


def main() -> int:
    try:
        import yaml  # type: ignore
    except Exception as exc:  # pragma: no cover
        print(f"[FAIL] PyYAML unavailable: {exc}")
        return 2

    if not WORKFLOW.is_file():
        print(f"[FAIL] workflow missing: {WORKFLOW}")
        return 2
    text = WORKFLOW.read_text(encoding="utf-8")

    # 1) YAML parses
    try:
        data = yaml.safe_load(text)
    except Exception as exc:
        print(f"[FAIL] YAML parse error: {exc}")
        return 2
    if not isinstance(data, dict):
        print("[FAIL] workflow root is not a mapping")
        return 2
    ok("YAML parses as a mapping")

    # PyYAML (YAML 1.1) turns the bare key `on` into boolean True
    trig = data.get("on", data.get(True))
    if not isinstance(trig, dict):
        fail("trigger block (`on:`) missing or malformed")
    else:
        if "workflow_dispatch" not in trig:
            fail("trigger missing workflow_dispatch")
        else:
            ok("trigger: workflow_dispatch present")
        push = trig.get("push")
        if not isinstance(push, dict) or not push.get("branches"):
            fail("trigger missing push.branches")
        else:
            ok(f"trigger: push.branches={push.get('branches')}")

    # 2) KSU_EXPECTED_* env matches committed test cert
    env = data.get("env") or {}
    size = str(env.get("KSU_EXPECTED_SIZE", "")).strip()
    hsh = str(env.get("KSU_EXPECTED_HASH", "")).strip().lower()
    if not CERT.is_file():
        fail("committed test cert missing: keystore/ghostsam-test.cer")
    else:
        der = CERT.read_bytes()
        real_size = str(len(der))
        real_hash = hashlib.sha256(der).hexdigest()
        if size == real_size:
            ok(f"KSU_EXPECTED_SIZE={size} matches cert DER length")
        else:
            fail(f"KSU_EXPECTED_SIZE='{size}' != cert DER length {real_size}")
        if hsh == real_hash:
            ok(f"KSU_EXPECTED_HASH matches sha256(cert.der)={real_hash}")
        else:
            fail(f"KSU_EXPECTED_HASH='{hsh}' != sha256(cert.der)={real_hash}")
    if not KEYSTORE.is_file():
        fail("committed test keystore missing: keystore/ghostsam-test.keystore")

    # 3) referenced local paths exist
    missing = [p for p in REQUIRED_PATHS if not (ROOT / p).exists()]
    if missing:
        for p in missing:
            fail(f"referenced path missing: {p}")
    else:
        ok(f"all {len(REQUIRED_PATHS)} referenced local paths exist")

    # 4) manager job signs with test keystore + fixed artifact name
    jobs = data.get("jobs") or {}
    mgr = jobs.get("manager")
    if not isinstance(mgr, dict):
        fail("jobs.manager missing")
    else:
        mgr_text = yaml.safe_dump(mgr, allow_unicode=True)
        if "MAPLE_RELEASE_STORE_FILE" in mgr_text and "ghostsam-test.keystore" in mgr_text:
            ok("manager job wires MAPLE_RELEASE_STORE_FILE -> keystore/ghostsam-test.keystore")
        else:
            fail("manager job does not wire MAPLE_RELEASE_STORE_FILE to the test keystore")
        if "MapleSU-Manager-ghostsam-test.apk" in mgr_text:
            ok("manager job publishes fixed name MapleSU-Manager-ghostsam-test.apk")
        else:
            fail("manager job missing fixed artifact name MapleSU-Manager-ghostsam-test.apk")
        if "assembleRelease" in mgr_text:
            ok("manager job runs :manager:assembleRelease")
        else:
            fail("manager job missing :manager:assembleRelease")

    # 5) LKM/ksud job drives build_lkm.sh + build_ksud.sh
    if "build_lkm.sh" in text and "build_ksud.sh" in text:
        ok("workflow drives build_lkm.sh + build_ksud.sh")
    else:
        fail("workflow missing build_lkm.sh / build_ksud.sh invocation")

    print("-" * 60)
    if failures:
        print(f"RESULT: FAIL ({failures} check(s) failed)")
        return 1
    print("RESULT: PASS (workflow syntax + referenced paths + test-cert pins consistent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
