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

    # 6) F1/F2/F3 defects fixed (CI run 45770781379)
    if "--extension-series third_party/kernelsu/patches/7k/series-ghostsam" in text:
        ok("F1: --extension-series uses repo-root relative third_party/kernelsu/patches/7k/series-ghostsam")
    else:
        fail("F1: --extension-series path is not repo-root relative third_party/kernelsu/patches/7k/series-ghostsam")
    if "--extension-series patches/7k/series-ghostsam" in text:
        fail("F1: stale CWD-relative --extension-series path still present")
    if "docker pull" in text and "ghcr.io/ylarod/ddk-min:${{ matrix.kmi }}-${DDK_RELEASE}" in text \
            and "--ddk-image \"$DDK_IMAGE\"" in text:
        ok("F2: per-KMI docker pull ghcr.io/ylarod/ddk-min:<kmi>-<DDK_RELEASE> + --ddk-image passed")
    else:
        fail("F2: missing docker pull / --ddk-image wiring for the per-KMI DDK image")
    try:
        kmis = data["jobs"]["matrix"]["strategy"]["matrix"]["kmi"]
        if isinstance(kmis, list) and len(kmis) == 8:
            ok(f"F2: matrix has 8 Normal KMI entries ({kmis[0]}..{kmis[-1]})")
        else:
            fail(f"F2: matrix KMI count != 8: {kmis!r}")
    except Exception:
        fail("F2: matrix.kmi list missing")
    if "ksud-maplesu-aarch64.version" in text and "cp \"$ksud\" \"out/ksud-maplesu-aarch64\"" in text:
        ok("F3: exports ksud-maplesu-aarch64 + .version sidecar")
    else:
        fail("F3: missing ksud-maplesu-aarch64 / .version export")
    if "libksud_ksu.so" in text:
        ok("F3: ksud product is sourced from libksud_ksu.so")
    else:
        fail("F3: ksud product source libksud_ksu.so missing")

    # 7) F6 Rust target on DEFAULT toolchain; F7 manager inputs/diagnostics
    try:
        matrix_text = yaml.safe_dump(jobs["matrix"], allow_unicode=True)
    except Exception:
        matrix_text = ""
    if "libclang-dev" in matrix_text:
        ok("F6: matrix job installs libclang-dev")
    else:
        fail("F6: matrix job missing libclang-dev install")
    # F6 precise fix (run 45774114076): the target must be installed on the runner
    # DEFAULT toolchain via unconditional `rustup target add`, NOT into a separate
    # 1.99.1 toolchain that build_ksud.sh (default rustc) never uses.
    if "rustup target add aarch64-linux-android" in matrix_text:
        ok("F6: matrix job runs unconditional `rustup target add aarch64-linux-android` (default toolchain)")
    else:
        fail("F6: matrix job missing unconditional `rustup target add aarch64-linux-android`")
    if "rustup toolchain install 1.99.1" in matrix_text:
        fail("F6: stale `rustup toolchain install 1.99.1` still present in matrix job (target lands in wrong toolchain)")
    else:
        ok("F6: no stale `rustup toolchain install 1.99.1` in matrix job")
    mgr_flat = (yaml.safe_dump(mgr, allow_unicode=True) if isinstance(mgr, dict) else "")
    # F7c: the fork manager job PREPARES (downloads+verifies) the pinned public native
    # inputs in CI instead of only --check; a fork checkout may not carry a pinned binary.
    if "tools/prepare_native_inputs.py" in mgr_flat:
        ok("F7c: manager job prepares pinned native inputs (tools/prepare_native_inputs.py, download-capable)")
    else:
        fail("F7c: manager job missing tools/prepare_native_inputs.py preparation")
    if "prepare_native_inputs.py --check" in mgr_flat:
        fail("F7c: stale verify-only `prepare_native_inputs.py --check` present (no download self-heal)")
    else:
        ok("F7c: no verify-only prepare_native_inputs.py --check (CI downloads missing pinned inputs)")
    # F7c: `sync-ultra-sdk-identity.py --check` is unusable (it asserts on the private
    # source-build report .tmp/p1-source-r9-build/report/build-report.json); the fork must
    # regenerate the identity from committed artifacts via GENERATE mode instead.
    if "sync-ultra-sdk-identity.py --check" in mgr_flat:
        fail("F7c: stale `sync-ultra-sdk-identity.py --check` present (private build-report input)")
    else:
        ok("F7c: no sync-ultra-sdk-identity.py --check (private .tmp build-report input removed)")
    if "sync-ultra-sdk-identity.py" in mgr_flat:
        ok("F7c: manager job regenerates Ultra SDK identity from committed manifest (generate mode)")
    else:
        fail("F7c: manager job does not regenerate the Ultra SDK identity (scripts/sync-ultra-sdk-identity.py)")
    # F7c: failure diagnostics must capture the exact native build error (build.py -> build.log).
    if ("manager/build/jailbreakProviders" in text and "build.log" in text and "build.json" in text):
        ok("F7c: manager failure diagnostics capture buildJailbreakProviders build.log/build.json")
    else:
        fail("F7c: manager failure diagnostics missing manager/build/jailbreakProviders build.log/build.json")
    if "manager-failure-logs" in text:
        ok("F7: manager failure diagnostics artifact configured")
    else:
        fail("F7: manager failure diagnostics artifact missing")

    print("-" * 60)
    if failures:
        print(f"RESULT: FAIL ({failures} check(s) failed)")
        return 1
    print("RESULT: PASS (workflow syntax + referenced paths + test-cert pins consistent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
