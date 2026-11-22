"""Host-side smoke test for the root-canary packaging path.

This is not a product test: it exercises `build.py --root-canary`'s builder
function in isolation (no provider build, no APK), so the canary artifacts and
their recorded identities can be checked in seconds while the packaging edge is
being changed. `docs/patching/maplesu-canary-packaging-2026-10-29.md` records the
step-2 full-run evidence; `docs/patching/maplesu-step3-implementation-2026-10-29.md`
records the step-3 semantic change asserted here.

Step-3 semantics (design §3.4): the canary slot delivers the hook module, the module
execs `<CE>/bs` (the App-staged bootstrap) with `--umh --entry-enforcing <saved>`, and
**no separate canary helper asset** is packaged. So the helper record is expected to
be absent, and its absence must not fail packaging - the opposite of step-2.

Usage:
    python jailbreak-providers/root-loader/canary/test_canary_packaging.py [--output DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROVIDERS = HERE.parents[1]
PROJECT_ROOT = PROVIDERS.parent
sys.path.insert(0, str(PROVIDERS))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))
import native_toolchain  # noqa: E402

import build as provider_build  # noqa: E402  (path setup must run first)

DEFAULT_NDK = native_toolchain.provider_ndk()
EXPECTED_HELPER_PATH = "/data/user/0/dev.maplesu.manager/bs"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(PROJECT_ROOT / "work/canary-packaging-test"))
    parser.add_argument("--ndk-dir", default=None)
    args = parser.parse_args(argv)

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    ndk = Path(args.ndk_dir) if args.ndk_dir else DEFAULT_NDK

    report: dict = {}
    code = provider_build.build_root_canary(output, ndk, report)
    ir = report.get("ir", {})
    root = ir.get("rootCanary", {})
    failures: list[str] = []
    if code != 0:
        failures.append("build_root_canary returned %s: %s" % (code, ir.get("error")))

    # Every identity the packaging edge will hand to package.py must still describe
    # the bytes on disk. The helper is deliberately absent from step-3 on.
    entries = {
        "canary module": (ir.get("canary") or {}).get("path"),
        "stub": (ir.get("build") or {}).get("module"),
    }
    expected = {
        "canary module": (ir.get("canary") or {}).get("sha256"),
        "stub": (ir.get("build") or {}).get("sha256"),
    }
    for label, raw_path in entries.items():
        if not raw_path:
            failures.append("missing %s record" % label)
            continue
        path = Path(raw_path)
        if not path.is_file():
            failures.append("%s missing on disk: %s" % (label, path))
        elif sha256(path) != expected[label]:
            failures.append("%s digest drift: %s" % (label, path))

    if (ir.get("build") or {}).get("facts", {}).get("stub") is not True:
        failures.append("product IR slot is not marked as a stub")
    stub_path = entries["stub"]
    if stub_path and Path(stub_path).is_file():
        if Path(stub_path).read_bytes()[:4] == b"\x7fELF":
            failures.append("IR stub is an ELF image; install_ir() could load it")
    if not ir.get("specs"):
        failures.append("no per-release specs packaged")

    # Step-3: the module in the canary slot IS the hook module, and the handover target
    # is the CE `bs` the App stages. A divergence here is exactly the device-only bug
    # this test exists to catch on the host.
    module_record = (root.get("module") or {})
    if module_record.get("helperPath") != EXPECTED_HELPER_PATH:
        failures.append("hook module dispatch path is %r, expected %r"
                        % (module_record.get("helperPath"), EXPECTED_HELPER_PATH))
    if module_record.get("handoverMode") != "setup-exec":
        failures.append("hook module does not report the two-stage handover")
    if module_record.get("helperPathSource") != "contract":
        failures.append("hook module helper path did not come from the contract")
    if not (module_record.get("umhArgvStorage") or {}):
        failures.append("hook module records no UMH argv storage (R1)")
    if root.get("helperPath") != provider_build.ROOT_CANARY_HELPER_PATH:
        failures.append("packaging helper path constant drifted from the module")
    if provider_build.ROOT_CANARY_HELPER_PATH != EXPECTED_HELPER_PATH:
        failures.append("ROOT_CANARY_HELPER_PATH is not the CE bs path")

    # Step-3: no helper asset any more; a reintroduced one would be a silent second
    # helper track (HANDOVER §5.4 gap 2).
    if root.get("helper") is not None:
        failures.append("step-3 packaging still ships a canary helper asset")
    if root.get("helperAsset") is not None:
        failures.append("step-3 packaging records a canary helper asset")
    if not any("step-3 semantics" in note for note in root.get("notes", [])):
        failures.append("the packaging record does not state the step-3 semantics")

    # A step-2 frozen set must remain describable: a report that still carries a helper
    # (with a device path) is packaged the old way rather than refused. The packaging
    # function itself is exercised for that shape by the record check above; here we
    # only assert the builder no longer produces that shape.
    if root.get("helper") == {}:
        failures.append("empty helper record; use null for 'no helper'")

    for warning in root.get("warnings", []):
        print("warning: " + warning)

    print(json.dumps({
        "exitCode": code,
        "mode": ir.get("mode"),
        "module": ir.get("canary"),
        "stub": ir.get("build"),
        "helper": root.get("helper"),
        "helperPath": root.get("helperPath"),
        "specs": [spec["release"] for spec in ir.get("specs", [])],
        "warnings": root.get("warnings", []),
        "failures": failures,
    }, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
