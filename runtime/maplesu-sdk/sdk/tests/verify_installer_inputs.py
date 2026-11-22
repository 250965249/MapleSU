#!/usr/bin/env python3
"""Compile only the four installers and verify their actual embedded payload bytes.

Run build.py --payloads [--source-payloads] with the same isolated --build-dir first.
This produces installer-inputs.a, never a complete delivery SDK.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK / "tools"))
import extract_payloads as EP

spec = importlib.util.spec_from_file_location("sdk_installer_input_check", SDK / "build.py")
B = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = B
spec.loader.exec_module(B)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--source-payloads", action="store_true")
    options = parser.parse_args()
    root = Path(options.build_dir).resolve()
    if B.main(["--report", "--build-dir", str(root)]) != 0:
        return 1
    B.SOURCE_PAYLOADS = options.source_payloads
    manifest = json.loads((B.ASSETS_OUT / "PAYLOADS.json").read_text(encoding="utf-8"))
    mode = "source-programs-reference-bootstrap" if options.source_payloads else "reference"
    if manifest.get("input_mode") != mode:
        raise ValueError("payload stage mode differs from requested installer validation")
    args = B.parse_args(["--compile", "--compose", "--pack", "--allow-partial", "--jobs", "2"])
    tc = B.S.resolve_toolchain(None)
    entries, _metadata = B.load_manifest(B.MANIFEST_PATH, True)
    names = {row[-1] for row in B.PH.TABLE}
    entries = [entry for entry in entries if entry.name in names]
    if len(entries) != 4:
        raise ValueError("expected exactly four installer members")
    report = {"scope": "four-installer-members-only-not-delivery-candidate", "mode": mode}
    B.ensure_payload_headers(args)
    B.prepare_payload_sources(entries, report)
    B.stage_compile(entries, tc, args, report, B.VendorRules.load(B.VENDOR_RULES_PATH))
    B.stage_compose(entries, tc, args, report, B.S.find_freeze(None))
    B.ARCHIVE_OUT = B.OUT_DIR / "installer-inputs.a"
    B.stage_pack(entries, tc, args, report)
    extracted = B.OUT_DIR / "installer-inputs-extracted"
    result = EP.main(["--archive", str(B.ARCHIVE_OUT), "--out", str(extracted),
                      "--expected-assets", str(B.ASSETS_OUT), "--emit", "--quiet"])
    report["embedded"] = json.loads((extracted / "payloads.json").read_text(encoding="utf-8"))
    report["public_symbols"] = {
        entry.name: sorted(B.S.nm_defined_only(tc, entry.object_path).defined)
        for entry in entries}
    report["exit_code"] = result
    path = B.REPORT_DIR / "installer-input-validation.json"
    B.S.write_json(path, report)
    print(f"installer validation mode={mode} exit={result} -> {path}")
    return result


if __name__ == "__main__":
    sys.exit(main())
