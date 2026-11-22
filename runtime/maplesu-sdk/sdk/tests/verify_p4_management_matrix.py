#!/usr/bin/env python3
"""Validate the six-target P4 object receipt and its actual object files."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


TARGETS = (
    "android12-5.10",
    "android13-5.15",
    "android14-6.1",
    "android15-6.6",
    "android16-6.12",
    "android17-6.18",
)
EXPECTED_OBJECTS = {
    "manager_management.o",
    "manager_task_state.o",
    "manager_credential_domain.o",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path, help="path to the six-target MATRIX.json")
    parser.add_argument("--out", type=Path, help="write the verification result as JSON")
    parser.add_argument("--repo-root", type=Path, help="repository used for the matrix input snapshot")
    args = parser.parse_args()
    receipt_path = args.receipt.resolve()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    rows = receipt.get("results", [])
    results = {item["target"]: item for item in rows}
    errors: list[str] = []
    if len(rows) != len(TARGETS) or set(results) != set(TARGETS):
        errors.append(f"target set mismatch: {sorted(results)}")

    source = Path(receipt["source"])
    root = args.repo_root.resolve() if args.repo_root else source.resolve().parents[4]
    if not source.is_file() or sha256(source) != receipt.get("sourceSha256"):
        errors.append("current source is missing or differs from the receipt SHA-256")
    if receipt.get("inputsUnchanged") is False:
        errors.append("matrix build inputs changed during compilation")
    inputs = receipt.get("selectedInputs", [])
    for entry in inputs:
        selected = root / entry["path"]
        snapshot = receipt_path.parent / "inputs" / entry["snapshot"]
        if not selected.is_file() or sha256(selected) != entry["sha256"]:
            errors.append("current selected input differs: " + entry["path"])
        if not snapshot.is_file() or sha256(snapshot) != entry["sha256"]:
            errors.append("input snapshot differs: " + entry["snapshot"])

    checked = []
    for target in TARGETS:
        result = results.get(target)
        if result is None:
            continue
        if result.get("exitCode") != 0:
            errors.append(f"{target}: build exit code is not zero")
        if result.get("sourceSha256") != receipt.get("sourceSha256"):
            errors.append(f"{target}: source SHA-256 differs from matrix source")
        if result.get("missingArtifacts"):
            errors.append(f"{target}: receipt declares missing artifacts")
        artifacts = result.get("artifacts") or []
        names = {item.get("path") for item in artifacts}
        if len(artifacts) != len(EXPECTED_OBJECTS) or names != EXPECTED_OBJECTS:
            errors.append(f"{target}: object set mismatch: {sorted(names)}")
            continue
        for entry in inputs:
            compiled = receipt_path.parent / target / entry["snapshot"]
            if not compiled.is_file() or sha256(compiled) != entry["sha256"]:
                errors.append(f"{target}: compiled input differs: {entry['snapshot']}")
        for artifact in artifacts:
            object_path = receipt_path.parent / target / artifact["path"]
            if not object_path.is_file():
                errors.append(f"{target}: missing {artifact['path']}")
                continue
            actual_bytes = object_path.stat().st_size
            actual_sha = sha256(object_path)
            if not actual_bytes:
                errors.append(f"{target}: {artifact['path']} is empty")
            if actual_bytes != artifact.get("bytes"):
                errors.append(f"{target}: {artifact['path']} size differs from receipt")
            if actual_sha != artifact.get("sha256"):
                errors.append(f"{target}: {artifact['path']} SHA-256 differs from receipt")
            checked.append({
                "target": target,
                "path": artifact["path"],
                "bytes": actual_bytes,
                "sha256": actual_sha,
            })

    if receipt.get("complete") is not True:
        errors.append("matrix receipt does not mark all builds complete")
    report = {
        "passed": not errors,
        "matrix": str(receipt_path),
        "source": str(source),
        "sourceSha256": receipt.get("sourceSha256"),
        "targets": list(TARGETS),
        "objects": checked,
        "errors": errors,
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
