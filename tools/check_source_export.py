#!/usr/bin/env python3
"""Check that git archive excludes private files; release eligibility is audited separately."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def check_export(root: Path, ref: str = "HEAD") -> dict:
    commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--verify", ref + "^{commit}"], text=True).strip()
    policy = json.loads(subprocess.check_output(
        ["git", "-C", str(root), "show", commit + ":release/source-policy.json"]))
    inputs = {}
    if policy.get("native_input_manifest"):
        manifest = json.loads(subprocess.check_output(
            ["git", "-C", str(root), "show", commit + ":" + policy["native_input_manifest"]]))
        inputs = {item["path"]: item for item in manifest["files"]}
    names = []
    errors = []
    with subprocess.Popen(["git", "-C", str(root), "archive", "--format=tar", commit],
                          stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                if member.isdir():
                    continue
                names.append(member.name)
                if member.name in inputs:
                    expected = inputs[member.name]
                    if not member.isfile() or member.size != expected["bytes"] or hashlib.file_digest(
                            archive.extractfile(member), "sha256").hexdigest() != expected["sha256"]:
                        errors.append(f"native build input differs in source archive: {member.name}")
        process.stdout.read()
        if process.wait():
            raise subprocess.CalledProcessError(process.returncode, process.args)
    prefixes = tuple(policy.get("excluded_prefixes", []))
    excluded = set(policy.get("excluded_files", []))
    errors.extend(f"excluded path in source archive: {name}" for name in names
                  if name.startswith(prefixes) or name in excluded or ".git" in Path(name).parts)
    selected = set(names)
    errors.extend(f"missing native build input in source archive: {name}"
                  for name in inputs if name not in selected)
    errors.extend(f"missing required file in source archive: {name}"
                  for name in policy.get("required_files", []) if name not in selected)
    return dict(source_commit=commit, files_checked=len(names), native_inputs_checked=len(inputs),
                errors=errors, passed=not errors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ref", default="HEAD", help="Committed revision to inspect")
    args = parser.parse_args()
    result = check_export(args.root.resolve(), args.ref)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
