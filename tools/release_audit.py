#!/usr/bin/env python3
"""Audit actual Git candidates or an exported tree; never modify or publish files."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
BINARY_SUFFIXES = {".apk", ".aab", ".so", ".a", ".o", ".ko", ".exe", ".dll", ".jar", ".zip",
                   ".7z", ".img", ".bin", ".dex", ".bc", ".class", ".i64", ".idb"}
KEY_SUFFIXES = {".key", ".pem", ".jks", ".keystore", ".p12", ".pfx", ".keybox"}
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----(?:\r?\n|\\n)[A-Za-z0-9+/=\r\n\\]{100,}")
TOKEN = re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{70,})\b")
LINK = re.compile(r"!?\[[^\]\n]*\]\(<?([^\s)>]+)>?(?:\s+[^)]*)?\)")


def git_candidates(root: Path) -> list[str]:
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "--cached", "--others",
                                   "--exclude-standard", "-z"])
    names = {p.decode("utf-8") for p in raw.split(b"\0") if p}
    for name in list(names):
        directory = root / name
        if not directory.is_dir():
            continue
        names.remove(name)
        for child in git_candidates(directory):
            names.add((directory / child).relative_to(root).as_posix())
    return sorted(names)


def native_inputs(root: Path, policy: dict) -> list[dict]:
    name = policy.get("native_input_manifest")
    if not name:
        return []
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Native input manifest leaves candidate tree")
    return json.loads(path.read_text(encoding="utf-8"))["files"]


def audit_files(root: Path, relatives: list[str], policy: dict) -> list[str]:
    root = root.resolve()
    errors = []
    selected = set(relatives)
    inputs = native_inputs(root, policy)
    allowed = policy.get("allowed_binaries", {}) | policy.get("public_test_keys", {})
    allowed |= {item["path"]: item["sha256"] for item in inputs}
    for item in inputs:
        name = item["path"]
        path = root / name
        if name not in selected:
            errors.append(f"missing native build input: {name}")
        elif not path.is_file() or path.stat().st_size != item["bytes"]:
            errors.append(f"native build input size changed: {name}")
    for name in relatives:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
            errors.append(f"missing file or path outside candidate tree: {name}")
            continue
        parts = Path(name).parts
        if name in policy.get("excluded_files", []) or any(name.startswith(prefix) for prefix in policy.get("excluded_prefixes", [])) or any(
                p in {"build", "__pycache__", ".gradle", ".private", "node_modules"} for p in parts):
            errors.append(f"excluded/internal path: {name}")
        data = path.read_bytes()
        if name in allowed:
            if hashlib.sha256(data).hexdigest() != allowed[name]:
                errors.append(f"pinned public fixture digest changed: {name}")
            continue
        if path.suffix.lower() in KEY_SUFFIXES or path.name in {".env", "keybox.xml", "local.properties"}:
            errors.append(f"local configuration or credential path: {name}")
        if path.suffix.lower() in BINARY_SUFFIXES or data[:4] in {b"\x7fELF", b"!<ar"} or data[:2] == b"MZ":
            errors.append(f"unreviewed binary/artifact: {name}")
        if PRIVATE_KEY.search(data) or TOKEN.search(data):
            errors.append(f"credential content: {name}")
        # Check maintained entry docs; vendored upstream documents retain their original links.
        if path.suffix.lower() == ".md" and (len(parts) == 1 or parts[0] == "docs" and len(parts) <= 3):
            for match in LINK.finditer(data.decode("utf-8-sig")):
                url = urlsplit(match.group(1))
                if url.scheme or url.netloc or not url.path:
                    continue
                target = (path.parent / unquote(url.path)).resolve()
                if not target.is_relative_to(root):
                    errors.append(f"documentation link leaves candidate: {name}: {match.group(1)}")
                    continue
                relative = target.relative_to(root).as_posix()
                if relative not in selected and not any(p.startswith(relative + "/") for p in selected):
                    errors.append(f"missing candidate document target: {name}: {match.group(1)}")
    errors.extend(f"missing required file: {p}" for p in policy.get("required_files", []) if p not in selected)
    return errors


def audit(root: Path, relatives: list[str], strict: bool) -> dict:
    policy = json.loads((root / "release/source-policy.json").read_text(encoding="utf-8"))
    errors = audit_files(root, relatives, policy)
    blockers = [b for b in policy["release_blockers"] if b.get("resolved") is not True]
    return dict(files_checked=len(relatives), errors=errors, release_blockers=blockers,
                strict=strict, passed=not errors and (not strict or not blockers))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--all", action="store_true", help="Inspect an exported tree without Git")
    parser.add_argument("--strict", action="store_true", help="Require all release blockers to be resolved")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    names = sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                   if p.is_file() and ".git" not in p.relative_to(root).parts) if args.all else git_candidates(root)
    result = audit(root, names, args.strict)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
