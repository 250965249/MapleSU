#!/usr/bin/env python3
"""Run the real public seccomp getter using the existing SDK layout fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from run import CASES as LAYOUT_CASES

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
CASES = ["seccomp-btf-nested", "seccomp-btf-zero", "seccomp-btf-width",
         "seccomp-btf-damaged", "seccomp-btf-missing", "seccomp-accessor-real-510",
         "seccomp-accessor-real-66", "seccomp-accessor-zero", "seccomp-accessor-ldr", "seccomp-accessor-mov-w",
         "seccomp-accessor-wide", "seccomp-accessor-indirect", "seccomp-accessor-conflict",
         "seccomp-accessor-missing", "seccomp-accessor-read-error", "seccomp-accessor-size-error",
         "seccomp-accessor-truncated", "seccomp-accessor-unknown-return",
         "accessor-overflow-interrupted", "accessor-overflow-preserve-hint",
         "accessor-overflow-preserve-mov", "accessor-overflow-preserve-ldr",
         "accessor-overflow-preserve-branch", "accessor-overflow-clobber-adds",
         "accessor-overflow-clobber-ands"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--regression", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    cases = list(dict.fromkeys([*CASES, *LAYOUT_CASES])) if args.regression else CASES
    command = [sys.executable, str(HERE / "run.py"), "--out", str(out), "--case", cases[0]]
    if args.sanitize:
        command.append("--sanitize")
    done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    receipt = json.loads((out / "receipt.json").read_text())
    if receipt["commands"][0]["exit"]:
        print(done.stdout + done.stderr)
        raise SystemExit(done.returncode)
    rows = receipt["commands"]
    base = rows[1]["argv"][:-1]
    for case in cases[1:]:
        argv = [*base, case]
        result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace")
        (out / (case + ".log")).write_text(result.stdout + result.stderr, encoding="utf-8")
        rows.append({"name": case, "argv": argv, "exit": result.returncode})
    receipt["commands"] = rows
    receipt["passed"] = all(row["exit"] == 0 for row in rows)
    for path in (Path(__file__), HERE / "fixtures/seccomp-real.h", HERE / "fixtures/seccomp-real.json"):
        receipt["sources"].append({"path": str(path.resolve().relative_to(ROOT)),
                                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    for row in rows:
        print(f'{row["name"]}: {row["exit"]}')
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
