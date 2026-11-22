"""Gate: the device-class support matrix must agree with the code and the artifacts.

"Supports all models" is only a claim until something checks it. Three sources have
to agree, and each fails differently in the field:

  1. the admission table in `DirtyfragAttempt.exactKmi()`  - a KMI missing here is
     refused on the device with `DIRTYFRAG_EXACT_KMI_UNSUPPORTED`, before anything runs;
  2. `jailbreak-providers/contracts/kmi-matrix.json`       - what each target still
     needs for that KMI (Ultra contract, Normal ko + embedding);
  3. the artifacts on disk                                  - a contract file that does
     not exist, or a ko that is not where the build expects it.

A row may honestly say `supported: false`; what must never happen is a row that says
supported while its artifact is absent, or a KMI the code admits but the matrix does
not describe.

Usage: python tools/check_kmi_matrix.py [--require]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "jailbreak-providers/contracts/kmi-matrix.json"
ADMISSION = ROOT / ("jailbreak-providers/android/src/main/java/dev/maplesu/manager/"
                    "jailbreak/DirtyfragAttempt.java")
BUILDER = ROOT / "jailbreak-providers/build.py"

# The product claim: 5.10 through 6.18. Anything outside this list is out of scope
# until the claim changes; anything missing from it is a regression.
REQUIRED_KMIS = {
    "android12-5.10", "android13-5.10", "android13-5.15", "android14-5.15",
    "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18",
}


def admission_kmis() -> set[str]:
    text = ADMISSION.read_text(encoding="utf-8")
    block = text[text.index("String[][] table"):]
    block = block[:block.index("};")]
    return set(re.findall(r'"(android\d+-\d+\.\d+)"', block))


def builder_kmis() -> set[str]:
    """The KMI table inside build.py, which decides which family a module is built for."""
    text = BUILDER.read_text(encoding="utf-8")
    start = text.index("KMI_TABLE = (")
    block = text[start:text.index(")", text.index("android17-6.18", start))]
    return set(re.findall(r'"(android\d+-\d+\.\d+)"', block))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require", action="store_true",
                        help="treat any unsupported row as a failure (release gate)")
    args = parser.parse_args()

    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    rows = {row["kmi"]: row for row in matrix["kmis"]}
    admitted = admission_kmis()

    problems: list[str] = []
    pending: list[str] = []

    # 1. the required 5.10..6.18 set, and all three tables agreeing on it
    built = builder_kmis()
    for kmi in sorted(REQUIRED_KMIS - set(rows)):
        problems.append("required KMI missing from the matrix: " + kmi)
    for kmi in sorted(set(rows) - REQUIRED_KMIS):
        problems.append("matrix describes a KMI outside the 5.10..6.18 claim: " + kmi)
    for kmi in sorted(admitted - set(rows)):
        problems.append("admitted by code but absent from the matrix: " + kmi)
    for kmi in sorted(set(rows) - admitted):
        problems.append("described in the matrix but the code refuses it: " + kmi)
    for kmi in sorted(built - set(rows)):
        problems.append("build.py knows a KMI the matrix does not: " + kmi)
    for kmi in sorted(set(rows) - built):
        problems.append("matrix lists a KMI build.py cannot target: " + kmi)

    # 2. a supported target must have its artifact
    for kmi, row in sorted(rows.items()):
        ultra = row.get("ultra", {})
        if ultra.get("supported"):
            contract = ultra.get("contract")
            if not contract or not (ROOT / contract).is_file():
                problems.append("%s: ultra claims support without a contract file" % kmi)
            module = ultra.get("module")
            if not module or not (ROOT / module).is_file():
                problems.append("%s: ultra claims support without a built module" % kmi)
        else:
            pending.append("%s: ultra - %s" % (kmi, ultra.get("needs", "not implemented")))

        normal = row.get("normal", {})
        if normal.get("supported"):
            ko = normal.get("ko")
            if not ko or not (ROOT / ko).is_file():
                problems.append("%s: normal claims support without its ko" % kmi)
            if not normal.get("embedded"):
                problems.append("%s: normal claims support but ksud does not embed the ko" % kmi)
        else:
            pending.append("%s: normal - %s" % (kmi, normal.get("needs", "not implemented")))

        if not row.get("exploit", {}).get("supported"):
            pending.append("%s: exploit - %s" % (kmi, row["exploit"].get("reason", "unproven")))

    for item in problems:
        print("FAIL " + item)
    shown = pending if args.require else pending[:12]
    for item in shown:
        print("PENDING " + item)
    if len(pending) > len(shown):
        print("PENDING ... and %d more" % (len(pending) - len(shown)))

    supported = [kmi for kmi, row in rows.items()
                 if row.get("ultra", {}).get("supported") and row.get("normal", {}).get("supported")]
    print("KMIs with both targets ready: %s" % (", ".join(sorted(supported)) or "none"))
    if problems:
        print("RESULT: matrix is inconsistent")
        return 1
    if args.require and pending:
        print("RESULT: %d pending capabilities (release gate)" % len(pending))
        return 1
    print("RESULT: matrix is consistent (%d KMIs admitted, %d pending capabilities)"
          % (len(rows), len(pending)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
