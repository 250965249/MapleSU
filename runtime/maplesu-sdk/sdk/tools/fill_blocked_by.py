"""Fill `blockedBy` on partial records that have no source yet.

`gen_manifest.py` requires an explicit blocking reason when a member is
`partial` with an empty `sources` list.  The batches that produced those
records described the blocker in free text (`notes`, `recovery.unrecovered`)
but not in the machine-readable field, so the manifest gate rejects them.

This script derives `blockedBy` from the data that is already there:

* the first few unrecovered entry names (function level detail), and
* the package fragment path that holds the long form explanation.

It never invents a reason out of thin air: if a record has neither a
`recovery.unrecovered` entry nor a `blockedBy`, it is reported and left
alone so it stays visible as an authoring defect.

Idempotent; `--check` only reports.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
MANIFEST = SDK / "manifest"
WORK = SDK / "notes" / "work"


def short_name(entry: str) -> str:
    text = str(entry).strip()
    for sep in ("(IR", "（IR", "(", "（"):
        if sep in text:
            text = text.split(sep)[0]
    return text.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    filled = 0
    untouched = 0
    unresolved: list[str] = []

    for path in sorted(MANIFEST.glob("[0-9][0-9][0-9][0-9]_*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("status") != "partial":
            continue
        if data.get("sources"):
            continue
        if data.get("blockedBy"):
            untouched += 1
            continue

        unrecovered = (data.get("recovery") or {}).get("unrecovered") or []
        if not unrecovered:
            unresolved.append(path.name)
            continue

        names = [short_name(item) for item in unrecovered if short_name(item)]
        detail = "; ".join(names[:3])
        if len(names) > 3:
            detail += f"; ... (+{len(names) - 3})"
        data["blockedBy"] = [
            f"unrecovered functions: {detail}",
            "full reason and IR locations: notes/work/*/UNRECOVERED.fragment.md",
        ]
        rec = data.setdefault("recovery", {})
        need = int(rec.get("recovered") or 0) + len(unrecovered)
        if int(rec.get("functions") or 0) < need:
            rec["functions"] = need

        if not args.check:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        filled += 1

    print(f"filled blockedBy : {filled}")
    print(f"already had one  : {untouched}")
    print(f"unexplained      : {len(unresolved)}")
    for name in unresolved:
        print(f"  ! {name}")
    return 0 if not unresolved else 3


if __name__ == "__main__":
    raise SystemExit(main())
