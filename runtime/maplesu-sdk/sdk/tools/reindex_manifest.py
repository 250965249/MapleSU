"""Re-align every member record with a new fixed archive census.

The build input moved from a 258-member archive to a fixed 260-member archive.
Member order changed, two members were added and thirteen members were rebuilt
(their bytes differ).  The manifests carry the member index in the file name and
in the `idx` field, plus the reference hash in `original`, so all three must be
recomputed from the new census.

Matching rules:
* unique member name -> matched by name;
* duplicated member names (`patch_base.o` appears three times) -> matched by the
  recorded reference sha256 first, then by order of appearance.
* a matched member whose bytes changed keeps its source but gets the new
  reference hash and is re-opened as `partial` until the source is updated;
* a member present in the census without a record gets a stub record with an
  empty source list and a blocker, so the build reports it as pending instead of
  silently skipping it.

Usage:
    py tools/reindex_manifest.py --census notes/ARCHIVE-CENSUS-260.json [--check]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
MANIFEST = SDK / "manifest"


def load_records() -> list[tuple[Path, dict]]:
    out = []
    for path in sorted(MANIFEST.glob("[0-9][0-9][0-9][0-9]_*.json")):
        out.append((path, json.loads(path.read_text(encoding="utf-8"))))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    census = json.loads((SDK / args.census).read_text(encoding="utf-8"))
    rows: list[dict] = census["members"]

    records = load_records()
    by_name: dict[str, list[tuple[Path, dict]]] = {}
    for path, rec in records:
        by_name.setdefault(rec.get("name", ""), []).append((path, rec))

    used: set[int] = set()
    plan: list[tuple[dict, Path | None, dict | None]] = []

    # pass 1: duplicated names by hash, unique names by name
    for row in rows:
        name = row["name"]
        candidates = by_name.get(name, [])
        if not candidates:
            plan.append((row, None, None))
            continue
        if len(candidates) == 1:
            path, rec = candidates[0]
            used.add(id(rec))
            plan.append((row, path, rec))
            continue
        picked = None
        for path, rec in candidates:
            if id(rec) in used:
                continue
            if str((rec.get("original") or {}).get("sha256", "")) == row["sha256"]:
                picked = (path, rec)
                break
        if picked is None:
            picked = next(((p, r) for p, r in candidates if id(r) not in used), None)
        if picked:
            used.add(id(picked[1]))
        plan.append((row, picked[0] if picked else None, picked[1] if picked else None))

    renamed = 0
    updated = 0
    added = 0
    changed = 0
    for row, path, rec in plan:
        target = MANIFEST / f"{row['idx']:04d}_{row['name']}.json"
        if rec is None:
            data = {
                "idx": row["idx"], "name": row["name"], "group": "core",
                "layout": "elf" if row["layout"] == "native-elf" else "bitcode",
                "kind": "SINGLE", "sources": [], "flagsProfile":
                    "core-oz-elf-fexceptions" if row["layout"] == "native-elf" else "core-oz-bitcode-fexceptions",
                "extraFlags": ["-D_FORTIFY_SOURCE=2"],
                "status": "partial",
                "recovery": {"functions": 1, "recovered": 0,
                             "unrecovered": ["not yet implemented: source for this member is pending"]},
                "original": {"sha256": row["sha256"], "bytes": row["bytes"]},
                "blockedBy": ["source not recovered yet"],
                "notes": "",
            }
            added += 1
        else:
            data = rec
            old_sha = str((data.get("original") or {}).get("sha256", ""))
            data["idx"] = row["idx"]
            data["name"] = row["name"]
            data["original"] = {"sha256": row["sha256"], "bytes": row["bytes"]}
            data["layout"] = "elf" if row["layout"] == "native-elf" else "bitcode"
            if old_sha and old_sha != row["sha256"]:
                changed += 1
                data["status"] = "partial"
                rec_ = data.setdefault("recovery", {})
                items = [str(i) for i in (rec_.get("unrecovered") or []) if "reference build changed" not in str(i)]
                items.append("not yet implemented: source must be updated for the new reference build")
                rec_["unrecovered"] = items
                data["blockedBy"] = []
        if not args.check:
            if path is not None and path != target and path.exists():
                path.unlink()
            target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        renamed += 1
        updated += 1

    print(f"census members        : {len(rows)}")
    print(f"records written       : {updated}")
    print(f"added (no record)     : {added}")
    print(f"changed reference     : {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
