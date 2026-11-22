"""Normalize sdk/manifest/*.json to the canonical frozen-archive identity.

Why this exists
---------------
Parallel work packages write one metadata file per archive member. Agents cannot
be trusted to number members by hand: the canonical index is the 0-based
position in `llvm-ar t` of the frozen archive, and it is easy to be off by one.
So the *name* plus the *original sha256* are treated as the identity, and the
index is derived from the census, never from the file contents or file name.

Canonical outputs
-----------------
  file name : <idx:04d>_<full member name>.json   e.g. 0036_module_base_linux_version.o.json
  idx field : 0-based frozen-archive position

Rules
-----
* `patch_base.o` appears three times with different bytes; those rows are
  disambiguated by `original.sha256`, never by name alone.
* A file whose `name` is not an archive member (e.g. `helper.json`) is left
  untouched and reported as `unmatched`.
* A mismatch between the declared `original` bytes/sha and the census row is a
  hard conflict: the metadata claims to describe bytes that are not in the
  snapshot.

Exit codes: 0 ok, 3 identity conflict, 1 internal error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
CENSUS = SDK / "notes" / "recon" / "ARCHIVE-CENSUS.json"
MANIFEST_DIR = SDK / "manifest"


def load_census() -> list[dict]:
    data = json.loads(CENSUS.read_text(encoding="utf-8"))
    members = data["members"] if isinstance(data, dict) else data
    if not isinstance(members, list) or len(members) != 258:
        raise SystemExit(f"census is not a 258-row list: {type(members)} {len(members)}")
    return members


def canonical_name(member: dict) -> str:
    return f"{member['idx']:04d}_{member['name']}.json"


def resolve(members: list[dict], name: str, sha: str) -> tuple[dict | None, str]:
    candidates = [m for m in members if m["name"] == name]
    if not candidates:
        return None, "not-a-member"
    if len(candidates) == 1:
        return candidates[0], "by-name"
    if sha:
        by_sha = [m for m in candidates if m["sha256"].lower() == sha.lower()]
        if len(by_sha) == 1:
            return by_sha[0], "by-name+sha"
        return None, f"ambiguous-name-sha({len(by_sha)}/{len(candidates)})"
    return None, f"ambiguous-name({len(candidates)})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest-dir", default=str(MANIFEST_DIR))
    ap.add_argument("--check", action="store_true", help="report only, never rewrite")
    args = ap.parse_args()

    mdir = Path(args.manifest_dir)
    if not mdir.is_dir():
        print(f"no manifest dir: {mdir}", file=sys.stderr)
        return 3

    members = load_census()
    by_target: dict[str, Path] = {}
    problems: list[str] = []
    rows: list[tuple[str, str, str, str, str]] = []

    for path in sorted(mdir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{path.name}: unreadable json ({exc})")
            continue
        if not isinstance(data, dict) or "name" not in data:
            problems.append(f"{path.name}: no 'name' field (left untouched)")
            continue
        name = str(data["name"])
        orig = data.get("original") or {}
        sha = str(orig.get("sha256") or "")
        member, how = resolve(members, name, sha)

        if member is None:
            if how == "not-a-member":
                rows.append((path.name, name, str(data.get("idx")), "-", "unmatched (not an archive member)"))
                continue
            problems.append(f"{path.name}: cannot resolve {name} ({how})")
            continue

        if sha and member["sha256"].lower() != sha.lower():
            problems.append(
                f"{path.name}: original.sha256 {sha[:16]} != census {member['sha256'][:16]} for {name}"
            )
            continue

        declared = data.get("idx")
        data["idx"] = member["idx"]
        data["name"] = member["name"]
        data.setdefault("original", {})
        data["original"]["sha256"] = member["sha256"]
        data["original"]["bytes"] = member["bytes"]

        target = mdir / canonical_name(member)
        if target in by_target and by_target[target] != path:
            problems.append(f"two files map to {target.name}: {by_target[target].name} and {path.name}")
            continue
        by_target[target] = path

        action = "ok"
        if target != path:
            action = "rename"
        elif declared != member["idx"]:
            action = "idx-field-fixed"
        rows.append((path.name, member["name"], str(declared), str(member["idx"]), f"{action} ({how})"))

        if args.check:
            continue
        if target != path:
            if target.exists():
                problems.append(f"refusing to overwrite existing {target.name} with {path.name}")
                continue
            path.unlink()
            target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        else:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    width = max((len(r[1]) for r in rows), default=10)
    print(f"{'file':44s} {'member':{width}s} {'old':>4s} {'new':>4s}  result")
    for r in rows:
        print(f"{r[0]:44s} {r[1]:{width}s} {r[2]:>4s} {r[3]:>4s}  {r[4]}")

    print()
    print(f"members in census : {len(members)}")
    print(f"metadata files    : {len(rows)}")
    print(f"problems          : {len(problems)}")
    for p in problems:
        print(f"  ! {p}")

    if problems:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
