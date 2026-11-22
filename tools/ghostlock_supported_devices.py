#!/usr/bin/env python3
"""Turn GhostLock-App's SUPPORTED_DEVICES_ZH.md table into the packaged asset.

The asset is the *only* source of truth for "does this exact `uname -r` appear in
the upstream Ghostlock support list". It is generated, never hand-edited:

    python tools/ghostlock_supported_devices.py \
        --source .tmp/ghostlock/upstream_SUPPORTED_DEVICES_ZH.md \
        --fetched-at 2026-10-31T09:44:13Z \
        --commit 437b3b257462e17d395cfd2cd8fb81536d6c6358 \
        --git-blob-sha 9075be61e43518f9bcec3e7d665637b205bc9655 \
        --out manager/src/main/assets/ghostlock/supported-devices.json

Provenance (source URL, fetch time, source sha256, upstream commit) is written
into the asset header so the APK carries the identity of the table it shipped
with. `--check` re-verifies a committed asset against a fresh copy of the source.

Parsing rules, both deliberate:
  * only the markdown table rows are read; prose is ignored, so the doc can grow
    new sections without silently changing the list;
  * a row is accepted only when the kernel cell is a single backticked token and
    the device cell is non-empty. Anything else is a hard error: a partially
    parsed support list would disable devices that upstream does support.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/YuKongA/ghostlock-app/main/"
    "docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md"
)
SOURCE_PAGE_URL = (
    "https://github.com/YuKongA/ghostlock-app/blob/main/"
    "docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md"
)
ASSET_PATH = "manager/src/main/assets/ghostlock/supported-devices.json"

# | `6.6.118-android15-8-g608a629fedf7-ab15154340-4k` | REDMI K90 Ultra |
ROW = re.compile(r"^\|\s*`(?P<release>[^`|]+)`\s*\|\s*(?P<device>[^|]*?)\s*\|\s*$")

# Upstream marks a few firmwares with a note after a middle dot, e.g.
# "MEIZU 20 Pro · 推荐Shizuku". The device name never contains "·".
NOTE_SEPARATOR = "·"


class ParseError(SystemExit):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse(markdown: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen: dict[str, dict[str, str]] = {}
    for number, line in enumerate(markdown.splitlines(), start=1):
        if not line.lstrip().startswith("|"):
            continue
        # Skip the header row and the alignment row; both fail the release token
        # rule, but skipping them explicitly keeps the error messages meaningful.
        match = ROW.match(line.strip())
        if match is None:
            if "`" in line and "|" in line:
                raise ParseError(
                    f"{number}: table row is not a kernel/device pair: {line!r}"
                )
            continue
        release = match.group("release").strip()
        raw_device = collapse(match.group("device"))
        if not raw_device:
            raise ParseError(f"{number}: empty device cell for {release}")
        device, note = raw_device, ""
        if NOTE_SEPARATOR in raw_device:
            head, _, tail = raw_device.rpartition(NOTE_SEPARATOR)
            device, note = collapse(head), collapse(tail)
        if not device:
            raise ParseError(f"{number}: note-only device cell for {release}")
        entry = {"unameRelease": release, "device": device, "note": note}
        if release in seen:
            # The upstream table lists one kernel twice; both rows describe the
            # same firmware. A conflicting duplicate would make matching
            # ambiguous, so that is an error rather than a silent pick.
            if seen[release] != entry:
                raise ParseError(
                    f"{number}: conflicting duplicate for {release}: "
                    f"{seen[release]} vs {entry}"
                )
        else:
            seen[release] = entry
        entries.append(entry)
    if not entries:
        raise ParseError("no kernel/device rows parsed; refusing to emit an empty list")
    return entries


def build_asset(
    entries: list[dict[str, str]],
    *,
    source_sha256: str,
    source_bytes: int,
    fetched_at: str,
    commit: str,
    git_blob_sha: str,
) -> dict:
    unique = {entry["unameRelease"] for entry in entries}
    # Header first: a reader that only looks at the head still sees where the
    # list came from and what it hashed to.
    return {
        "sourceUrl": SOURCE_URL,
        "sourcePageUrl": SOURCE_PAGE_URL,
        "sourceCommit": commit,
        "sourceGitBlobSha": git_blob_sha,
        "sourceSha256": source_sha256,
        "sourceBytes": source_bytes,
        "fetchedAt": fetched_at,
        "fetchedVia": (
            "GitHub REST contents API "
            "(https://api.github.com/repos/YuKongA/ghostlock-app/contents/"
            "docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md?ref=main); "
            "raw.githubusercontent.com was reset in this environment"
        ),
        "matchPolicy": (
            "exact equality against the complete uname -r string; no prefix, "
            "suffix, case-insensitive or fuzzy matching; a missing, truncated or "
            "unparseable list fails closed (every release UNSUPPORTED)"
        ),
        "entryCount": len(entries),
        "uniqueReleaseCount": len(unique),
        "generator": "tools/ghostlock_supported_devices.py",
        "devices": entries,
    }


def render(asset: dict) -> str:
    return json.dumps(asset, ensure_ascii=False, indent=2) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="the downloaded SUPPORTED_DEVICES_ZH.md")
    parser.add_argument("--out", type=Path, default=Path(ASSET_PATH))
    parser.add_argument("--fetched-at", required=True,
                        help="ISO-8601 UTC instant the source document was fetched")
    parser.add_argument("--commit", required=True, help="upstream commit of main")
    parser.add_argument("--git-blob-sha", required=True,
                        help="git blob sha of the source document")
    parser.add_argument("--check", action="store_true",
                        help="compare with the committed asset instead of writing")
    args = parser.parse_args(argv)

    raw = args.source.read_bytes()
    digest = sha256_bytes(raw)
    entries = parse(raw.decode("utf-8"))
    asset = build_asset(
        entries,
        source_sha256=digest,
        source_bytes=len(raw),
        fetched_at=args.fetched_at,
        commit=args.commit,
        git_blob_sha=args.git_blob_sha,
    )
    text = render(asset)

    if args.check:
        if not args.out.exists():
            print(f"missing asset: {args.out}", file=sys.stderr)
            return 1
        current = args.out.read_text(encoding="utf-8")
        if current != text:
            print(f"asset is stale: {args.out} (source sha256 {digest})", file=sys.stderr)
            return 1
        print(f"ok: {args.out} matches {args.source} ({len(entries)} rows, sha256 {digest})")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8", newline="\n")
    asset_digest = sha256_bytes(text.encode("utf-8"))
    print(f"wrote {args.out}")
    print(f"  rows            : {len(entries)} ({asset['uniqueReleaseCount']} distinct releases)")
    print(f"  source sha256   : {digest} ({len(raw)} bytes)")
    print(f"  asset sha256    : {asset_digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
