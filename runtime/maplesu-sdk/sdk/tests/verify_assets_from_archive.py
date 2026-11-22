#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_assets_from_archive.py -- prove sdk/assets/*.bin are the frozen bytes.

Acceptance gate for R-PROGRAMS ("从归档成员读出的数据 sha256 与 ASSETS.json 一致"):

For every asset listed in ``sdk/assets/ASSETS.json`` this tool

  1. opens the **frozen** archive recorded in ASSETS.json (never the production
     ``lib/`` copy, never the network),
  2. finds the member by name and checks its size and sha256 against the values
     recorded in ASSETS.json,
  3. reads the payload symbol out of the member's own ``.symtab`` and asserts the
     shipped invariant ``st_value == 0 && st_size == .data.size``,
  4. slices exactly ``[.data.offset + st_value, +st_size)`` and hashes it,
  5. compares that slice with ``sdk/assets/<name>.bin`` byte-for-byte and with the
     sha256/size recorded in ASSETS.json.

Nothing is extracted to disk and no external tool is used: the System V ``ar``
container and the ELF64 member are parsed here, so the numbers are reproducible
without llvm-ar/readelf.

Usage
    py runtime/maplesu-sdk/sdk/tests/verify_assets_from_archive.py
    py runtime/maplesu-sdk/sdk/tests/verify_assets_from_archive.py --json out.json

Exit codes: 0 all assets verified, 1 mismatch, 2 cannot run (missing inputs).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.abspath(os.path.join(HERE, ".."))
REPO = os.path.abspath(os.path.join(SDK, "..", "..", ".."))
ASSETS_DIR = os.path.join(SDK, "assets")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def parse_ar(blob: bytes) -> dict:
    """{name: bytes} for a System V ar archive (GNU long names + BSD #1/)."""
    if not blob.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    out, longnames, off, n = {}, b"", 8, len(blob)
    while off + 60 <= n:
        hdr = blob[off:off + 60]
        if hdr[58:60] != b"`\n":
            raise ValueError(f"bad member header at {off}")
        raw = hdr[0:16].decode("ascii", "replace").rstrip()
        size = int(hdr[48:58].decode("ascii").strip() or "0")
        data = off + 60
        body = blob[data:data + size]
        name, real = raw, size
        if raw == "//":
            longnames, name = body, "//"
        elif raw in ("/", "/SYM64/"):
            name = raw
        elif raw.startswith("#1/"):
            ln = int(raw[3:])
            name, body, real = body[:ln].decode(), body[ln:], size - ln
        elif raw.startswith("/") and raw[1:].isdigit():
            lo = int(raw[1:])
            end = longnames.find(b"/\n", lo)
            name = longnames[lo:end].decode()
        elif raw.endswith("/"):
            name = raw[:-1]
        if name not in ("/", "//", "/SYM64/"):
            out[name] = body[:real]
        off = data + size + (size & 1)
    return out


class Elf64:
    """Just enough ELF64 for ET_REL members: sections + symtab lookup."""

    def __init__(self, data: bytes):
        if not data.startswith(b"\x7fELF") or data[4] != 2 or data[5] != 1:
            raise ValueError("not a little-endian ELF64 member")
        self.data = data
        self.e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        self.e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        self.e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
        self.e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        self.sections = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            (name, type_, _flags, _addr, offset, size, link, _info, _align,
             entsize) = struct.unpack_from("<IIQQQQIIQQ", data, o)
            self.sections.append(dict(index=i, name_off=name, type=type_, offset=offset,
                                      size=size, link=link, entsize=entsize, name=""))
        shstr = self.sections[self.e_shstrndx]
        strtab = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
        for s in self.sections:
            end = strtab.find(b"\x00", s["name_off"])
            s["name"] = strtab[s["name_off"]:end].decode("ascii", "replace") if end >= 0 else ""

    def section(self, name: str):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def find_symbol(self, wanted: str):
        """Return (st_value, st_size, st_shndx) for `wanted` in any SHT_SYMTAB."""
        for s in self.sections:
            if s["type"] != 2 or s["entsize"] == 0:      # SHT_SYMTAB
                continue
            strtab = self.sections[s["link"]]
            names = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]
            blob = self.data[s["offset"]:s["offset"] + s["size"]]
            for off in range(0, s["size"], s["entsize"]):
                st_name, st_info, _other, st_shndx, st_value, st_size = struct.unpack_from(
                    "<IBBHQQ", blob, off)
                end = names.find(b"\x00", st_name)
                nm = names[st_name:end].decode("ascii", "replace") if end >= 0 else ""
                if nm == wanted:
                    return st_value, st_size, st_shndx
        return None


def verify(json_path: str | None) -> int:
    """Prove the pinned reference images in sdk/assets/ are the frozen bytes.

    The build consumes *source-built* payloads (build/out/assets); sdk/assets/
    keeps the vendor images as the reference/provenance record.  This check keeps
    that record honest: every reference image must still be byte-identical to the
    payload array inside its member of the frozen archive.
    """
    assets_json = os.path.join(ASSETS_DIR, "ASSETS.json")
    if not os.path.isfile(assets_json):
        print(f"[E] missing {assets_json}", file=sys.stderr)
        return 2
    with open(assets_json, encoding="utf-8") as fh:
        doc = json.load(fh)

    snapshot = doc.get("freeze_snapshot")
    if not snapshot:
        print("[E] ASSETS.json has no freeze_snapshot", file=sys.stderr)
        return 2
    archive_path = os.path.join(
        REPO, "runtime", "maplesu-sdk", "maintenance", "freeze", snapshot,
        "archive", "libkernel_module_kit_static.a")   # residual: reference input
    if not os.path.isfile(archive_path):
        print(f"[E] frozen archive not found: {archive_path}", file=sys.stderr)
        return 2
    with open(archive_path, "rb") as fh:
        arch_blob = fh.read()
    archive_sha = sha256(arch_blob)

    # mangled symbol names live in the extractor report next to ASSETS.json
    mangled = {}
    payloads_json = os.path.join(ASSETS_DIR, "payloads.json")
    if os.path.isfile(payloads_json):
        with open(payloads_json, encoding="utf-8") as fh:
            report = json.load(fh)
        for target in report.get("targets") or []:
            mangled[target.get("member")] = target.get("symbol")

    rows, failed = [], 0

    def fail(msg):
        nonlocal failed
        failed += 1
        print(f"[FAIL] {msg}")

    declared_sha = str(doc.get("archive_sha256") or "")
    if declared_sha and archive_sha != declared_sha:
        fail(f"archive sha256 {archive_sha} != ASSETS.json {declared_sha}")

    members = parse_ar(arch_blob)
    for entry in doc.get("assets") or []:
        asset_rel = str(entry.get("asset") or "")
        asset_name = os.path.basename(asset_rel)
        member_name = str(entry.get("member") or "")
        blob = members.get(member_name)
        if blob is None:
            fail(f"{asset_name}: member {member_name} not found in the archive")
            continue
        symbol = mangled.get(member_name)
        if symbol is None:
            fail(f"{asset_name}: mangled symbol for {member_name} not recorded")
            continue
        elf = Elf64(blob)
        found = elf.find_symbol(symbol)
        if found is None:
            fail(f"{asset_name}: symbol {symbol} not found in {member_name}")
            continue
        st_value, st_size, st_shndx = found
        data_section = elf.sections[st_shndx]
        if st_value != 0:
            fail(f"{asset_name}: shipped invariant st_value == 0 violated ({st_value})")
        if st_size != data_section["size"]:
            fail(f"{asset_name}: st_size {st_size} != .data size {data_section['size']}")
        if st_value + st_size > data_section["size"]:
            fail(f"{asset_name}: payload range exceeds .data")
            continue
        start = data_section["offset"] + st_value
        payload = blob[start:start + st_size]
        payload_sha = sha256(payload)

        local_path = os.path.join(ASSETS_DIR, asset_name)
        local_sha = None
        if os.path.isfile(local_path):
            with open(local_path, "rb") as fh:
                local_sha = sha256(fh.read())
        declared_asset_sha = str(entry.get("sha256") or "")
        declared_asset_size = entry.get("size")

        if len(payload) != declared_asset_size:
            fail(f"{asset_name}: extracted size {len(payload)} != ASSETS.json {declared_asset_size}")
        if declared_asset_sha and payload_sha != declared_asset_sha:
            fail(f"{asset_name}: extracted sha256 {payload_sha} != ASSETS.json {declared_asset_sha}")
        if local_sha is None:
            fail(f"{asset_name}: reference image missing at {local_path}")
        elif local_sha != payload_sha:
            fail(f"{asset_name}: sdk/assets image {local_sha} != archive payload {payload_sha}")
        rows.append(dict(asset=asset_name, member=member_name, symbol=symbol,
                         bytes=len(payload), sha256=payload_sha,
                         matches=local_sha == payload_sha if local_sha else False))

    result = dict(
        schema="maplesu-sdk-reference-assets/1",
        archive=dict(path=os.path.relpath(archive_path, REPO).replace(os.sep, "/"),
                     sha256=archive_sha, bytes=len(arch_blob)),
        assets=rows,
        failures=failed,
    )
    if json_path:
        with open(json_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"[report] {json_path}")
    for row in rows:
        print(f"[ok] {row['asset']:24s} {row['bytes']:>9,d} B  {row['sha256'][:16]}…")
    if failed:
        print(f"\n[FAIL] {failed} reference-asset check(s) failed", file=sys.stderr)
        return 1
    print(f"\n[ok] {len(rows)} reference image(s) match the frozen archive payload arrays")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)
    return verify(args.json)


if __name__ == "__main__":
    sys.exit(main())
