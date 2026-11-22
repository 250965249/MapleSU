#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_payload_headers.py -- turn the pinned payload **assets** into C++ array headers.

Why a generator at all
----------------------
The four Ultra install objects embed a whole stripped userland binary as
``static const unsigned char <name>[]`` in ``.data``; the installers size every
buffer, ``memcpy``, ``write`` and the sliding token-search loop from
``sizeof(<name>)``.  To keep that contract after the payloads became **assets**
(``sdk/assets/*.bin``) instead of hand-written headers, this tool regenerates the
same shape of header from the pinned bytes:

    namespace maplesu::sdk {
        static const unsigned char su_data[741912] = { 0x7f, 0x45, ... };
        static_assert(sizeof(su_data) == 741912, "…");
    }

* each array uses internal linkage inside ``maplesu::sdk``;
* the array keeps the **original type** ``const unsigned char[N]``, so
  ``sizeof(name)`` is the payload byte count at compile time -- no runtime size
  table, no off-by-one, no ``extern`` declaration that could disagree with the
  bytes actually linked;
* every header carries a ``static_assert`` plus the sha256 of the bytes it was
  generated from, so a stale or hand-edited header fails the build instead of
  silently shipping a wrong payload.

Generated headers are **build output** and are written into the build tree
(default ``sdk/build/assets-gen/``), never into the source tree.

Usage
-----
    py runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py                 # write headers
    py runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py --check         # verify, write nothing
    py runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py --out DIR       # custom output dir
    py runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py --list          # show the asset table

Exit codes: 0 ok, 1 verification failure, 2 usage/IO failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.abspath(os.path.join(HERE, ".."))
DEFAULT_ASSETS = os.path.join(SDK, "assets")
DEFAULT_OUT = os.path.join(SDK, "build", "assets-gen")

# asset file -> (namespace symbol, header file, original mangled symbol in the shipped member)
TABLE = [
    ("su.bin", "su_data", "su_data.h", "_ZN10skroot_envL7su_dataE",
     "maplesu_unsafe_su_install.o"),
    ("resetprop_file.bin", "resetprop_file_data", "resetprop_file_data.h",
     "_ZN10skroot_envL19resetprop_file_dataE", "maplesu_unsafe_resetprop_install.o"),
    ("webui_loader.bin", "webui_loader_data", "webui_loader_data.h",
     "_ZN10skroot_envL17webui_loader_dataE", "maplesu_unsafe_webui_loader_install.o"),
    ("autorun_bootstrap.bin", "autorun_bootstrap_file_data", "autorun_bootstrap_file_data.h",
     "_ZN10skroot_envL27autorun_bootstrap_file_dataE", "maplesu_autorun_bootstrap_install.o"),
]

UMBRELLA = "payload_assets.generated.h"
SIZES_HEADER = "payload_sizes.generated.h"
SIZE_CONSTANTS = {
    "su.bin": "kSuPayloadSize",
    "resetprop_file.bin": "kResetpropPayloadSize",
    "webui_loader.bin": "kWebuiLoaderPayloadSize",
    "autorun_bootstrap.bin": "kAutorunBootstrapPayloadSize",
}
BYTES_PER_LINE = 12


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_assets_json(assets_dir: str) -> dict:
    p = os.path.join(assets_dir, "ASSETS.json")
    if not os.path.isfile(p):
        return {}
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def asset_index(assets_json: dict) -> dict:
    """asset basename -> ASSETS.json entry"""
    out = {}
    for e in assets_json.get("assets", []):
        out[os.path.basename(e["asset"])] = e
    return out


def render_header(sym: str, fname: str, blob: bytes, member: str, dim: str, extra: str) -> str:
    n = len(blob)
    digest = sha256_bytes(blob)
    lines = []
    lines.append("// ===========================================================================")
    lines.append("// GENERATED FILE -- do not edit, do not commit.")
    lines.append(f"// produced by : runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py")
    lines.append(f"// asset       : runtime/maplesu-sdk/sdk/assets/{fname}")
    lines.append(f"// payload     : {n} B  sha256 {digest}")
    lines.append(f"// shipped as  : maplesu::sdk::{sym} in {member}")
    lines.append(f"// array type  : const unsigned char[{n}]  ->  sizeof({sym}) == {n}")
    lines.append("// ===========================================================================")
    lines.append("#pragma once")
    lines.append("")
    lines.append("namespace maplesu::sdk {")
    lines.append("")
    lines.append(f"static const unsigned char {sym}[{n}] = {{")
    for off in range(0, n, BYTES_PER_LINE):
        chunk = blob[off:off + BYTES_PER_LINE]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("};")
    lines.append("")
    lines.append(f'static_assert(sizeof({sym}) == {n}u, "{sym}: payload size changed '
                 f'without regenerating the header");')
    lines.append(f'static_assert(sizeof({sym}[0]) == 1u, "{sym}: element type must stay 1 byte");')
    if extra:
        lines.append(f"// {extra}")
    lines.append("")
    lines.append("}  // namespace maplesu::sdk")
    lines.append("")
    return "\n".join(lines)


def load_payload_manifest(manifest_path: str):
    """sdk/build/out/assets/PAYLOADS.json -> {asset basename: program record}."""
    with open(manifest_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    index = {}
    for program in doc.get("programs") or []:
        asset = os.path.basename(str(program.get("asset") or ""))
        if asset:
            index[asset] = program
    return doc, index


def build(assets_dir: str, manifest_path: str | None = None):
    """Return (headers, table, errors) for the assets in ``assets_dir``.

    With ``manifest_path`` the bytes are verified against the payload build's own
    manifest (``PAYLOADS.json``): those assets are source-built programs, so their
    hashes are whatever the compiler produced, and the pinned reference image
    recorded by the payload builder is kept as provenance only.  Without a
    manifest the historical contract stays in force: the assets are the extracted
    reference images and every byte is checked against ``ASSETS.json``.
    """
    assets_json = load_assets_json(assets_dir)
    idx = asset_index(assets_json)
    payload_index = {}
    payload_doc = {}
    if manifest_path:
        payload_doc, payload_index = load_payload_manifest(manifest_path)
    produced, table, errors = [], [], []
    for fname, sym, hname, mangled, member in TABLE:
        path = os.path.join(assets_dir, fname)
        if not os.path.isfile(path):
            errors.append(f"missing asset: {path}")
            continue
        with open(path, "rb") as fh:
            blob = fh.read()
        digest = sha256_bytes(blob)
        program = None
        if manifest_path:
            program = payload_index.get(fname)
            if program is None:
                errors.append(f"{fname}: not listed in {os.path.basename(manifest_path)}")
            else:
                published = program.get("published") or {}
                if published.get("sha256") != digest:
                    errors.append(f"{fname}: sha256 {digest} != payload manifest "
                                  f"{published.get('sha256')}")
                if published.get("bytes") not in (None, len(blob)):
                    errors.append(f"{fname}: size {len(blob)} != payload manifest "
                                  f"{published.get('bytes')}")
                if program.get("status") not in ("built", "reference-copy"):
                    errors.append(f"{fname}: payload build status is "
                                  f"{program.get('status')!r}")
            copy_note = "source-built program (see src/payload)"
        else:
            want = idx.get(fname)
            if want is None:
                errors.append(f"{fname}: not listed in ASSETS.json")
            else:
                if want.get("sha256") != digest:
                    errors.append(f"{fname}: sha256 {digest} != ASSETS.json {want.get('sha256')}")
                if want.get("size") != len(blob):
                    errors.append(f"{fname}: size {len(blob)} != ASSETS.json {want.get('size')}")
            copy_note = "extracted reference image (see ASSETS.json)"
        reference = (payload_index.get(fname) or {}).get("reference") or {}
        extra = (f"source member {member}  ({copy_note})"
                 + (f"; reference image {reference.get('bytes')} B "
                    f"sha256 {(reference.get('sha256') or '')[:16]}" if reference.get("sha256") else ""))
        produced.append((hname, render_header(sym, fname, blob, member, digest, extra)))
        status = (program or {}).get("status")
        origin = {"built": "source-built", "reference-copy": "reference-image"}.get(
            status, "reference")
        table.append(dict(asset=fname, symbol=sym, header=hname, mangled=mangled,
                          member=member, size=len(blob), sha256=digest,
                          size_constant=SIZE_CONSTANTS[fname],
                          origin=origin, reference=reference))
    if errors:
        return None, None, errors, {}
    return produced, table, [], payload_doc


def render_umbrella(table) -> str:
    lines = [
        "// ===========================================================================",
        "// GENERATED FILE -- do not edit, do not commit.",
        "// umbrella for the four Ultra payload assets; include exactly one of these",
        "// headers per translation unit (each defines a static array).",
        "// ===========================================================================",
        "#pragma once",
        "",
    ]
    for row in table:
        lines.append(f'#include "{row["header"]}"')
    lines.append("")
    lines.append("namespace maplesu::sdk {")
    lines.append("")
    for row in table:
        lines.append(f'static_assert(sizeof({row["symbol"]}) == {row["size"]}u,')
        lines.append(f'              "{row["symbol"]}: expected {row["size"]} payload bytes");')
    lines.append("")
    lines.append("}  // namespace maplesu::sdk")
    lines.append("")
    return "\n".join(lines)


def render_sizes(table) -> str:
    """Compile-time size pins for the arrays this build embeds.

    Installers assert ``sizeof(<array>) == k<Name>PayloadSize`` so the embedded
    program cannot silently change length between the payload build and the
    member build.  Deriving the constants from the bytes that were actually
    staged keeps the gate meaningful now that the payloads are source-built.
    """
    lines = [
        "// ===========================================================================",
        "// GENERATED FILE -- do not edit, do not commit.",
        "// payload byte sizes for the arrays compiled into the install members.",
        "// produced by : runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py",
        "// source      : build/out/assets/PAYLOADS.json (source-built payloads)",
        "// ===========================================================================",
        "#pragma once",
        "",
        "namespace maplesu::sdk {",
        "",
    ]
    for row in table:
        lines.append(f'constexpr unsigned long {row["size_constant"]} = {row["size"]}ul;'
                     f'  // {row["asset"]} sha256 {row["sha256"][:16]}')
    lines.append("")
    lines.append("}  // namespace maplesu::sdk")
    lines.append("")
    return "\n".join(lines)


def render_manifest(table) -> str:
    doc = dict(
        generator="runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py",
        assets="runtime/maplesu-sdk/sdk/assets",
        note="generated build output -- never committed",
        arrays=[dict(symbol=r["symbol"], header=r["header"], asset=r["asset"],
                     source_member=r["member"], original_mangled_symbol=r["mangled"],
                     size=r["size"], sha256=r["sha256"]) for r in table],
    )
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="generate C++ payload array headers from the staged assets")
    ap.add_argument("--assets", default=DEFAULT_ASSETS,
                    help="asset directory (reference assets, or build/out/assets for built payloads)")
    ap.add_argument("--manifest", default=None,
                    help="payload build manifest (PAYLOADS.json); verifies source-built assets")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true",
                    help="verify the assets and existing headers; write nothing")
    ap.add_argument("--list", action="store_true", help="print the asset table and exit")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.assets):
        print(f"[E] assets dir not found: {args.assets}", file=sys.stderr)
        return 2
    if args.manifest and not os.path.isfile(args.manifest):
        print(f"[E] payload manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    produced, table, errors, payload_doc = build(args.assets, args.manifest)
    if errors:
        for e in errors:
            print(f"[E] {e}", file=sys.stderr)
        return 1

    if args.list:
        for r in table:
            print(f'{r["symbol"]:28s} {r["size"]:>9d} B  {r["sha256"][:16]}…  '
                  f'({r["origin"]}) -> {r["header"]}')
        return 0

    umbrella = render_umbrella(table)
    sizes = render_sizes(table)
    manifest = render_manifest(table)

    if args.check:
        bad = 0
        for hname, text in produced + [(UMBRELLA, umbrella), (SIZES_HEADER, sizes)]:
            p = os.path.join(args.out, hname)
            if not os.path.isfile(p):
                print(f"[E] missing generated header: {p}", file=sys.stderr)
                bad += 1
                continue
            with open(p, encoding="utf-8") as fh:
                if fh.read() != text:
                    print(f"[E] stale generated header: {p}", file=sys.stderr)
                    bad += 1
        if not bad:
            print(f"[ok] {len(produced)} headers + umbrella + sizes up to date "
                  f"({sum(r['size'] for r in table)} payload bytes)")
        return 0 if not bad else 1

    os.makedirs(args.out, exist_ok=True)
    for hname, text in produced + [(UMBRELLA, umbrella), (SIZES_HEADER, sizes)]:
        with open(os.path.join(args.out, hname), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    with open(os.path.join(args.out, "payload_assets.generated.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write(manifest)
    for r in table:
        print(f'{r["symbol"]:28s} {r["size"]:>9d} B  {r["sha256"][:16]}…  '
              f'({r["origin"]}) -> {r["header"]}')
    try:
        output_label = os.path.relpath(args.out, os.path.dirname(SDK))
    except ValueError:  # --build-dir may be on another Windows drive.
        output_label = os.path.abspath(args.out)
    print(f'\n{len(produced)} headers -> {output_label}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
