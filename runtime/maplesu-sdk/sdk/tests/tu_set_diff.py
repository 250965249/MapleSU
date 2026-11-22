#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tu_set_diff.py -- T/U symbol-set diff between a rebuilt object and the frozen member.

Acceptance gate for R-PROGRAMS: for each of the four installers the rebuilt object
must have the *same* set of external definitions (T: global, defined, FUNC) as the
member inside the frozen archive, in both directions (no missing, no extra).

The U set (imports) is reported as information. It is **not** a pass condition by
default because the rebuilt objects are compiled from independent C++ rather than
re-linked from the vendor's exact inlining, so libc++ chooses different
instantiation points (std::filesystem::path / std::string helpers, the vendor's
TU-local `snprintf` shadow). Use `--strict-u` to require an exact import set too.

  py runtime/maplesu-sdk/sdk/tests/tu_set_diff.py                # all four
  py runtime/maplesu-sdk/sdk/tests/tu_set_diff.py --member maplesu_unsafe_su_install.o
  py runtime/maplesu-sdk/sdk/tests/tu_set_diff.py --json out.json

The comparison reads the frozen archive directly (no llvm-ar extraction) but uses
llvm-nm for symbol decoding, so the numbers are the same ones `llvm-nm` prints.

Exit code 0 = every compared pair has empty diffs in both directions.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.abspath(os.path.join(HERE, ".."))
REPO = os.path.abspath(os.path.join(SDK, "..", "..", ".."))
NDK_BIN = "D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin"
ARCHIVE = os.path.join(
    REPO, "runtime", "maplesu-sdk", "maintenance", "freeze",
    "freeze-maplesu-pro-5.2.0-helper-allowlist-20261114-20261114",
    "archive", "libkernel_module_kit_static.a",   # residual: reference input
)
BUILT = os.path.join(SDK, "build", "programs")
MEMBERS = [
    "maplesu_unsafe_su_install.o",
    "maplesu_unsafe_resetprop_install.o",
    "maplesu_unsafe_webui_loader_install.o",
    "maplesu_autorun_bootstrap_install.o",
]


def parse_ar(blob: bytes):
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
            out[name] = body
        off = data + size + (size & 1)
    return out


def nm(path: str):
    exe = os.path.join(NDK_BIN, "llvm-nm.exe")
    res = subprocess.run([exe, "-S", "--defined-only", path], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"llvm-nm failed on {path}: {res.stderr}")
    defined = res.stdout
    res_u = subprocess.run([exe, "-u", path], capture_output=True, text=True)
    if res_u.returncode != 0:
        raise RuntimeError(f"llvm-nm -u failed on {path}: {res_u.stderr}")
    return defined, res_u.stdout


def split_sets(defined_out: str, undef_out: str):
    t_set, weak_t = set(), set()
    for line in defined_out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        # "<addr> <size> <type> <name>" or "<addr> <type> <name>"
        if len(parts) >= 4 and parts[2] in ("T", "t", "W", "w", "V", "v", "D", "d", "B", "b", "R", "r"):
            sym_type, name = parts[2], parts[3]
        else:
            sym_type, name = parts[1], parts[2]
        if sym_type == "T":
            t_set.add(name)
        elif sym_type in ("W", "w"):
            weak_t.add(name)
    u_set = set()
    for line in undef_out.splitlines():
        line = line.strip()
        if line.startswith("U "):
            u_set.add(line[2:].strip())
        elif line and not line.startswith("U"):
            continue
    return t_set, weak_t, u_set


def compare(member: str, built: str | None):
    blob = open(ARCHIVE, "rb").read()
    members = parse_ar(blob)
    if member not in members:
        return dict(member=member, error="member not in frozen archive")
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_frozen_member.o")
    with open(tmp, "wb") as fh:
        fh.write(members[member])
    try:
        o_def, o_undef = nm(tmp)
        o_t, o_w, o_u = split_sets(o_def, o_undef)
        rec = dict(member=member, original=dict(t=sorted(o_t), u=sorted(o_u), weak=sorted(o_w)))
        if built is None or not os.path.isfile(built):
            rec["error"] = f"rebuilt object not found: {built}"
            return rec
        n_def, n_undef = nm(built)
        n_t, n_w, n_u = split_sets(n_def, n_undef)
        rec["rebuilt"] = dict(t=sorted(n_t), u=sorted(n_u), weak=sorted(n_w),
                              path=os.path.relpath(built, REPO).replace("\\", "/"))
        rec["tDiff"] = sorted(o_t ^ n_t)
        rec["tOnlyOriginal"] = sorted(o_t - n_t)
        rec["tOnlyRebuilt"] = sorted(n_t - o_t)
        rec["uDiff"] = sorted(o_u ^ n_u)
        rec["uOnlyOriginal"] = sorted(o_u - n_u)
        rec["uOnlyRebuilt"] = sorted(n_u - o_u)
        rec["ok"] = not rec["tDiff"] and not rec["uDiff"]
        return rec
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--member", default=None, help="single member name (default: all four)")
    ap.add_argument("--built", default=None, help="rebuilt object path (default: build/programs/<member>)")
    ap.add_argument("--json", default=None)
    ap.add_argument("--strict-u", action="store_true",
                    help="also require the import (U) sets to match exactly")
    args = ap.parse_args(argv)

    targets = [args.member] if args.member else MEMBERS
    rows, all_ok = [], True
    for m in targets:
        built = args.built or os.path.join(BUILT, m)
        rec = compare(m, built)
        rows.append(rec)
        if rec.get("error"):
            print(f'[E] {m}: {rec["error"]}')
            all_ok = False
            continue
        t_only_orig, t_only_new = rec["tOnlyOriginal"], rec["tOnlyRebuilt"]
        u_only_orig, u_only_new = rec["uOnlyOriginal"], rec["uOnlyRebuilt"]
        t_ok = not rec["tDiff"]
        if rec["ok"]:
            status = "OK "
        elif t_ok:
            status = "T-OK"      # T sets match; imports differ (informational)
        else:
            status = "DIFF"
        print(f'[{status}] {m}: T orig={len(rec["original"]["t"])} new={len(rec["rebuilt"]["t"])} '
              f'diff={len(rec["tDiff"])} | U orig={len(rec["original"]["u"])} '
              f'new={len(rec["rebuilt"]["u"])} diff={len(rec["uDiff"])}')
        if t_only_orig:
            print(f'        T only in frozen  : {t_only_orig}')
        if t_only_new:
            print(f'        T only in rebuilt : {t_only_new}')
        if u_only_orig:
            print(f'        U only in frozen  : {u_only_orig[:12]}'
                  f'{" …" if len(u_only_orig) > 12 else ""}')
        if u_only_new:
            print(f'        U only in rebuilt : {u_only_new[:12]}'
                  f'{" …" if len(u_only_new) > 12 else ""}')
        all_ok = all_ok and (t_ok and (rec["ok"] or not args.strict_u))

    print(f"\nT sets (external definitions): "
          f"{'all match' if all_ok else 'MISMATCH'} "
          f"({'strict: U sets also required' if args.strict_u else 'U differences informational'})")
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(dict(archive=os.path.relpath(ARCHIVE, REPO).replace("\\", "/"), rows=rows),
                      fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"-> {args.json}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
