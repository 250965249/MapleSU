#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_freeze.py — 冻结快照完整性复算器（只用 Python 标准库）.

用途
====
对 ``freeze/<snapshotId>/HASHES.sha256`` 的**每一项**重新计算 sha256 与字节数，
与清单逐行比对；并检查「清单外多出的文件」与「清单里缺失的文件」。
这是 W0 冻结快照的**唯一权威校验**——Windows/msys 下 ``chmod a-w`` 的只读位
不可靠（见 FREEZE.json.notes），文件被改动的发现手段就是本脚本的复算。

清单格式（每行一项，按 relpath 升序）::

    <sha256-hex 64>  <空格>  <bytes 十进制>  <空格>  <relpath，用 / 分隔，相对冻结根>

自引用排除
==========
``HASHES.sha256`` / ``FREEZE.json`` / ``HASHES.verify.txt`` 三者不进清单
（前两者若进清单会自引用，第三者是本脚本的产物），按名排除并**显式报告**，
不静默忽略。

退出码
======
====  ==========================================
 0    全部通过（无缺失 / 无哈希不符 / 无尺寸不符 / 无未列出的多余文件）
 1    校验失败（有任一不符项）
 2    用法错误或环境不可用（找不到冻结目录 / 清单 / 清单格式错）
====  ==========================================

用法
====
    py runtime/maplesu-sdk/sdk/tools/check_freeze.py
    py runtime/maplesu-sdk/sdk/tools/check_freeze.py --snapshot freeze-...-20261114
    py runtime/maplesu-sdk/sdk/tools/check_freeze.py --freeze /abs/path --out /abs/out.txt
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
TOOL = "check_freeze.py"

# 自引用/生成顺序问题，按名排除（不静默：结果里会列出被排除的名字）
EXCLUDED_NAMES = ("HASHES.sha256", "FREEZE.json", "HASHES.verify.txt")

REPO = Path(__file__).resolve().parents[4]  # sdk/tools/check_freeze.py -> repo root
FREEZE_ROOT = REPO / "runtime" / "maplesu-sdk" / "maintenance" / "freeze"


def sha256_and_size(path: Path, chunk: int = 1 << 20) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def pick_snapshot() -> Path:
    """没有显式指定时，选 freeze/ 下最近修改的目录。"""
    if not FREEZE_ROOT.is_dir():
        raise SystemExit(f"冻结根不存在: {FREEZE_ROOT}")
    cands = [p for p in FREEZE_ROOT.iterdir() if p.is_dir() and (p / "HASHES.sha256").is_file()]
    if not cands:
        raise SystemExit(f"{FREEZE_ROOT} 下没有含 HASHES.sha256 的快照目录")
    cands.sort(key=lambda p: (p / "HASHES.sha256").stat().st_mtime)
    return cands[-1]


def parse_manifest(path: Path) -> tuple[list[tuple[str, int, str]], list[str]]:
    """返回 (entries, format_errors)。entries = [(sha256, bytes, relpath)]。"""
    entries: list[tuple[str, int, str]] = []
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            errors.append(f"line {lineno}: 空行（清单不允许空行）")
            continue
        parts = raw.split(" ")
        if len(parts) != 3:
            errors.append(f"line {lineno}: 期望 3 个空格分隔字段，实际 {len(parts)}: {raw!r}")
            continue
        hexpart, sizepart, rel = parts
        if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
            errors.append(f"line {lineno}: sha256 不是 64 位小写 hex: {hexpart!r}")
            continue
        if not sizepart.isdigit():
            errors.append(f"line {lineno}: 字节数不是十进制整数: {sizepart!r}")
            continue
        if rel.startswith("/") or "\\" in rel or ".." in Path(rel).parts:
            errors.append(f"line {lineno}: relpath 非法（绝对路径 / 反斜杠 / 上跳）: {rel!r}")
            continue
        entries.append((hexpart, int(sizepart), rel))
    return entries, errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="冻结快照 HASHES.sha256 全项复算校验")
    ap.add_argument("--freeze", help="冻结目录绝对或相对路径（默认取 freeze/ 下最新快照）")
    ap.add_argument("--snapshot", help="冻结目录名（freeze/<snapshotId>）")
    ap.add_argument("--out", help="校验报告输出路径（默认 <freeze>/HASHES.verify.txt）")
    ap.add_argument("--quiet", action="store_true", help="只在标准输出打印结论")
    args = ap.parse_args(argv)

    if args.freeze and args.snapshot:
        print("--freeze 与 --snapshot 不能同时给", file=sys.stderr)
        return 2
    if args.snapshot:
        fz = FREEZE_ROOT / args.snapshot
    elif args.freeze:
        fz = Path(args.freeze)
        if not fz.is_absolute():
            fz = (REPO / fz).resolve()
    else:
        fz = pick_snapshot()

    manifest = fz / "HASHES.sha256"
    if not fz.is_dir():
        print(f"冻结目录不存在: {fz}", file=sys.stderr)
        return 2
    if not manifest.is_file():
        print(f"清单不存在: {manifest}", file=sys.stderr)
        return 2

    entries, fmt_errors = parse_manifest(manifest)
    if fmt_errors and not entries:
        print("清单格式全错，无法校验:", file=sys.stderr)
        for e in fmt_errors:
            print("  " + e, file=sys.stderr)
        return 2

    rels = [r for _, _, r in entries]
    dupes = sorted({r for r in rels if rels.count(r) > 1})
    sorted_ok = rels == sorted(rels)

    results: list[tuple[str, str, int, str, str]] = []  # (status, exp_sha, exp_size, rel, detail)
    ok = missing = hash_bad = size_bad = unreadable = 0
    for exp_sha, exp_size, rel in entries:
        p = fz / rel
        if not p.is_file():
            results.append(("MISSING", exp_sha, exp_size, rel, "清单登记但文件不存在"))
            missing += 1
            continue
        try:
            got_sha, got_size = sha256_and_size(p)
        except OSError as exc:
            results.append(("UNREADABLE", exp_sha, exp_size, rel, repr(exc)))
            unreadable += 1
            continue
        if got_sha != exp_sha:
            results.append(("HASH_MISMATCH", exp_sha, exp_size, rel,
                            f"实际 {got_sha} ({got_size} bytes)"))
            hash_bad += 1
        elif got_size != exp_size:
            results.append(("SIZE_MISMATCH", exp_sha, exp_size, rel, f"实际 {got_size} bytes"))
            size_bad += 1
        else:
            results.append(("OK", exp_sha, exp_size, rel, ""))
            ok += 1

    # 清单外多出的文件（自引用三项按名排除，但要报告）
    listed = set(rels)
    extras: list[str] = []
    excluded_present: list[str] = []
    for p in sorted(fz.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(fz).as_posix()
        if rel in listed:
            continue
        if rel in EXCLUDED_NAMES:
            excluded_present.append(rel)
            continue
        extras.append(rel)

    passed = (
        not fmt_errors and not dupes and not missing and not hash_bad
        and not size_bad and not unreadable and not extras and sorted_ok
    )
    total_bytes = sum(s for _, s, _ in entries)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    lines: list[str] = []
    w = lines.append
    w("=" * 78)
    w(f"{TOOL} v{VERSION} — 冻结快照完整性复算")
    w("=" * 78)
    w(f"校验时间(UTC) : {now}")
    w(f"冻结目录      : {fz}")
    w(f"清单          : {manifest.name}  ({len(entries)} 项, {total_bytes} bytes)")
    w(f"解释器        : Python {sys.version.split()[0]}")
    w(f"按名排除      : {', '.join(EXCLUDED_NAMES)}")
    w("")
    w("判据：逐项重算 sha256 与字节数；要求全项一致 + 无缺失 + 无额外文件 + 清单按 relpath 升序。")
    w("")
    w("-" * 78)
    w(f"{'STATUS':<14} {'BYTES':>10}  RELPATH")
    w("-" * 78)
    for status, _exp, size, rel, detail in results:
        w(f"{status:<14} {size:>10}  {rel}")
        if detail:
            w(f"{'':<14} {'':>10}  └─ {detail}")
    if extras:
        w("")
        w("清单外多出的文件（不允许）:")
        for rel in extras:
            w(f"  EXTRA          {rel}")
    if dupes:
        w("")
        w("重复 relpath:")
        for rel in dupes:
            w(f"  DUPLICATE      {rel}")
    if fmt_errors:
        w("")
        w("清单格式问题:")
        for e in fmt_errors:
            w(f"  FORMAT         {e}")
    w("")
    w("-" * 78)
    w("汇总")
    w("-" * 78)
    w(f"  OK              : {ok}")
    w(f"  MISSING         : {missing}")
    w(f"  HASH_MISMATCH   : {hash_bad}")
    w(f"  SIZE_MISMATCH   : {size_bad}")
    w(f"  UNREADABLE      : {unreadable}")
    w(f"  EXTRA           : {len(extras)}")
    w(f"  DUPLICATE       : {len(dupes)}")
    w(f"  FORMAT          : {len(fmt_errors)}")
    w(f"  清单升序        : {'yes' if sorted_ok else 'NO'}")
    w("  按名排除        : " + ", ".join(
        f"{n}{'(存在)' if n in excluded_present else '(不存在)'}" for n in EXCLUDED_NAMES))
    w("")
    w(f"结论: {'PASS' if passed else 'FAIL'} — "
      + ("HASHES.sha256 全项复算一致。" if passed else "存在不符项，见上表。"))
    w(f"exit code: {0 if passed else 1}")
    report = "\n".join(lines) + "\n"

    out = Path(args.out) if args.out else (fz / "HASHES.verify.txt")
    if args.out and not out.is_absolute():
        out = (REPO / out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8", newline="\n")

    if not args.quiet:
        print("\n".join(lines))
        print(f"\n报告已写入: {out}")
    else:
        print(f"check_freeze: {'PASS' if passed else 'FAIL'} "
              f"ok={ok} missing={missing} hash={hash_bad} size={size_bad} "
              f"extra={len(extras)} -> {out}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
