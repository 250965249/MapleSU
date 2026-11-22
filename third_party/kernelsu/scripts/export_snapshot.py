#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""导出 LF 归一化的上游 / 7K 快照（无 git submodule 的替代实现）。

用法（仓库根执行，Windows Git-Bash 可跑）：
  python third_party/kernelsu/scripts/export_snapshot.py --which upstream --clean
  python third_party/kernelsu/scripts/export_snapshot.py --which source7k --out /tmp/s7k

为什么必须从这里导出：`.research/*` 是 `core.autocrlf=true` 下的 Windows 工作树，
不是上游字节（03 分册 §0.2 实测）。`git -c core.autocrlf=false archive` 才能拿到
Git 对象里的 LF 字节；symlink（`uapi`、`cpp/uapi`）在本机被落成真实目录（§1.2.4）。

产物：
  third_party/kernelsu/upstream/SNAPSHOT.json   # 快照自述（无时间戳，可复现）
  third_party/kernelsu/upstream/**              # 只读快照（LF）
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import ksu_common as C


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="导出 KSU 分支树的 LF 快照")
    ap.add_argument("--which", choices=["upstream", "source7k"], default="upstream")
    ap.add_argument("--out", default=None, help="输出目录（默认 upstream/ 或临时目录）")
    ap.add_argument("--research-root", default=str(C.RESEARCH_ROOT))
    ap.add_argument("--clean", action="store_true", help="目标已存在且非空时删除重建")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    research = Path(args.research_root)

    if args.which == "upstream":
        repo = research / "KernelSU"
        rev = C.UPSTREAM_COMMIT
        out = Path(args.out) if args.out else C.UPSTREAM_DIR
        meta = C.export_git_tree(repo, rev, out, clean=args.clean)
        snapshot = {
            "schema": 1,
            "role": "upstream-snapshot",
            "repo": C.UPSTREAM_REPO,
            "commit": C.UPSTREAM_COMMIT,
            "refNote": C.UPSTREAM_REF_NOTE,
            "ci": C.UPSTREAM_CI,
            "uapiVersion": C.UPSTREAM_UAPI,
            "exportCommand": C.GIT_ARCHIVE_CMD.replace("<repo>", ".research/KernelSU")
            .replace("<rev>", C.UPSTREAM_COMMIT),
            "lineEnding": "LF (git object bytes; core.autocrlf=false)",
            "gitMembers": meta["gitMembers"],
            "fileCount": meta["fileCount"],
            "materializedSymlinks": meta["materializedSymlinks"],
            "generator": "third_party/kernelsu/scripts/export_snapshot.py@1",
        }
        C.write_json(out / "SNAPSHOT.json", snapshot)
        print(f"OK upstream: {out} files={meta['fileCount']} "
              f"gitMembers={meta['gitMembers']} symlinks={len(meta['materializedSymlinks'])}")
        return 0

    repo = research / "7kimisu"
    rev = C.SOURCE7K_COMMIT
    out = Path(args.out) if args.out else (C.KSU_ROOT / ".source7k.tmp")
    # 7K 树只作为补丁来源读取，默认落在临时目录，不进 third_party/kernelsu/。
    meta = C.export_git_tree(repo, rev, out, clean=args.clean)
    snapshot = {
        "schema": 1,
        "role": "patch-source-snapshot",
        "repo": C.SOURCE7K_REPO,
        "commit": C.SOURCE7K_COMMIT,
        "release": C.SOURCE7K_RELEASE,
        "uapiVersion": C.SOURCE7K_UAPI,
        "exportCommand": C.GIT_ARCHIVE_CMD.replace("<repo>", ".research/7kimisu")
        .replace("<rev>", C.SOURCE7K_COMMIT),
        "lineEnding": "LF (git object bytes; core.autocrlf=false)",
        "gitMembers": meta["gitMembers"],
        "fileCount": meta["fileCount"],
        "materializedSymlinks": meta["materializedSymlinks"],
        "generator": "third_party/kernelsu/scripts/export_snapshot.py@1",
    }
    C.write_json(out / "SNAPSHOT.json", snapshot)
    print(f"OK source7k: {out} files={meta['fileCount']} "
          f"gitMembers={meta['gitMembers']} symlinks={len(meta['materializedSymlinks'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
