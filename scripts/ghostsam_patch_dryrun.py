#!/usr/bin/env python3
"""GhostSam × MapleSU Normal 兼容补丁的离线 dry-run / 静态登记校验。

背景
----
MapleSU 的基础补丁序列是 ``third_party/kernelsu/patches/7k/series``（26 项，由
``scripts/gen_patches.py`` 生成、``scripts/apply_patches.py`` 消费，并与
``manifest.json.patchSeries.seriesSha256`` 绑定）。本工具**不修改**基础序列，也不
手改生成树 ``applied/``；它校验一个**扩展序列** ``patches/7k/series-ghostsam``
（当前仅 0028-ghostsam-late-load-compat.patch），并在临时目录里按“基础序列 →
扩展序列”的顺序真实 ``git apply`` 一遍，作为可重复的应用检查。

设计边界（fail-closed）
- 只读取/复制 ``third_party/kernelsu/upstream`` 到临时目录，绝不写 ``applied/``；
- 扩展补丁只允许改 ``userspace/ksud/src/{cli.rs,late_load.rs}``；
- 新增行不得出现 boot-patch / boot-restore / InstallerPartitionService / /dev/block /
  modules.rc / metadata / set_active / flash 等系统或启动分区写入路径；
- 校验 ``late_load.rs`` 重启组件走 MapleSU 自己的 build-time 包名（
  ``defs::DEFAULT_PACKAGE_NAME``），不再沿用上游 ``me.weishu`` 硬编码组件；
- 校验 ``cli.rs`` 接受 ``--soft-reboot``（兼容 no-op）。

用法
----
    py -3 scripts/ghostsam_patch_dryrun.py            # 全量 dry-run（真实 apply 到临时树）
    py -3 scripts/ghostsam_patch_dryrun.py --static   # 只做静态登记/内容校验，不 apply
    py -3 scripts/ghostsam_patch_dryrun.py --self-test # 等价默认，供 CI/门禁
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ALLOWED_TARGETS = {
    "userspace/ksud/src/cli.rs",
    "userspace/ksud/src/late_load.rs",
}
FORBIDDEN_ADDED = [
    "/dev/block",
    "boot-patch",
    "boot_patch",
    "boot-restore",
    "boot_restore",
    "InstallerPartitionService",
    "modules.rc",
    "/metadata",
    "set_active",
    "flash ",
    "flash_boot",
]
EXTENSION_PATCH = "0028-ghostsam-late-load-compat.patch"


class DryRunError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_series(path: Path) -> list[str]:
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _git_ok(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    proc = _git(args, cwd)
    if proc.returncode != 0:
        raise DryRunError(f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def patch_added_lines(patch_text: str) -> list[str]:
    return [ln[1:] for ln in patch_text.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def patch_targets(patch_text: str) -> list[str]:
    targets = []
    for ln in patch_text.splitlines():
        m = re.match(r"^diff --git a/(\S+) b/(\S+)$", ln)
        if m:
            if m.group(1) != m.group(2):
                raise DryRunError(f"patch renames/mismatched path: {ln}")
            targets.append(m.group(1))
    return targets


def static_checks(kroot: Path) -> dict:
    patches_dir = kroot / "patches" / "7k"
    base_series = patches_dir / "series"
    ext_series = patches_dir / "series-ghostsam"
    patch = patches_dir / EXTENSION_PATCH
    for p in (base_series, ext_series, patch):
        if not p.is_file():
            raise DryRunError(f"missing required file: {p}")

    base_entries = read_series(base_series)
    ext_entries = read_series(ext_series)
    if ext_entries != [EXTENSION_PATCH]:
        raise DryRunError(f"series-ghostsam must contain exactly [{EXTENSION_PATCH}], got {ext_entries}")
    if EXTENSION_PATCH in base_entries:
        raise DryRunError("0028 must NOT be in the base series (base must stay byte-identical)")

    text = patch.read_text(encoding="utf-8")
    if "\r" in text:
        raise DryRunError("patch contains CR (line-ending policy is LF-only)")
    targets = patch_targets(text)
    for t in targets:
        if t not in ALLOWED_TARGETS:
            raise DryRunError(f"patch touches a non-allowed file: {t}")
    if "userspace/ksud/src/cli.rs" not in targets or "userspace/ksud/src/late_load.rs" not in targets:
        raise DryRunError(f"patch must touch both cli.rs and late_load.rs, got {targets}")

    added = patch_added_lines(text)
    for ln in added:
        low = ln.lower()
        for bad in FORBIDDEN_ADDED:
            if bad.lower() in low:
                raise DryRunError(f"forbidden token {bad!r} in added line: {ln!r}")
        if "me.weishu" in low:
            raise DryRunError(f"added line still references upstream me.weishu component: {ln!r}")

    added_blob = "\n".join(added)
    if "soft_reboot" not in added_blob or "--soft-reboot" not in added_blob:
        raise DryRunError("patch does not accept --soft-reboot on late-load")
    if "defs::DEFAULT_PACKAGE_NAME" not in added_blob:
        raise DryRunError("patch does not switch manager restart to defs::DEFAULT_PACKAGE_NAME")
    if "MapleSU Manager" not in added_blob:
        raise DryRunError("patch does not log the MapleSU manager restart")

    manifest_path = kroot / "manifest.json"
    manifest_series_sha = None
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_series_sha = (manifest.get("patchSeries") or {}).get("seriesSha256")

    result = {
        "baseSeries": "series",
        "baseSeriesEntries": base_entries,
        "baseSeriesSha256": _sha256(base_series),
        "manifestSeriesSha256": manifest_series_sha,
        "baseSeriesMatchesManifest": (manifest_series_sha is None or manifest_series_sha == _sha256(base_series)),
        "extensionSeries": "series-ghostsam",
        "extensionSeriesEntries": ext_entries,
        "extensionSeriesSha256": _sha256(ext_series),
        "patch": EXTENSION_PATCH,
        "patchSha256": _sha256(patch),
        "patchTargets": targets,
        "patchAddedLines": added,
    }
    if manifest_series_sha is not None and manifest_series_sha != _sha256(base_series):
        raise DryRunError(
            "base series sha256 does not match manifest.json patchSeries.seriesSha256 "
            f"({_sha256(base_series)} != {manifest_series_sha})"
        )
    return result


def apply_dry_run(kroot: Path, info: dict) -> dict:
    """复制 upstream 到临时树，按 基础序列 -> 扩展序列 顺序真实 git apply。"""
    patches_dir = kroot / "patches" / "7k"
    upstream = kroot / "upstream"
    work = Path(tempfile.mkdtemp(prefix="maplesu-ghostsam-dryrun-"))
    try:
        dst = work / "u"
        shutil.copytree(upstream, dst)
        _git_ok(["init", "-q"], dst)
        _git_ok(["config", "core.autocrlf", "false"], dst)
        _git_ok(["add", "-A"], dst)
        _git_ok(["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "base"], dst)

        applied = []
        for name in info["baseSeriesEntries"] + info["extensionSeriesEntries"]:
            patch_path = patches_dir / name
            if not patch_path.is_file():
                raise DryRunError(f"series entry missing: {name}")
            check = _git(["apply", "--check", "-p1", "--whitespace=error-all", str(patch_path)], dst)
            if check.returncode != 0:
                raise DryRunError(f"git apply --check failed for {name}: {check.stderr.strip()}")
            _git_ok(["apply", "-p1", "--whitespace=error-all", str(patch_path)], dst)
            applied.append(name)

        cli = (dst / "userspace/ksud/src/cli.rs").read_text(encoding="utf-8")
        late = (dst / "userspace/ksud/src/late_load.rs").read_text(encoding="utf-8")
        if "soft_reboot" not in cli or "--soft-reboot" not in cli:
            raise DryRunError("applied cli.rs lacks --soft-reboot compat flag")
        if "defs::DEFAULT_PACKAGE_NAME" not in late or "MapleSU Manager" not in late:
            raise DryRunError("applied late_load.rs does not restart the MapleSU manager component")
        if "{package_name}/me.weishu.kernelsu.ui.MainActivity" in late:
            raise DryRunError("applied late_load.rs still uses the upstream me.weishu component")
        # 三重身份校验不得被削弱：补丁不得触及 apk_sign.c / Kbuild。
        for t in info["patchTargets"]:
            if "apk_sign" in t or t.endswith("kernel/Kbuild"):
                raise DryRunError(f"patch must not touch identity code: {t}")

        return {"appliedEntries": applied, "appliedCount": len(applied)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run(repo_root: Path, apply: bool = True) -> dict:
    kroot = repo_root / "third_party" / "kernelsu"
    info = static_checks(kroot)
    if apply:
        info.update(apply_dry_run(kroot, info))
    return info


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--static", action="store_true", help="只做静态校验，不真实 apply")
    ap.add_argument("--self-test", action="store_true", help="等价默认 dry-run，供门禁调用")
    ap.add_argument("--json", action="store_true", help="输出 JSON 摘要")
    args = ap.parse_args(argv)
    repo_root = Path(__file__).resolve().parent.parent
    try:
        info = run(repo_root, apply=not args.static)
    except DryRunError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    if args.json:
        summary = {k: v for k, v in info.items() if k != "patchAddedLines"}
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("[OK] base series sha256:", info["baseSeriesSha256"])
        print("[OK] manifest series sha256:", info["manifestSeriesSha256"], "(match:", info["baseSeriesMatchesManifest"], ")")
        print("[OK] extension series:", info["extensionSeriesEntries"], "sha256:", info["extensionSeriesSha256"])
        print("[OK] patch:", info["patch"], "sha256:", info["patchSha256"])
        print("[OK] patch targets:", info["patchTargets"])
        if "appliedCount" in info:
            print("[OK] applied", info["appliedCount"], "patches to temp tree (base+extension)")
        print("[OK] static + dry-run checks passed; note: nothing was built (no SDK/NDK/artifact).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
